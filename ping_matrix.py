#!/usr/bin/env python3
"""
Ping Matrix Sweep
=================

Run a grid of ICMP (ping) tests varying payload size, DF flag, TTL, and DSCP/TOS
values to help diagnose erratic latency or fragmentation issues.

Designed to work on Termux/Android using the system `ping` binary. No root
permissions required for basic operation (but some options may need elevated
privileges depending on device policies).
"""
from __future__ import annotations

import argparse
import itertools
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


SUMMARY_RE = re.compile(
    r"(?P<tx>\d+)\s+packets\s+transmitted,\s+"
    r"(?P<rx>\d+)\s+(?:packets\s+)?received"
    r"(?:,\s*\+?(?P<errors>\d+)\s*errors)?"
    r",\s+(?P<loss>\d+(?:\.\d+)?)%\s+packet\s+loss"
)
RTT_RE = re.compile(
    r"rtt\s+(?:min/avg/max/(?:mdev|stddev)|"
    r"round-trip\s+min/avg/max/stddev)\s*=\s*"
    r"(?P<min>[\d\.]+)/(?P<avg>[\d\.]+)/(?P<max>[\d\.]+)/(?P<mdev>[\d\.]+)"
)


@dataclass
class PingConfig:
    size: int
    df: Optional[str]
    ttl: Optional[int]
    tos: Optional[int]


@dataclass
class PingResult:
    config: PingConfig
    transmitted: Optional[int] = None
    received: Optional[int] = None
    loss_percent: Optional[float] = None
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    rtt_mdev: Optional[float] = None
    errors: Optional[int] = None
    exit_code: int = 0
    stderr: str = ""
    stdout: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.loss_percent is not None


def parse_csv_ints(value: str) -> List[int]:
    parts = [v.strip() for v in value.split(",") if v.strip()]
    result: List[int] = []
    for part in parts:
        if "-" in part:
            start_str, end_str, *more = part.split("-")
            step = 1
            if more:
                try:
                    step = int(more[0])
                except ValueError as exc:
                    raise argparse.ArgumentTypeError(f"Invalid step in range: {part}") from exc
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid integer range: {part}") from exc
            if start <= end:
                result.extend(range(start, end + 1, step))
            else:
                result.extend(range(start, end - 1, -step))
        else:
            try:
                result.append(int(part))
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid integer: {part}") from exc
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run multiple ping tests varying packet size, DF flag, TTL, and DSCP."
    )
    parser.add_argument("host", help="Target hostname or IP.")
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of echo requests per test (default: 5).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.2,
        help="Interval between packets in seconds (default: 0.2).",
    )
    parser.add_argument(
        "--deadline",
        type=float,
        help="Overall deadline per ping command (seconds).",
    )
    parser.add_argument(
        "--sizes",
        type=parse_csv_ints,
        default=[56, 248, 504, 988, 1472],
        help=(
            "Payload sizes in bytes (ping -s). Accepts comma-separated values and ranges "
            "e.g. '56,512-1500-256'. Default: 56,248,504,988,1472."
        ),
    )
    parser.add_argument(
        "--ttl",
        type=parse_csv_ints,
        default=[32, 64, 128, 255],
        help="TTL values to test (ping -t). Comma-separated or ranges.",
    )
    parser.add_argument(
        "--tos",
        type=parse_csv_ints,
        default=[0, 32, 96, 184],
        help="DSCP/TOS values in decimal (ping -Q). Default: 0,32,96,184 (CS0, CS1, CS3, CS7).",
    )
    parser.add_argument(
        "--df",
        default="dont,do",
        help="DF/fragmentation modes (ping -M). Options: dont/do/want, comma-separated. Default: dont,do.",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="Use IPv6 (forces ping -6).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable tables.",
    )
    parser.add_argument(
        "--ping-command",
        default=None,
        help="Path to ping binary (default: auto-detect).",
    )
    return parser


def detect_ping_command(force_cmd: Optional[str], ipv6: bool) -> str:
    if force_cmd:
        return force_cmd
    candidate = shutil.which("ping")
    if not candidate:
        raise RuntimeError("Unable to find 'ping' command in PATH.")
    if ipv6:
        # On some systems ping6 is a separate binary; prefer ping6 if available.
        ping6 = shutil.which("ping6")
        if ping6:
            return ping6
    return candidate


def parse_ping_output(stdout: str) -> Tuple[Optional[re.Match], Optional[re.Match]]:
    summary_match = None
    rtt_match = None
    for line in stdout.splitlines():
        if summary_match is None:
            summary_match = SUMMARY_RE.search(line)
        if rtt_match is None:
            rtt_match = RTT_RE.search(line)
        if summary_match and rtt_match:
            break
    return summary_match, rtt_match


def execute_ping(
    cmd: List[str],
) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def run_matrix(
    host: str,
    sizes: Sequence[int],
    df_modes: Sequence[Optional[str]],
    ttl_values: Sequence[Optional[int]],
    tos_values: Sequence[Optional[int]],
    count: int,
    interval: float,
    deadline: Optional[float],
    ipv6: bool,
    ping_cmd: Optional[str],
) -> List[PingResult]:
    command_path = detect_ping_command(ping_cmd, ipv6)
    matrix_results: List[PingResult] = []

    combos = itertools.product(sizes, df_modes, ttl_values, tos_values)
    for size, df_mode, ttl, tos in combos:
        config = PingConfig(size=size, df=df_mode, ttl=ttl, tos=tos)
        cmd = [command_path]
        if ipv6 and command_path.endswith("ping"):
            cmd.append("-6")
        cmd.extend(["-c", str(count), "-s", str(size)])
        if interval:
            cmd.extend(["-i", str(interval)])
        if deadline:
            cmd.extend(["-w", str(deadline)])
        if ttl is not None:
            cmd.extend(["-t", str(ttl)])
        if tos is not None:
            cmd.extend(["-Q", str(tos)])
        if df_mode:
            cmd.extend(["-M", df_mode])
        cmd.append(host)

        code, stdout, stderr = execute_ping(cmd)

        result = PingResult(config=config, exit_code=code, stdout=stdout, stderr=stderr)
        summary_match, rtt_match = parse_ping_output(stdout)

        if summary_match:
            result.transmitted = int(summary_match.group("tx"))
            result.received = int(summary_match.group("rx"))
            result.loss_percent = float(summary_match.group("loss"))
            errors = summary_match.group("errors")
            if errors:
                result.errors = int(errors)
        if rtt_match:
            result.rtt_min = float(rtt_match.group("min"))
            result.rtt_avg = float(rtt_match.group("avg"))
            result.rtt_max = float(rtt_match.group("max"))
            result.rtt_mdev = float(rtt_match.group("mdev"))

        matrix_results.append(result)
    return matrix_results


def print_table(results: Iterable[PingResult]) -> None:
    headers = [
        "Size",
        "DF",
        "TTL",
        "TOS",
        "Loss%",
        "Avg ms",
        "Max ms",
        "Errors",
        "Exit",
    ]
    rows: List[List[str]] = []
    for res in results:
        cfg = res.config
        rows.append(
            [
                str(cfg.size),
                cfg.df or "-",
                str(cfg.ttl) if cfg.ttl is not None else "-",
                str(cfg.tos) if cfg.tos is not None else "-",
                f"{res.loss_percent:.1f}" if res.loss_percent is not None else "?",
                f"{res.rtt_avg:.2f}" if res.rtt_avg is not None else "-",
                f"{res.rtt_max:.2f}" if res.rtt_max is not None else "-",
                str(res.errors) if res.errors is not None else "-",
                str(res.exit_code),
            ]
        )

    # Compute column widths
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    horizontal = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row: Sequence[str]) -> str:
        cells = [cell.ljust(widths[idx]) for idx, cell in enumerate(row)]
        return "| " + " | ".join(cells) + " |"

    print("=== Ping Matrix Results ===")
    print(horizontal)
    print(fmt(headers))
    print(horizontal)
    for row in rows:
        print(fmt(row))
    print(horizontal)


def print_json(results: Iterable[PingResult]) -> None:
    payload = []
    for res in results:
        cfg = res.config
        payload.append(
            {
                "size": cfg.size,
                "df": cfg.df,
                "ttl": cfg.ttl,
                "tos": cfg.tos,
                "transmitted": res.transmitted,
                "received": res.received,
                "loss_percent": res.loss_percent,
                "rtt_min": res.rtt_min,
                "rtt_avg": res.rtt_avg,
                "rtt_max": res.rtt_max,
                "rtt_mdev": res.rtt_mdev,
                "errors": res.errors,
                "exit_code": res.exit_code,
                "stderr": res.stderr.strip(),
            }
        )
    print(json.dumps(payload, indent=2))


def parse_df_modes(df_option: str) -> List[Optional[str]]:
    modes: List[Optional[str]] = []
    for part in df_option.split(","):
        p = part.strip().lower()
        if not p:
            continue
        if p in {"do", "dont", "want"}:
            modes.append(p)
        elif p in {"none", "off"}:
            modes.append(None)
        else:
            raise argparse.ArgumentTypeError(f"Invalid DF mode: {part}")
    if not modes:
        modes.append(None)
    return modes


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        df_modes = parse_df_modes(args.df)
    except argparse.ArgumentTypeError as exc:
        print(f"Invalid --df argument: {exc}", file=sys.stderr)
        return 2

    ttl_values = args.ttl if args.ttl else [None]
    tos_values = args.tos if args.tos else [None]

    results = run_matrix(
        host=args.host,
        sizes=args.sizes,
        df_modes=df_modes,
        ttl_values=ttl_values,
        tos_values=tos_values,
        count=args.count,
        interval=args.interval,
        deadline=args.deadline,
        ipv6=args.ipv6,
        ping_cmd=args.ping_command,
    )

    if args.json:
        print_json(results)
    else:
        print_table(results)
        failures = [res for res in results if not res.success]
        if failures:
            print("\nFailures/Warnings:")
            for res in failures:
                cfg = res.config
                reason = res.stderr.strip() or res.stdout.splitlines()[-1] if res.stdout else ""
                print(
                    f"  size={cfg.size} df={cfg.df} ttl={cfg.ttl} tos={cfg.tos} -> exit {res.exit_code}, "
                    f"loss={res.loss_percent}, note={reason}"
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())

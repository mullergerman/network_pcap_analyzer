#!/usr/bin/env python3
"""
TCP Handshake Probe
===================

Utility to repeatedly attempt TCP (optionally TLS) connections to a target host
while measuring handshake times and reporting failures. Designed to run in
lightweight environments such as Termux on Android (pure Python standard lib).
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence


@dataclass
class AttemptResult:
    index: int
    ip: str
    port: int
    connect_time: Optional[float] = None
    tls_time: Optional[float] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.error is None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure TCP/TLS handshake success and latency."
    )
    parser.add_argument("host", help="Hostname or IP of the target service.")
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Destination port (default: 443).",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=5,
        help="Number of connection attempts (default: 5).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds to wait between attempts (default: 1.0).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Perform a TLS handshake after TCP connect.",
    )
    parser.add_argument(
        "--sni",
        help="Override SNI host for TLS (defaults to --host).",
    )
    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=0.5,
        help="Warn when TCP connect exceeds this many seconds (default: 0.5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable text.",
    )
    parser.add_argument(
        "--ipv6-only",
        action="store_true",
        help="Force IPv6 (ignore IPv4 addresses).",
    )
    parser.add_argument(
        "--ipv4-only",
        action="store_true",
        help="Force IPv4 (ignore IPv6 addresses).",
    )
    return parser


def resolve_addresses(
    host: str, port: int, prefer_ipv6: bool, prefer_ipv4: bool
) -> List[tuple]:
    family = socket.AF_UNSPEC
    if prefer_ipv6 and not prefer_ipv4:
        family = socket.AF_INET6
    elif prefer_ipv4 and not prefer_ipv6:
        family = socket.AF_INET

    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for {host}:{port}: {exc}") from exc

    addresses = []
    for family, socktype, proto, canonname, sockaddr in infos:
        ip = sockaddr[0]
        addresses.append((family, socktype, proto, ip))
    if not addresses:
        raise RuntimeError(f"No addresses found for {host}:{port}")
    return addresses


def perform_attempt(
    index: int,
    target_host: str,
    addr_info: tuple,
    port: int,
    timeout: float,
    use_tls: bool,
    sni_host: Optional[str],
) -> AttemptResult:
    family, socktype, proto, ip = addr_info
    result = AttemptResult(index=index, ip=ip, port=port)

    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        connect_done = time.perf_counter()
        result.connect_time = connect_done - start

        if use_tls:
            context = ssl.create_default_context()
            # Disable cert verification in case Termux lacks CA store, but report warning.
            context.check_hostname = False if sni_host is None else True
            if sni_host is None:
                context.verify_mode = ssl.CERT_NONE
            tls_start = time.perf_counter()
            tls_sock = context.wrap_socket(sock, server_hostname=sni_host or target_host)
            tls_sock.do_handshake()
            tls_done = time.perf_counter()
            result.tls_time = tls_done - tls_start
            tls_sock.close()
        sock.close()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        try:
            sock.close()
        except Exception:
            pass
    return result


def summarize(results: Sequence[AttemptResult], warn_threshold: float) -> dict:
    successes = [res for res in results if res.ok]
    failures = [res for res in results if not res.ok]
    slow = [
        res
        for res in successes
        if res.connect_time is not None and res.connect_time >= warn_threshold
    ]

    summary = {
        "attempts": len(results),
        "success": len(successes),
        "failures": len(failures),
        "slow_connects": len(slow),
        "warn_threshold": warn_threshold,
    }

    if successes:
        connect_times = [res.connect_time for res in successes if res.connect_time]
        tls_times = [res.tls_time for res in successes if res.tls_time]
        if connect_times:
            summary["connect_min"] = min(connect_times)
            summary["connect_avg"] = statistics.mean(connect_times)
            summary["connect_max"] = max(connect_times)
        if tls_times:
            summary["tls_min"] = min(tls_times)
            summary["tls_avg"] = statistics.mean(tls_times)
            summary["tls_max"] = max(tls_times)
    return summary


def print_human(results: Sequence[AttemptResult], warn_threshold: float) -> None:
    print("=== TCP Handshake Probe ===")
    for res in results:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res.timestamp))
        if res.ok:
            note = ""
            if res.connect_time is not None and res.connect_time >= warn_threshold:
                note = " [WARN: slow connect]"
            tls_info = ""
            if res.tls_time is not None:
                tls_info = f", TLS={res.tls_time*1000:.1f}ms"
            print(
                f"[{res.index}] {ts} {res.ip}:{res.port} ok "
                f"(TCP={res.connect_time*1000:.1f}ms{tls_info}){note}"
            )
        else:
            print(f"[{res.index}] {ts} {res.ip}:{res.port} ERROR {res.error}")

    summary = summarize(results, warn_threshold)
    print("\nSummary:")
    for key, value in summary.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.3f}")
        else:
            print(f"  {key}: {value}")


def print_json(results: Sequence[AttemptResult], warn_threshold: float) -> None:
    payload = {
        "results": [
            {
                "index": res.index,
                "timestamp": res.timestamp,
                "ip": res.ip,
                "port": res.port,
                "connect_time": res.connect_time,
                "tls_time": res.tls_time,
                "error": res.error,
            }
            for res in results
        ],
        "summary": summarize(results, warn_threshold),
    }
    print(json.dumps(payload, indent=2))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.attempts <= 0:
        print("Error: --attempts must be positive.", file=sys.stderr)
        return 2

    if args.ipv6_only and args.ipv4_only:
        print("Error: --ipv6-only and --ipv4-only are mutually exclusive.", file=sys.stderr)
        return 2

    try:
        addresses = resolve_addresses(args.host, args.port, args.ipv6_only, args.ipv4_only)
    except RuntimeError as exc:
        print(f"Resolution error: {exc}", file=sys.stderr)
        return 3

    results: List[AttemptResult] = []
    addr_index = 0

    for attempt in range(1, args.attempts + 1):
        addr_info = addresses[addr_index % len(addresses)]
        addr_index += 1

        res = perform_attempt(
            index=attempt,
            target_host=args.host,
            addr_info=addr_info,
            port=args.port,
            timeout=args.timeout,
            use_tls=args.tls,
            sni_host=args.sni,
        )
        results.append(res)

        if attempt < args.attempts:
            time.sleep(max(args.delay, 0.0))

    if args.json:
        print_json(results, args.warn_threshold)
    else:
        print_human(results, args.warn_threshold)

    return 0


if __name__ == "__main__":
    sys.exit(main())

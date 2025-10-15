#!/usr/bin/env python3
"""
Handshake Diagnostics
=====================

Detects TCP handshakes that fail or stall, highlighting SYN/SYN-ACK timing,
RST-aborted negotiations, and late SYN-ACK responses that might indicate loss.

The script supports PCAP and PCAPNG captures, both Ethernet and Linux SLL.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import dpkt
from dpkt.ethernet import VLANtag8021Q


@dataclass
class HandshakeEvent:
    timestamp: float
    flags: str
    seq: int
    ack: int


@dataclass
class HandshakeRecord:
    syn_ts: float
    syn_seq: int
    synack_ts: Optional[float] = None
    synack_seq: Optional[int] = None
    synack_ack: Optional[int] = None
    ack_ts: Optional[float] = None
    completed: bool = False
    aborted_ts: Optional[float] = None
    aborted_type: Optional[str] = None
    events: List[HandshakeEvent] = None

    def __post_init__(self) -> None:
        if self.events is None:
            self.events = []


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Highlight aborted or delayed TCP handshakes in a capture."
    )
    parser.add_argument("pcap", help="PCAP/PCAPNG file to inspect.")
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of records to display (default: 20, 0 = unlimited).",
    )
    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=0.5,
        help="Warn when SYN-ACK arrives later than this threshold in seconds (default: 0.5).",
    )
    parser.add_argument(
        "--only-aborted",
        action="store_true",
        help="Show only handshakes that ended with a RST or never completed.",
    )
    return parser


def iter_packets(path: str) -> Iterator[Tuple[float, bytes]]:
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        pcap_magics = {
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\xd4",
        }
        if magic in pcap_magics:
            reader = dpkt.pcap.Reader(fh)
            yield from reader
        else:
            reader = dpkt.pcapng.Reader(fh)
            for record in reader:
                if not isinstance(record, tuple) or len(record) != 2:
                    continue
                yield record


def decode_l3(raw: bytes) -> Tuple[Optional[int], Optional[object]]:
    """
    Attempt to decode the L3 payload as Ethernet, VLAN-tagged, or Linux SLL.
    Returns (ethertype, network_payload) or (None, None) if unsupported.
    """
    # Try Linux cooked capture first (common in mobile traces).
    try:
        sll = dpkt.sll.SLL(raw)
    except (dpkt.UnpackError, dpkt.NeedData):
        sll = None
    else:
        if sll.ethtype in (0x0800, 0x86DD):
            return sll.ethtype, sll.data

    # Fall back to Ethernet.
    try:
        ethernet = dpkt.ethernet.Ethernet(raw)
    except (dpkt.UnpackError, dpkt.NeedData):
        return None, None
    if ethernet.type == 0:
        return None, None
    payload = ethernet.data
    if isinstance(payload, VLANtag8021Q):
        return payload.type, payload.data
    return ethernet.type, payload


def canonical_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    return (a, b) if a <= b else (b, a)


def inet_to_str(addr: bytes) -> str:
    import socket

    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        if len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except OSError:
        pass
    return addr.hex()


def analyze_handshakes(path: str) -> Dict[
    Tuple[Tuple[str, int], Tuple[str, int]], Dict[str, HandshakeRecord]
]:
    """
    Return a nested dict: key -> { 'client': HandshakeRecord, 'server': HandshakeRecord }
    where each HandshakeRecord tracks the handshake seen from each initiator.
    """
    records: Dict[
        Tuple[Tuple[str, int], Tuple[str, int]], Dict[str, HandshakeRecord]
    ] = defaultdict(dict)

    for ts, raw in iter_packets(path):
        ethtype, payload = decode_l3(raw)
        if ethtype not in (0x0800, 0x86DD) or payload is None:
            continue

        if isinstance(payload, dpkt.ip.IP):
            src_ip = inet_to_str(payload.src)
            dst_ip = inet_to_str(payload.dst)
            transport = payload.data
        elif isinstance(payload, dpkt.ip6.IP6):
            src_ip = inet_to_str(payload.src)
            dst_ip = inet_to_str(payload.dst)
            transport = payload.data
        else:
            continue

        if not isinstance(transport, dpkt.tcp.TCP):
            continue

        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        key = canonical_key(src_ip, src_port, dst_ip, dst_port)
        is_initiator = (src_ip, src_port) <= (dst_ip, dst_port)
        direction = "initiator" if is_initiator else "responder"

        flags = transport.flags
        syn = bool(flags & dpkt.tcp.TH_SYN)
        ack = bool(flags & dpkt.tcp.TH_ACK)
        rst = bool(flags & dpkt.tcp.TH_RST)
        fin = bool(flags & dpkt.tcp.TH_FIN)
        has_payload = len(transport.data) > 0

        # Target record to populate: always keyed by the true initiator endpoint.
        initiator_endpoint = key[0]
        record_set = records[key]
        record = record_set.get(initiator_endpoint)

        if direction == "initiator":
            if syn and not ack:
                if record is None or record.completed:
                    record = HandshakeRecord(
                        syn_ts=ts,
                        syn_seq=int(transport.seq),
                    )
                    record_set[initiator_endpoint] = record
                else:
                    # Repeated SYN (possibly retransmission); keep earliest timestamp.
                    if ts < record.syn_ts:
                        record.syn_ts = ts
                        record.syn_seq = int(transport.seq)
                record.events.append(
                    HandshakeEvent(
                        timestamp=ts,
                        flags="SYN",
                        seq=int(transport.seq),
                        ack=int(transport.ack),
                    )
                )
            elif record is not None:
                if ack and not syn:
                    record.events.append(
                        HandshakeEvent(
                            timestamp=ts,
                            flags="ACK+DATA" if has_payload else "ACK",
                            seq=int(transport.seq),
                            ack=int(transport.ack),
                        )
                    )
                    if not record.completed:
                        record.completed = True
                        record.ack_ts = ts
                elif has_payload and not record.completed:
                    record.events.append(
                        HandshakeEvent(
                            timestamp=ts,
                            flags="DATA",
                            seq=int(transport.seq),
                            ack=int(transport.ack),
                        )
                    )
                    record.completed = True
                    record.ack_ts = ts
                if rst and not record.completed:
                    record.aborted_ts = ts
                    record.aborted_type = "RST (client)"
                    record.events.append(
                        HandshakeEvent(
                            timestamp=ts,
                            flags="RST",
                            seq=int(transport.seq),
                            ack=int(transport.ack),
                        )
                    )
        else:
            # Responder -> initiator (server side)
            if record is None:
                # We saw server reply but never captured client's SYN; skip.
                continue
            if syn and ack and record.synack_ts is None:
                record.synack_ts = ts
                record.synack_seq = int(transport.seq)
                record.synack_ack = int(transport.ack)
                record.events.append(
                    HandshakeEvent(
                        timestamp=ts,
                        flags="SYN-ACK",
                        seq=int(transport.seq),
                        ack=int(transport.ack),
                    )
                )
            elif ack and not syn and not has_payload and record.ack_ts is None:
                record.ack_ts = ts
                record.completed = True
                record.events.append(
                    HandshakeEvent(
                        timestamp=ts,
                        flags="ACK",
                        seq=int(transport.seq),
                        ack=int(transport.ack),
                    )
                )
            elif rst:
                if not record.completed:
                    record.aborted_ts = ts
                    record.aborted_type = "RST (server)"
                record.events.append(
                    HandshakeEvent(
                        timestamp=ts,
                        flags="RST",
                        seq=int(transport.seq),
                        ack=int(transport.ack),
                    )
                )
            elif fin and record.completed:
                record.events.append(
                    HandshakeEvent(
                        timestamp=ts,
                        flags="FIN",
                        seq=int(transport.seq),
                        ack=int(transport.ack),
                    )
                )

    return records


def build_table(headers: List[str], rows: Iterable[List[str]]) -> List[str]:
    data_rows = [list(map(str, row)) for row in rows]
    if not data_rows:
        return []
    widths = [len(h) for h in headers]
    for row in data_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    horizontal = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row: List[str]) -> str:
        return "| " + " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row)) + " |"

    lines = [horizontal, fmt(headers), horizontal]
    for row in data_rows:
        lines.append(fmt(row))
    lines.append(horizontal)
    return lines


def summarize(records, warn_threshold: float, only_aborted: bool, limit: Optional[int]):
    rows: List[List[str]] = []
    warn_threshold = max(warn_threshold, 0.0)

    for key, rec_map in records.items():
        for initiator, rec in rec_map.items():
            responder = key[1] if key[0] == initiator else key[0]

            if rec.completed:
                status = "COMPLETE"
            elif rec.aborted_ts:
                status = "ABORTED"
            else:
                status = "OPEN"
            abort_note = rec.aborted_type or ""
            synack_delay = (
                rec.synack_ts - rec.syn_ts if rec.synack_ts and rec.syn_ts else None
            )
            ack_delay = (
                rec.ack_ts - rec.synack_ts
                if rec.ack_ts and rec.synack_ts
                else None
            )

            warn = ""
            if synack_delay and synack_delay >= warn_threshold:
                warn = f"SYN-ACK delay {synack_delay:.3f}s"
            if rec.aborted_ts and not rec.completed:
                warn = (warn + "; " if warn else "") + f"Aborted via {rec.aborted_type}"

            if only_aborted and rec.completed and not rec.aborted_ts:
                continue

            rows.append(
                [
                    f"{initiator[0]}:{initiator[1]}",
                    f"{responder[0]}:{responder[1]}",
                    f"{rec.syn_ts:.6f}" if rec.syn_ts else "-",
                    f"{synack_delay:.3f}" if synack_delay is not None else "-",
                    f"{ack_delay:.3f}" if ack_delay is not None else "-",
                    status,
                    warn or "-",
                ]
            )

    rows.sort(key=lambda r: float(r[2]) if r[2] != "-" else float("inf"))
    if limit is not None and limit > 0:
        rows = rows[:limit]

    return build_table(
        [
            "Initiator",
            "Responder",
            "SYN time",
            "SYN-ACK delay",
            "ACK delay",
            "Status",
            "Notes",
        ],
        rows,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        records = analyze_handshakes(args.pcap)
    except FileNotFoundError:
        print(f"Error: file '{args.pcap}' not found.", file=sys.stderr)
        return 2

    table = summarize(records, args.warn_threshold, args.only_aborted, args.limit)
    if not table:
        print("No TCP handshakes detected.")
        return 0

    print("=== TCP Handshake Diagnostics ===")
    for line in table:
        print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())

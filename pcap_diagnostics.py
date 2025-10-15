#!/usr/bin/env python3
"""
PCAP Diagnostics
================

Deep-dive analyzer for network captures. It inspects Ethernet/SLL frames,
parses IPv4/IPv6 payloads, and reports on common transport anomalies:
fragmentation, TCP retransmissions/gaps, duplicate ACK bursts, handshake
failures, resets, and unresolved ARP traffic.

The tool works with PCAP and PCAPNG files (Ethernet or Linux cooked capture).
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import dpkt
from dpkt.ethernet import ETH_TYPE_ARP, VLANtag8021Q


# ---------------------------------------------------------------------------
# Helper data structures


@dataclass
class IPv4FragmentEvent:
    timestamp: float
    src: str
    dst: str
    identification: int
    offset: int
    more_fragments: bool


@dataclass
class IPv6FragmentEvent:
    timestamp: float
    src: str
    dst: str
    identification: int
    offset: int
    more_fragments: bool


@dataclass
class DuplicateAckEvent:
    timestamp: float
    ack_number: int
    count: int


@dataclass
class TCPDirectionStats:
    highest_seq_end: Optional[int] = None
    retransmissions: int = 0
    partial_retransmissions: int = 0
    retransmitted_bytes: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    packets_with_data: int = 0
    duplicate_ack_events: List[DuplicateAckEvent] = field(default_factory=list)
    last_ack: Optional[int] = None
    last_ack_count: int = 0


@dataclass
class TCPConnectionStats:
    endpoints: Tuple[Tuple[str, int], Tuple[str, int]]
    syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    handshake_ack_ts: Optional[float] = None
    handshake_direction: Optional[int] = None
    handshake_complete: bool = False
    resets: int = 0
    directions: Tuple[TCPDirectionStats, TCPDirectionStats] = field(
        default_factory=lambda: (TCPDirectionStats(), TCPDirectionStats())
    )


@dataclass
class ArpRequest:
    timestamp: float
    sender_mac: str
    sender_ip: str
    target_ip: str
    responded: bool = False


# ---------------------------------------------------------------------------
# Utility functions


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run transport diagnostics over a PCAP/PCAPNG capture."
    )
    parser.add_argument("pcap", help="Path to the capture file.")
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum rows per event table (default: 20, use 0 for unlimited).",
    )
    return parser


def build_table(headers: List[str], rows: Iterable[Iterable[str]]) -> List[str]:
    data_rows = [list(map(str, row)) for row in rows]
    if not data_rows:
        return []
    widths = [len(h) for h in headers]
    for row in data_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    horizontal = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row: List[str]) -> str:
        cells = [cell.ljust(widths[idx]) for idx, cell in enumerate(row)]
        return "| " + " | ".join(cells) + " |"

    table_lines = [horizontal, fmt(headers), horizontal]
    for row in data_rows:
        table_lines.append(fmt(row))
    table_lines.append(horizontal)
    return table_lines


def canonical_tcp_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    return (left, right) if left <= right else (right, left)


def endpoint_label(endpoint: Tuple[str, int]) -> str:
    return f"{endpoint[0]}:{endpoint[1]}"


def direction_label(
    conn: TCPConnectionStats, direction_idx: int, show_reverse: bool = False
) -> str:
    a, b = conn.endpoints
    if direction_idx == 0:
        src, dst = a, b
    else:
        src, dst = b, a
    if show_reverse:
        return f"{endpoint_label(dst)} -> {endpoint_label(src)}"
    return f"{endpoint_label(src)} -> {endpoint_label(dst)}"


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


def mac_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def inet_to_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return dpkt.utils.inet_to_str(addr)
        if len(addr) == 16:
            return dpkt.utils.inet_to_str(addr)
    except (ValueError, OSError):
        pass
    return repr(addr)


def parse_ipv6_extensions(ip6: dpkt.ip6.IP6):
    nxt = ip6.nxt
    payload = ip6.data
    while isinstance(payload, dpkt.ip6.IP6ExtensionHeader):
        yield nxt, payload
        nxt = payload.nxt
        payload = payload.data
    yield nxt, payload


# ---------------------------------------------------------------------------
# Core analysis


def analyze_capture(path: str):
    protocol_counter = Counter()
    l3_counter = Counter()
    tcp_flows = set()
    udp_flows = set()
    tcp_connections: Dict[
        Tuple[Tuple[str, int], Tuple[str, int]], TCPConnectionStats
    ] = {}
    ipv4_fragments: List[IPv4FragmentEvent] = []
    ipv6_fragments: List[IPv6FragmentEvent] = []
    arp_requests: Dict[Tuple[str, str], ArpRequest] = {}
    arp_replies = 0

    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    total_packets = 0

    for timestamp, raw in iter_packets(path):
        total_packets += 1
        if start_ts is None:
            start_ts = timestamp
        end_ts = timestamp

        network_payload = None
        ethtype = None

        # Prefer Linux cooked capture decoder when it yields a plausible ethertype.
        sll = None
        try:
            candidate_sll = dpkt.sll.SLL(raw)
        except (dpkt.UnpackError, dpkt.NeedData):
            candidate_sll = None
        if candidate_sll is not None and candidate_sll.ethtype in (
            0x0800,
            0x86DD,
            ETH_TYPE_ARP,
        ):
            sll = candidate_sll
            ethtype = sll.ethtype
            network_payload = sll.data

        if network_payload is None:
            ethernet = None
            try:
                ethernet = dpkt.ethernet.Ethernet(raw)
            except (dpkt.UnpackError, dpkt.NeedData):
                ethernet = None
            else:
                if ethernet.type == 0:
                    ethernet = None
            if ethernet is not None:
                ethtype = ethernet.type
                network_payload = ethernet.data
                if isinstance(network_payload, VLANtag8021Q):
                    ethtype = network_payload.type
                    network_payload = network_payload.data

        if ethtype == ETH_TYPE_ARP and network_payload is not None:
            try:
                arp = dpkt.arp.ARP(bytes(network_payload))
            except (dpkt.UnpackError, dpkt.NeedData):
                arp = None
            if arp is not None:
                sender_ip = inet_to_str(arp.spa)
                target_ip = inet_to_str(arp.tpa)
                sender_mac = mac_to_str(arp.sha)
                if arp.op == dpkt.arp.ARP_OP_REQUEST:
                    arp_requests[(sender_ip, target_ip)] = ArpRequest(
                        timestamp=timestamp,
                        sender_mac=sender_mac,
                        sender_ip=sender_ip,
                        target_ip=target_ip,
                    )
                elif arp.op == dpkt.arp.ARP_OP_REPLY:
                    arp_replies += 1
                    if (target_ip, sender_ip) in arp_requests:
                        arp_requests[(target_ip, sender_ip)].responded = True

        ip_layer = None
        if isinstance(network_payload, (dpkt.ip.IP, dpkt.ip6.IP6)):
            ip_layer = network_payload

        if ip_layer is None:
            continue

        if isinstance(ip_layer, dpkt.ip.IP):
            l3_counter["IPv4"] += 1
            src_ip = inet_to_str(ip_layer.src)
            dst_ip = inet_to_str(ip_layer.dst)

            flags_offset = ip_layer._flags_offset  # stable internal field
            frag_flag = bool(flags_offset & dpkt.ip.IP_MF)
            frag_offset = (flags_offset & dpkt.ip.IP_OFFMASK) * 8
            if frag_flag or frag_offset:
                ipv4_fragments.append(
                    IPv4FragmentEvent(
                        timestamp=timestamp,
                        src=src_ip,
                        dst=dst_ip,
                        identification=ip_layer.id,
                        offset=frag_offset,
                        more_fragments=frag_flag,
                    )
                )
        elif isinstance(ip_layer, dpkt.ip6.IP6):
            l3_counter["IPv6"] += 1
            src_ip = inet_to_str(ip_layer.src)
            dst_ip = inet_to_str(ip_layer.dst)

            for nxt, header in parse_ipv6_extensions(ip_layer):
                if isinstance(header, dpkt.ip6.IP6FragmentHeader):
                    ipv6_fragments.append(
                        IPv6FragmentEvent(
                            timestamp=timestamp,
                            src=src_ip,
                            dst=dst_ip,
                            identification=header.id,
                            offset=header.frag_off * 8,
                            more_fragments=bool(header.m_flag),
                        )
                    )
                if not isinstance(header, dpkt.ip6.IP6ExtensionHeader):
                    break
        else:
            continue

        transport = ip_layer.data
        if isinstance(transport, dpkt.tcp.TCP):
            protocol_counter["TCP"] += 1
            flow_key = canonical_tcp_key(src_ip, transport.sport, dst_ip, transport.dport)
            tcp_flows.add(flow_key)

            conn_stats = tcp_connections.get(flow_key)
            if conn_stats is None:
                conn_stats = TCPConnectionStats(endpoints=flow_key)
                tcp_connections[flow_key] = conn_stats

            direction_idx = 0
            if (src_ip, transport.sport) != flow_key[0]:
                direction_idx = 1
            dir_stats = conn_stats.directions[direction_idx]

            syn = bool(transport.flags & dpkt.tcp.TH_SYN)
            ack_flag = bool(transport.flags & dpkt.tcp.TH_ACK)
            fin = bool(transport.flags & dpkt.tcp.TH_FIN)
            rst = bool(transport.flags & dpkt.tcp.TH_RST)

            data_len = len(transport.data)
            seg_len = data_len + int(syn) + int(fin)
            seq = transport.seq
            seq_end = (seq + seg_len) & 0xFFFFFFFF

            has_payload = seg_len > 0

            if has_payload:
                dir_stats.packets_with_data += 1
                if dir_stats.highest_seq_end is None:
                    dir_stats.highest_seq_end = seq_end
                else:
                    highest = dir_stats.highest_seq_end
                    # unwrap simple sequence (no 32-bit wrap support)
                    if seq > highest:
                        dir_stats.gaps += 1
                        dir_stats.gap_bytes += seq - highest
                        dir_stats.highest_seq_end = max(highest, seq_end)
                    elif seq == highest:
                        # in-order continuation (e.g., FIN)
                        dir_stats.highest_seq_end = max(highest, seq_end)
                    else:
                        dir_stats.retransmissions += 1
                        dir_stats.retransmitted_bytes += seg_len
                        if seq_end > highest:
                            dir_stats.partial_retransmissions += 1
                            dir_stats.highest_seq_end = seq_end

            if ack_flag and not has_payload and not (syn or fin or rst):
                if dir_stats.last_ack == transport.ack:
                    dir_stats.last_ack_count += 1
                    if dir_stats.last_ack_count == 3:
                        dir_stats.duplicate_ack_events.append(
                            DuplicateAckEvent(
                                timestamp=timestamp,
                                ack_number=transport.ack,
                                count=dir_stats.last_ack_count,
                            )
                        )
                else:
                    dir_stats.last_ack = transport.ack
                    dir_stats.last_ack_count = 1
            elif has_payload:
                dir_stats.last_ack = None
                dir_stats.last_ack_count = 0

            if syn and not ack_flag:
                conn_stats.syn_ts = timestamp
                conn_stats.handshake_direction = direction_idx
            elif syn and ack_flag:
                conn_stats.synack_ts = timestamp
            elif ack_flag and not syn and conn_stats.synack_ts is not None:
                if (
                    conn_stats.handshake_direction is not None
                    and direction_idx == conn_stats.handshake_direction
                ):
                    conn_stats.handshake_ack_ts = timestamp
                    conn_stats.handshake_complete = True

            if rst:
                conn_stats.resets += 1

        elif isinstance(transport, dpkt.udp.UDP):
            protocol_counter["UDP"] += 1
            udp_flows.add(canonical_tcp_key(src_ip, transport.sport, dst_ip, transport.dport))
        elif isinstance(transport, dpkt.icmp.ICMP) or isinstance(
            transport, dpkt.icmp6.ICMP6
        ):
            protocol_counter["ICMP"] += 1
        else:
            protocol_counter["Other"] += 1

    return {
        "protocol_counter": protocol_counter,
        "l3_counter": l3_counter,
        "tcp_flows": tcp_flows,
        "udp_flows": udp_flows,
        "tcp_connections": tcp_connections,
        "ipv4_fragments": ipv4_fragments,
        "ipv6_fragments": ipv6_fragments,
        "arp_requests": arp_requests,
        "arp_replies": arp_replies,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "total_packets": total_packets,
    }


# ---------------------------------------------------------------------------
# Reporting


def limited_rows(rows: List[List[str]], limit: Optional[int]) -> List[List[str]]:
    if limit is None or limit <= 0:
        return rows
    return rows[:limit]


def print_overview(stats) -> None:
    start_ts = stats["start_ts"]
    end_ts = stats["end_ts"]
    duration = None
    if start_ts is not None and end_ts is not None:
        duration = end_ts - start_ts

    print("=== Capture Overview ===")
    print(f"Total packets: {stats['total_packets']}")
    if duration is not None:
        print(f"Capture duration: {duration:.3f} seconds")
    if stats["l3_counter"]:
        print(
            "Layer-3 distribution: "
            + ", ".join(f"{proto}={count}" for proto, count in stats["l3_counter"].items())
        )
    print(
        "Protocols: "
        + ", ".join(
            f"{proto}={count}" for proto, count in stats["protocol_counter"].items()
        )
    )
    print(
        f"Unique TCP flows: {len(stats['tcp_flows'])} | Unique UDP flows: {len(stats['udp_flows'])}"
    )
    print()


def report_fragments(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    limit: Optional[int],
) -> None:
    if not rows:
        return
    print(title)
    table_lines = build_table(headers, limited_rows(rows, limit))
    for line in table_lines:
        print(line)
    print()


def report_tcp_anomalies(stats, limit: Optional[int]) -> None:
    tcp_connections: Dict[
        Tuple[Tuple[str, int], Tuple[str, int]], TCPConnectionStats
    ] = stats["tcp_connections"]

    # Retransmissions / Gaps
    retrans_rows: List[List[str]] = []
    gap_rows: List[List[str]] = []
    dup_ack_rows: List[List[str]] = []
    reset_rows: List[List[str]] = []
    handshake_rows: List[List[str]] = []

    for conn in tcp_connections.values():
        for direction_idx, dir_stats in enumerate(conn.directions):
            flow_label = direction_label(conn, direction_idx)
            if dir_stats.retransmissions:
                retrans_rows.append(
                    [
                        flow_label,
                        str(dir_stats.retransmissions),
                        str(dir_stats.partial_retransmissions),
                        str(dir_stats.retransmitted_bytes),
                    ]
                )
            if dir_stats.gaps:
                gap_rows.append(
                    [
                        flow_label,
                        str(dir_stats.gaps),
                        str(dir_stats.gap_bytes),
                    ]
                )
            for event in dir_stats.duplicate_ack_events:
                dup_ack_rows.append(
                    [
                        flow_label,
                        f"{event.timestamp:.6f}",
                        str(event.ack_number),
                        str(event.count),
                    ]
                )

        if conn.resets:
            reset_rows.append(
                [
                    f"{endpoint_label(conn.endpoints[0])} <> {endpoint_label(conn.endpoints[1])}",
                    str(conn.resets),
                ]
            )

        if conn.syn_ts is not None and not conn.handshake_complete:
            handshake_rows.append(
                [
                    f"{endpoint_label(conn.endpoints[0])} <> {endpoint_label(conn.endpoints[1])}",
                    f"SYN@{conn.syn_ts:.6f}",
                    f"SYN-ACK@{conn.synack_ts:.6f}" if conn.synack_ts else "-",
                    "Incomplete",
                ]
            )

    report_fragments(
        "=== TCP Retransmissions ===",
        ["Flow direction", "Retrans", "Partial", "Bytes"],
        retrans_rows,
        limit,
    )
    report_fragments(
        "=== TCP Forward Gaps (potential loss) ===",
        ["Flow direction", "Gaps", "Gap bytes"],
        gap_rows,
        limit,
    )
    report_fragments(
        "=== Duplicate ACK Bursts ===",
        ["Flow direction", "Timestamp", "ACK", "Count"],
        dup_ack_rows,
        limit,
    )
    report_fragments(
        "=== TCP Resets ===",
        ["Flow", "RST packets"],
        reset_rows,
        limit,
    )
    report_fragments(
        "=== Incomplete TCP Handshakes ===",
        ["Flow", "SYN", "SYN-ACK", "Status"],
        handshake_rows,
        limit,
    )


def report_arp(stats, limit: Optional[int]) -> None:
    unresolved = [
        req
        for req in stats["arp_requests"].values()
        if not req.responded
    ]
    if not unresolved:
        return

    rows = [
        [
            f"{req.timestamp:.6f}",
            req.sender_ip,
            req.target_ip,
            req.sender_mac,
        ]
        for req in unresolved
    ]

    print("=== Unanswered ARP Requests ===")
    table_lines = build_table(
        ["Timestamp", "Requester IP", "Query IP", "Requester MAC"],
        limited_rows(rows, limit),
    )
    for line in table_lines:
        print(line)
    print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        stats = analyze_capture(args.pcap)
    except FileNotFoundError:
        print(f"Error: capture file '{args.pcap}' not found.", file=sys.stderr)
        return 2

    print_overview(stats)

    ipv4_rows = [
        [
            f"{event.timestamp:.6f}",
            f"{event.src} -> {event.dst}",
            str(event.identification),
            str(event.offset),
            "Y" if event.more_fragments else "N",
        ]
        for event in stats["ipv4_fragments"]
    ]
    report_fragments(
        "=== IPv4 Fragmentation Events ===",
        ["Timestamp", "Flow", "ID", "Offset", "More"],
        ipv4_rows,
        args.limit,
    )

    ipv6_rows = [
        [
            f"{event.timestamp:.6f}",
            f"{event.src} -> {event.dst}",
            str(event.identification),
            str(event.offset),
            "Y" if event.more_fragments else "N",
        ]
        for event in stats["ipv6_fragments"]
    ]
    report_fragments(
        "=== IPv6 Fragmentation Events ===",
        ["Timestamp", "Flow", "ID", "Offset", "More"],
        ipv6_rows,
        args.limit,
    )

    report_tcp_anomalies(stats, args.limit)
    report_arp(stats, args.limit)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""DNS Timer Analyzer
=====================

CLI utility for measuring DNS transaction times inside a PCAP/PCAPNG capture.
The script groups packets by client/server flow, DNS transaction ID, and
question tuple so concurrent queries are not mixed together.

Dependencies:
    - dpkt (https://github.com/kbandla/dpkt)
"""
from __future__ import annotations

import argparse
import csv
import socket
import statistics
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Tuple

import dpkt

DNS_QTYPE_NAMES = {
    getattr(dpkt.dns, "DNS_A", 1): "A",
    getattr(dpkt.dns, "DNS_AAAA", 28): "AAAA",
    getattr(dpkt.dns, "DNS_CNAME", 5): "CNAME",
    getattr(dpkt.dns, "DNS_NS", 2): "NS",
    getattr(dpkt.dns, "DNS_PTR", 12): "PTR",
    getattr(dpkt.dns, "DNS_MX", 15): "MX",
    getattr(dpkt.dns, "DNS_TXT", 16): "TXT",
    getattr(dpkt.dns, "DNS_SOA", 6): "SOA",
    getattr(dpkt.dns, "DNS_SRV", 33): "SRV",
    getattr(dpkt.dns, "DNS_SVCB", 64): "SVCB",
    65: "HTTPS",
    getattr(dpkt.dns, "DNS_ANY", 255): "ANY",
}


@dataclass(frozen=True)
class FlowKey:
    """Represents a unique client/server tuple."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    proto: str


@dataclass
class QueryRecord:
    """Stores metadata for a DNS query waiting for a response."""

    key: FlowKey
    dns_id: int
    qname: str
    qtype: str
    timestamp: float
    packet_index: int


@dataclass
class Transaction:
    """Holds matched query/response information."""

    query: QueryRecord
    response_ts: float
    rcode: int
    answer_count: int
    authoritative: bool

    @property
    def delta_ms(self) -> float:
        return (self.response_ts - self.query.timestamp) * 1000.0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze DNS query/response timings from a PCAP capture."
    )
    parser.add_argument("pcap", help="Path to the input PCAP file.")
    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="Write per-transaction metrics to a CSV file.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print per-domain timing aggregates.",
    )
    parser.add_argument(
        "--filter-domain",
        metavar="SUBSTRING",
        help="Only include domains containing this case-insensitive substring.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Only display the first N matched transactions.",
    )
    parser.add_argument(
        "--sort",
        choices=["capture", "rtt-desc", "rtt-asc"],
        default="capture",
        help="Ordering for the transaction output (default: capture).",
    )
    parser.add_argument(
        "--show-unmatched",
        action="store_true",
        help="Display a table with queries that did not receive an answer.",
    )
    return parser


def build_table(headers: List[str], rows: Iterable[List[str]]) -> List[str]:
    data_rows = [list(map(str, row)) for row in rows]
    widths = [len(h) for h in headers]
    for row in data_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    horizontal = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def format_row(row: List[str]) -> str:
        cells = [cell.ljust(widths[idx]) for idx, cell in enumerate(row)]
        return "| " + " | ".join(cells) + " |"

    table_lines = [horizontal, format_row(headers), horizontal]
    for row in data_rows:
        table_lines.append(format_row(row))
    table_lines.append(horizontal)
    return table_lines


def normalize_qname(raw_qname: Optional[bytes]) -> Optional[str]:
    if raw_qname is None:
        return None
    if isinstance(raw_qname, bytes):
        decoded = raw_qname.decode("utf-8", errors="ignore")
    else:
        decoded = str(raw_qname)
    return decoded.rstrip(".").lower()


def lookup_qtype_name(qtype_value: Optional[int]) -> Optional[str]:
    if qtype_value is None:
        return None
    return DNS_QTYPE_NAMES.get(qtype_value, f"TYPE{qtype_value}")


OutstandingKey = Tuple[FlowKey, int, str, str]


def pop_outstanding(
    outstanding: Dict[OutstandingKey, Deque[QueryRecord]],
    flow_key: FlowKey,
    dns_id: int,
    qname: Optional[str],
    qtype: Optional[str],
) -> Optional[QueryRecord]:
    """
    Retrieve the earliest outstanding query that matches the response.
    Falls back to any query with the same flow and DNS ID if the response
    lacks question data.
    """
    if qname and qtype:
        candidate_key = (flow_key, dns_id, qname, qtype)
        queue = outstanding.get(candidate_key)
        if queue:
            record = queue.popleft()
            if not queue:
                del outstanding[candidate_key]
            return record

    for key in list(outstanding.keys()):
        key_flow, key_dns_id, _, _ = key
        if key_flow == flow_key and key_dns_id == dns_id:
            queue = outstanding[key]
            record = queue.popleft()
            if not queue:
                del outstanding[key]
            return record
    return None


def analyze_pcap(
    path: str, domain_filter: Optional[str] = None
) -> Tuple[List[Transaction], List[QueryRecord]]:
    domain_filter_norm = (
        domain_filter.lower() if domain_filter is not None else None
    )

    transactions: List[Transaction] = []
    outstanding: Dict[OutstandingKey, Deque[QueryRecord]] = defaultdict(deque)
    packet_index = 0

    def iter_packets(file_path: str) -> Iterator[Tuple[float, bytes]]:
        with open(file_path, "rb") as fh:
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
                    yield record  # type: ignore[misc]

    for timestamp, raw in iter_packets(path):
        packet_index += 1
        try:
            ethernet = dpkt.ethernet.Ethernet(raw)
        except (dpkt.UnpackError, dpkt.NeedData):
            continue

        ip_layer = ethernet.data
        if isinstance(ip_layer, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip_layer.src)
            dst_ip = socket.inet_ntoa(ip_layer.dst)
        elif isinstance(ip_layer, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
        else:
            continue

        transport = ip_layer.data
        proto_label = None
        payload = b""
        if isinstance(transport, dpkt.udp.UDP):
            proto_label = "UDP"
            src_port = transport.sport
            dst_port = transport.dport
            payload = bytes(transport.data)
        elif isinstance(transport, dpkt.tcp.TCP):
            proto_label = "TCP"
            src_port = transport.sport
            dst_port = transport.dport
            tcp_payload = bytes(transport.data)
            if len(tcp_payload) < 2:
                continue
            length = int.from_bytes(tcp_payload[:2], "big")
            payload = tcp_payload[2:2 + length]
        else:
            continue

        if not payload:
            continue

        try:
            dns = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, dpkt.NeedData, ValueError):
            continue

        if dns.opcode != dpkt.dns.DNS_QUERY:
            continue

        flow_key_query = FlowKey(
            client_ip=src_ip,
            client_port=int(src_port),
            server_ip=dst_ip,
            server_port=int(dst_port),
            proto=proto_label,
        )

        if dns.qr == dpkt.dns.DNS_Q:  # Query
            if not dns.qd:
                continue
            question = dns.qd[0]
            qname = normalize_qname(question.name)
            qtype = lookup_qtype_name(question.type)
            if qname is None or qtype is None:
                continue
            record = QueryRecord(
                key=flow_key_query,
                dns_id=int(dns.id),
                qname=qname,
                qtype=qtype,
                timestamp=float(timestamp),
                packet_index=packet_index,
            )
            outstanding[(flow_key_query, record.dns_id, record.qname, record.qtype)].append(
                record
            )
        elif dns.qr == dpkt.dns.DNS_R:  # Response
            flow_key_response = FlowKey(
                client_ip=dst_ip,
                client_port=int(dst_port),
                server_ip=src_ip,
                server_port=int(src_port),
                proto=proto_label,
            )

            qname = None
            qtype = None
            if dns.qd:
                qname = normalize_qname(dns.qd[0].name)
                qtype = lookup_qtype_name(dns.qd[0].type)

            matched_query = pop_outstanding(
                outstanding,
                flow_key_response,
                int(dns.id),
                qname,
                qtype,
            )
            if matched_query is None:
                continue

            if (
                domain_filter_norm is not None
                and domain_filter_norm not in matched_query.qname
            ):
                continue

            transactions.append(
                Transaction(
                    query=matched_query,
                    response_ts=float(timestamp),
                    rcode=int(dns.rcode),
                    answer_count=len(dns.an) if dns.an else 0,
                    authoritative=bool(dns.aa),
                )
            )

    unmatched = [
        query
        for queues in outstanding.values()
        for query in queues
        if domain_filter_norm is None or domain_filter_norm in query.qname
    ]
    return transactions, unmatched


def print_transactions(transactions: Iterable[Transaction], limit: Optional[int]) -> None:
    headers = [
        "#",
        "Domain",
        "Type",
        "Client -> Server",
        "Proto",
        "RTT ms",
        "Answers",
        "RCODE",
        "Auth",
    ]
    rows: List[List[str]] = []

    for idx, txn in enumerate(transactions, start=1):
        if limit is not None and idx > limit:
            break
        query = txn.query
        flow = query.key
        rows.append(
            [
                str(idx),
                query.qname,
                query.qtype,
                f"{flow.client_ip}:{flow.client_port} -> {flow.server_ip}:{flow.server_port}",
                flow.proto,
                f"{txn.delta_ms:.3f}",
                str(txn.answer_count),
                str(txn.rcode),
                "Y" if txn.authoritative else "N",
            ]
        )

    for line in build_table(headers, rows):
        print(line)


def write_csv(path: str, transactions: Iterable[Transaction]) -> None:
    fieldnames = [
        "index",
        "domain",
        "query_type",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "protocol",
        "dns_id",
        "query_ts",
        "response_ts",
        "rtt_ms",
        "answer_count",
        "rcode",
        "authoritative",
    ]
    with open(path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for idx, txn in enumerate(transactions, start=1):
            query = txn.query
            flow = query.key
            writer.writerow(
                {
                    "index": idx,
                    "domain": query.qname,
                    "query_type": query.qtype,
                    "client_ip": flow.client_ip,
                    "client_port": flow.client_port,
                    "server_ip": flow.server_ip,
                    "server_port": flow.server_port,
                    "protocol": flow.proto,
                    "dns_id": query.dns_id,
                    "query_ts": f"{query.timestamp:.6f}",
                    "response_ts": f"{txn.response_ts:.6f}",
                    "rtt_ms": f"{txn.delta_ms:.3f}",
                    "answer_count": txn.answer_count,
                    "rcode": txn.rcode,
                    "authoritative": txn.authoritative,
                }
            )


def print_summary(transactions: Iterable[Transaction]) -> None:
    per_domain: Dict[str, List[float]] = defaultdict(list)
    for txn in transactions:
        per_domain[txn.query.qname].append(txn.delta_ms)

    if not per_domain:
        print("No transactions matched for summary.")
        return

    headers = ["Domain", "Count", "Avg ms", "P95 ms", "Max ms"]
    rows: List[List[str]] = []
    for domain, samples in sorted(per_domain.items()):
        avg = statistics.mean(samples)
        samples_sorted = sorted(samples)
        p95_index = max(int(round(0.95 * (len(samples_sorted) - 1))), 0)
        p95 = samples_sorted[p95_index]
        rows.append(
            [
                domain,
                str(len(samples)),
                f"{avg:.3f}",
                f"{p95:.3f}",
                f"{max(samples_sorted):.3f}",
            ]
        )

    print("\nPer-domain summary:")
    for line in build_table(headers, rows):
        print(line)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        transactions, unmatched = analyze_pcap(
            args.pcap, domain_filter=args.filter_domain
        )
    except FileNotFoundError:
        print(f"Error: PCAP file '{args.pcap}' not found.", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3

    if args.sort == "rtt-desc":
        transactions_to_show = sorted(
            transactions, key=lambda txn: txn.delta_ms, reverse=True
        )
    elif args.sort == "rtt-asc":
        transactions_to_show = sorted(
            transactions, key=lambda txn: txn.delta_ms, reverse=False
        )
    else:
        transactions_to_show = list(transactions)

    if not transactions_to_show:
        print("No DNS transactions matched the provided criteria.")
    else:
        print_transactions(transactions_to_show, limit=args.limit)

    if args.csv and transactions_to_show:
        write_csv(args.csv, transactions_to_show)
        print(f"\nCSV report written to {args.csv}")

    if args.summary and transactions_to_show:
        print_summary(transactions_to_show)

    if unmatched:
        print(
            f"\nUnmatched queries (likely timeouts or missing responses): {len(unmatched)}"
        )
        if args.show_unmatched:
            headers = [
                "#",
                "Domain",
                "Type",
                "Client -> Server",
                "Proto",
                "Query TS",
            ]
            rows: List[List[str]] = []
            for idx, query in enumerate(unmatched, start=1):
                flow = query.key
                rows.append(
                    [
                        str(idx),
                        query.qname,
                        query.qtype,
                        f"{flow.client_ip}:{flow.client_port} -> {flow.server_ip}:{flow.server_port}",
                        flow.proto,
                        f"{query.timestamp:.6f}",
                    ]
                )
            for line in build_table(headers, rows):
                print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

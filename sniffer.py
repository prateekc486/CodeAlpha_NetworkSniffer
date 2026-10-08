#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures packets with scapy and shows, for each one:
  - timestamp, protocol, source -> destination (IP:port)
  - TCP flags / ICMP type / DNS query / HTTP request line
  - a hex + ASCII preview of the payload
On exit it prints a summary (protocol counts, top talkers, total bytes).

Use ONLY on networks you own or have permission to monitor.
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, get_if_list, Raw
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    sys.exit("scapy is not installed. Run: pip install scapy")

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"HTTP/")
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}

proto_count = Counter()
talkers = Counter()
total_bytes = 0
packet_no = 0
saved_packets = []


def payload_preview(pkt, limit):
    """Return (hex_string, ascii_string) for the first `limit` payload bytes."""
    if limit <= 0 or Raw not in pkt:
        return None
    data = bytes(pkt[Raw].load)[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return data.hex(" "), text


def endpoint(addr, port):
    """Format address:port; IPv6 addresses are wrapped as [addr]:port."""
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def summarize(pkt):
    """Work out (protocol, src, dst, info, src_host) for a packet.

    src_host is the bare source address (no port), used for the top-talkers table.
    """
    if ARP in pkt:
        a = pkt[ARP]
        if a.op == 1:
            info = f"who-has {a.pdst} tell {a.psrc}"
        elif a.op == 2:
            info = f"{a.psrc} is-at {a.hwsrc}"
        else:
            info = f"op {a.op}"
        return "ARP", a.psrc, a.pdst, info, a.psrc

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        ip_proto = pkt[IP].proto
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        ip_proto = pkt[IPv6].nh
    elif Ether in pkt:
        return "ETH", pkt[Ether].src, pkt[Ether].dst, f"ethertype 0x{pkt[Ether].type:04x}", pkt[Ether].src
    else:
        return "OTHER", "?", "?", pkt.summary(), "?"

    if TCP in pkt:
        t = pkt[TCP]
        proto = "TCP"
        info = f"flags=[{t.flags}] seq={t.seq}"
        if Raw in pkt and bytes(pkt[Raw].load).startswith(HTTP_METHODS):
            proto = "HTTP"
            first_line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0][:80]
            info = first_line.decode("ascii", errors="replace")
        return proto, endpoint(src, t.sport), endpoint(dst, t.dport), info, src

    if UDP in pkt:
        u = pkt[UDP]
        proto = "UDP"
        info = f"len={u.len}"
        if DNS in pkt:
            proto = "DNS"
            try:
                d = pkt[DNS]
                kind = "response" if d.qr else "query"
                name = d.qd.qname.decode(errors="replace") if d.qd else "?"
                info = f"{kind} {name}"
            except Exception:
                info = "malformed DNS"
        return proto, endpoint(src, u.sport), endpoint(dst, u.dport), info, src

    if ICMP in pkt:
        ic = pkt[ICMP]
        return "ICMP", src, dst, ICMP_TYPES.get(ic.type, f"type {ic.type}"), src

    return f"IP/{ip_proto}", src, dst, "", src


def make_handler(args):
    def handle(pkt):
        global packet_no, total_bytes
        packet_no += 1
        size = len(pkt)
        total_bytes += size

        proto, src, dst, info, src_host = summarize(pkt)
        proto_count[proto] += 1
        talkers[src_host] += 1
        if args.write:
            saved_packets.append(pkt)

        ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
        print(f"#{packet_no:<4} {ts}  {proto:<5} {src} -> {dst}  {info}  ({size} B)")

        preview = payload_preview(pkt, args.payload)
        if preview:
            hex_str, text = preview
            print(f"        hex  : {hex_str}")
            print(f"        ascii: {text}")

    return handle


def print_summary():
    print("\n" + "=" * 60)
    print(f"Captured {packet_no} packets, {total_bytes} bytes total")
    if proto_count:
        print("\nProtocol breakdown:")
        for proto, n in proto_count.most_common():
            print(f"  {proto:<8} {n:>5}  ({n / packet_no * 100:.1f}%)")
        print("\nTop talkers (by packets sent):")
        for host, n in talkers.most_common(5):
            print(f"  {host:<40} {n:>5}")
    print("=" * 60)


def build_parser():
    p = argparse.ArgumentParser(description="Basic network sniffer (CodeAlpha Task 1)")
    p.add_argument("-i", "--iface", help="interface to sniff on (default: scapy's default)")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80' or 'udp port 53'")
    p.add_argument("-p", "--payload", type=int, default=48, help="payload bytes to show (0 = hide)")
    p.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    p.add_argument("-r", "--read", help="analyse an existing .pcap file instead of sniffing live")
    p.add_argument("-l", "--list-ifaces", action="store_true", help="list interfaces and exit")
    return p


def main():
    args = build_parser().parse_args()

    if args.list_ifaces:
        print("\n".join(get_if_list()))
        return

    handler = make_handler(args)
    try:
        if args.read:
            print(f"[*] Reading {args.read}")
            sniff(offline=args.read, prn=handler, store=False, count=args.count or 0)
        else:
            print(f"[*] Sniffing on {args.iface or 'default interface'}"
                  f"{' filter=' + repr(args.filter) if args.filter else ''}  (Ctrl+C to stop)")
            sniff(iface=args.iface, filter=args.filter or None, prn=handler,
                  store=False, count=args.count or 0)
    except PermissionError:
        sys.exit("[!] Permission denied. Run with sudo (Linux/macOS) or as Administrator with Npcap (Windows).")
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit(f"[!] Capture error: {e}")

    print_summary()
    if args.write and saved_packets:
        wrpcap(args.write, saved_packets)
        print(f"[*] Saved {len(saved_packets)} packets to {args.write}")


if __name__ == "__main__":
    main()

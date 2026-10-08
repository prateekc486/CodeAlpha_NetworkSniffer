#!/usr/bin/env python3
"""
Regenerates sample.pcap: eight synthetic packets that exercise every protocol
the sniffer decodes (ARP, DNS query/response, TCP SYN, HTTP request/response,
ICMP echo request/reply). All addresses are private or documentation-style.

Usage:  python tools/make_sample_pcap.py [output_file]
"""

import sys

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"

packets = [
    # 1. ARP who-has
    Ether() / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1"),
    # 2-3. DNS query and response for example.com
    Ether() / IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=53211, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
    Ether() / IP(src="8.8.8.8", dst="192.168.1.10")
    / UDP(sport=53, dport=53211)
    / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")),
    # 4. TCP SYN to port 80
    Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="S", seq=100),
    # 5-6. HTTP request and response
    Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="PA", seq=101)
    / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    Ether() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=40000, flags="PA", seq=500)
    / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>"),
    # 7-8. ICMP echo request and reply
    Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8) / Raw(b"abcdefgh"),
    Ether() / IP(src="1.1.1.1", dst="192.168.1.10") / ICMP(type=0) / Raw(b"abcdefgh"),
]

wrpcap(out, packets)
print(f"Wrote {len(packets)} packets to {out}")

# Author: TK
# Date: 22-01-2026
# Description: Python file which captures packets on the network and parse
# through them.

from __future__ import annotations
from typing import Iterable, Iterator, Optional
from scapy.all import rdcap
from scapy.layers.inet import IP, TCP, UDP
from .models import NetEvents

def events_from_pcap(pcap_path: str) -> Iterator[NetEvent]:
    pkts = rdpcap(pcap_path)
    for p in pkts:
        if IP not in p:
            continue

        ip = p[IP]
        proto = "IP"

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        info = {}

        if TCP in p:
            t = p[TCP]
            proto = "TCP"
            src_port, dst_port = int(t.sport), int(t.dport)
            info = {"flags": str(t.flags)}

        elif UDP in P:
            u = p[UDP]
            proto = "UDP"
            src_port, dst_port = int(u.sport), int(u.dport)

        yield NetEvent(
            ts = float(p.time),
            src_ip = str(ip.src),
            dst_ip = str(ip.dst),
            proto = proto,
            src_port = src_port,
            dst_port = dst_port,
            info = info or None,
        )



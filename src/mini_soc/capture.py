# Author: TK
# Date: 22-01-2026
# Description: reads a PCAP and converts packets into normalized NetEvent objs.

from __future__ import annotations
from typing import Iterable, Iterator, Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP

from .models import NetEvent

def events_from_pcap(pcap_path: str) -> Iterator[NetEvent]:
    """
    Loads packets from a PCAP file and yields normalized NetEvent objs.
    only ipv4 packets are considered (must have IP layer).
    for  tcp packets, flags are included in event.info.
    """
    pkts = rdpcap(pcap_path)

    for p in pkts:
        if IP not in p:
            continue

        ip = p[IP]
        proto = "IP"

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        info = None

        if TCP in p:
            t = p[TCP]
            proto = "TCP"
            src_port, dst_port = int(t.sport), int(t.dport)
            info = {"flags": str(t.flags)}

        elif UDP in p:
            u = p[UDP]
            proto = "UDP"
            src_port, dst_port = int(u.sport), int(u.dport)
            info = None

        yield NetEvent(
            ts = float(p.time),
            src_ip = str(ip.src),
            dst_ip = str(ip.dst),
            proto = proto,
            src_port = src_port,
            dst_port = dst_port,
            info = info,
        )



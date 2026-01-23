# Author:TK
# Date: 23-01-2026
# Desc:

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple, List

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR

@dataclass
class Alert:
    rule: str
    severity: str
    timestamp: float
    src: str
    dst: str
    message: str
    metadata: dict

class DnsSpikeRule:
    """
    Detects DNS query spikes per source IP using a sliding time window.
    Triggers on either:
        - Total queries in window >= query_threshold
        - unique qnames in window >= unique_threshold
    """
    name = "dns_spike"
    description = "Detect DNS query spikes per host"
    severity = "medium"

    def __init__(
        self,
        window_seconds: int = 10,
        query_threshold: int = 25,
        unique_threshold: int = 15,
        min_window_packets: int = 10,
        cooldown_seconds: int = 30,
        track_unique: bool = True,

    ):
        self.window_seconds = window_seconds
        self.query_threshold = query_threshold
        self.unique_threshold = unique_threshold
        self.min_window_packets = min_window_packets
        self.cooldown_seconds = cooldown_seconds
        self.track_unique = track_unique

        self.q_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.qname_times: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self,qname_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: default)
        self.last_alert_time: Dict[str, float] = {}

    def _prune(self, src: str, now: float):
        cutoff = now - self.window_seconds

        # prune total query timestamps
        qt = self.q_times[src]
        while qt and qt[0] < cutoff:
            qt.popleft()

        if not self.track_unique:
            return

        # prune qname timestamps + counts
        qnt = self.qname_times[src]
        qnc = self.qname_counts[src]
        while qnt and qnt[0][0] < cutoff:
            _, qname = qnt.popleft()
            qnc[qname] -= 1
            if qnc[qname] <= 0:
                del qnc[qname]

    def _cooldown_ok(self, src: str, now: float) -> bool:
        last = self.last_alert_time.get(src)
        return last is None or (now - last) >= self.cooldown_seconds


    def on_packet(self, pkt, ts: float) -> List[Alert]:
        """
        Return 0..n alerts for this packet.

        """
        alerts: List[Alert] = []

        # Must be DNS query over UDP/53
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return alerts

        ip = pkt[IP]
        udp = pkt[UDP]
        dns = pkt[DNS]

        # only queries (qr = 0). Also ensure it has a question record.
        if dns.qr != 0 or not pkt.haslayer(DNSQR):
            return alerts

        # client -> server is dport 53
        if udp.dport != 53:
            return alerts

        src = ip.src
        dst = ip.dst
        now = ts

        # record
        self.q_times[src].append(now)

        qname = None
        if self.track_unique:
            try:
                raw = pkt[DNSQR].qname
                qname = raw.decode(errors = "ignore"),rstrip(".").lower()
            except Exception:
                qname = "<decode_error>"

            self.qname_times[src].append((now, qname))
            self.qname__counts[src][qname] += 1

        # remove old entries
        self._prune(src, now)


        total_q = len(self.q_times[src])
        if total_q < self.min_window_packets:
            return alerts

        unique_q = len(self.qname_counts[src]) if self.track_unique else 0

        trigger_rate = total_q >= self.query_threshold
        trigger_unique = self.track_unique and unique_q >= self.unique_threshold

        if (trigger_rate or trigger_unique) and self._cooldown_ok(src, now):
            self.last_alert_time[src] = now

            reason = []
            if trigger_rate:
                reason.append(f"rate={total_q}/{self.window_seconds}s
                              (>= {self.query_threshold})")
            if trigger_unique:
                reason.append(f"unique={unique_q}/{self.window_seconds}s
                              (>= {self.unique_threshold})")

            alerts.append(
                Alert(
                    rule = self.name,
                    severity = self.severity,
                    timestamp = now,
                    src = src,
                    dst = dst,
                    message = f"DNS spike detected from {src}: " + ", ".join(reason),
                    metadata={
                        "window_seconds": self.window_seconds,
                        "total_queries_in_window": total_q,
                        "unique_qnames_in_window": unique_q,
                        "dst_dns_server": dst,
                        "example_qname": qname,
                    },
                )
            )

        return alerts



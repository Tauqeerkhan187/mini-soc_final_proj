# Author:TK
# Date: 23-01-2026
# Desc: Detects DNS query spikes per src ip using a sliding time window.

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple, List

from .base import Rule
from ..models import NetEvent, Alert


class DnsSpikeRule(Rule):
    """
    Detects DNS query spikes per source IP using a sliding time window.
    Triggers on either:
        - Total queries in window >= query_threshold
        - unique qnames in window >= unique_threshold
    """
    rule_id = "dns_spike"
    name = "DNS Spike"
    severity = "medium"

    def __init__(self, config = None):

        super().__init__(config)

        # Sliding win parameters

        self.window_seconds: int = int(self.config.get(
            "windows_seconds", 10))
        self.query_threshold: int = int(self.config.get
                                        ("query_threshold", 15))
        # unique threshold 0 = disabled
        self.unique_dst_threshold: int = int(self.config.get(
            "unique_dst_threshold", 0))
        self.min_window_packets: int = int(self.config.get
                                           ("min_window_packets", 8))
        self.cooldown_seconds: int = int(self.config.get
                                         ("cooldown_seconds", 20))

        self.q_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.dst_times: Dict[str, Deque[Tuple[float, str]]] = defaultdict(
            deque)
        self.dst_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self.last_alert_time: Dict[str, float] = {}


    def _prune(self, src: str, now: float) -> None:
        """
        removes entries older than win_seconds for this src.
        """
        cutoff = now - self.window_seconds

        # prune total query timestamps
        qt = self.q_times[src]
        while qt and qt[0] < cutoff:
            qt.popleft()

        if self.unique_dst_threshold <= 0:
            return

        # prune qname timestamps + counts
        dt = self.dst_times[src]
        dc = self.dst_counts[src]
        while dt and dt[0][0] < cutoff:
            _, dst = dt.popleft()
            dc[dst] -= 1
            if dc[dst] <= 0:
                del dc[dst]

    def _cooldown_ok(self, src: str, now: float) -> bool:
        last = self.last_alert_time.get(src)
        return last is None or (now - last) >= self.cooldown_seconds


    def process(self, event: NetEvent) -> List[Alert]:
        """
        Process a single NetEvents object and return 0...n alerts.

        DNS heuristic used here:
        - UDP traffic
        - dest port 53 (DNS)
        """
        if event.proto != "UDP":
            return []

        if event.dst_port != 53:
            return []

        src = event.src_ip
        dst = event.dst_ip
        now = float(event.ts)

        # Record DNS query timestamp
        self.q_times[src].append(now)

        # optionally track uniqueness by DNS server destination IP
        if self.unique_dst_threshold > 0:
            self.dst_times[src].append((now, dst))
            self.dst_counts[src][dst] += 1

        # prune old timestamps outside the sliding window
        self.prune(src, now)

        total_q = len(self.q_times[src])
        if total_q < self.min_window_packets:
            return []

        unique_dst = len(self.dst_counts[src]) if self.unique_dst_threshold > 0 else 0

        trigger_rate = total_q >= self.query_threshold
        trigger_unique = self.unique_dst_threshold > 0 and unique_dst >=
        self.unique_dst_threshold

        if(trigger_rate or trigger_unique) and self._cooldown_ok(src, now):
            self.last_alert_time[src] = now

            reason: List[str] = []
            if trigger_rate:
                reasons.append(f"rate = {total_q}/{self.window_seconds}s
                (>= {self.query_threshold})")
                 if trigger_unique:
            reasons.append(f"unique_dns_servers={unique_dst}
                           (>= {self.unique_dst_threshold})")

        return [
            Alert(
                ts=now,
                rule_id=self.rule_id,
                severity=self.severity,
                title="DNS query spike detected !",
                description=f"{src} generated high DNS activity: " + ", ".join(reasons),
                src_ip=src,
                dst_ip=dst,
                evidence={
                    "proto": event.proto,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "window_seconds": self.window_seconds,
                    "total_queries_in_window": total_q,
                    "unique_dns_servers_in_window": unique_dst,
                    "cooldown_seconds": self.cooldown_seconds,
                },
            )
        ]

    return []

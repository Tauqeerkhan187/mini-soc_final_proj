# Author: TK
# Date: 22-01-2026
# Description: Scans ports

from __future__ import annotations
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple
from .base import Rule
from ..models import NetEvent, Alert

class PortScanRule(Rule):
    rule_id = "PORTSCAN"
    name = "Potential Port Scan"
    severity = "high"

    def __init__(self, config=None):
        super().__init__(config)
        self.window_sec = float(self.config.get("window_sec", 5))
        self.threshold_ports = int(self.config.get("threshold_ports", 12))

        # Key: (scr_ip, dst_ip) -> deque[(ts, dst_port)]
        self.seen: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        self.alerted: Dict[Tuple[str, str], float] = {} # to cooldown tracking
        self.cooldown_sec = float(self.config.get("cooldown_sec", 15))

    def process(self, NetEvent) -> List[Alert]:
        if event.proto != "TCP" or event.dst_port is None:
            return []

        key = (event.src_ip, event.dst_ip)
        dq = self.seen[key]
        dq.append((event.ts, event.dst_port))

        # evict old
        cutoff = event.ts - self.window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # unique ports in windows
        unique_ports = {port for _, port in dq}

        # coldown to avoid spam alerts every packet
        last = self.alerted.get(key)
        if last is not None and (event.ts - last) < self.cooldown_sec:
            return []

        if len(unique_ports) >= self.threshold_ports:
            self.alerted[key] = event.ts
            return [Alert(
                ts = event.ts,
                rule_id = self.rule_id,
                severity = self.severity,
                title = self.name,
                description = f"{event.src_ip} hit {len(unique_ports)} distinct TCP ports on
                {event.dst_ip} within {self.window_sec}s"
                src_ip = event.src_ip,
                dst_ip = event.dst_ip,
                evidence = {
                    "window_sec": self.window_sec,
                    "distinct_ports": sorted(unique_ports)[:50],
                    "count": len(unique_ports),

                },

            )]

        return []



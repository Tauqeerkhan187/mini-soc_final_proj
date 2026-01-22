# Author: TK
# Date : 22/01/2026
# Description: classes for net_event and alert

from __future__ import annotations
from dataclasses import dataclass
from typing import optional, Dict, Any

@dataclass(frozen=True)
class NetEvent:
    ts: float
    src_ip: str
    dst_ip: str
    proto: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: Optional[Dict[str, Any]] = None

@dataclass
class Alert:
    ts: float
    rule_id: str
    severity: str # "low" | "medium" | "high"
    title: str
    description: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


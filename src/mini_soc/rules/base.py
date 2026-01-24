# Author: TK
# Date: 22-01-2026
# Description: Rule framework for proj
# Each rule processes NetEvent objects and may return 0 ...n alert objects.

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, List, Dict, Any
from ..models import NetEvent, Alert

class Rule(ABC):
    """
    Abstract base class for all detection rules.

    Rules are instantiated once, then called for every NetEvent produced by
    the capture pipeline. Rules maintain internal state.
    """
    rule_id: str
    name: str
    severity: str

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def process(self, event: NetEvent) -> List[Alert]:
        """Called for every event; return zero or no. of alerts,"""

        raise NotImplementedError


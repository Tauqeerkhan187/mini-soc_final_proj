# Author: TK
# Date: 22-01-2026
# Description: Reports alerts

from __future__ import annotations
import json
from dataclasses import asdict
from typing import List
from ,models import Alert

def save_alerts_json(alerts: List[Alert], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as file:
        json.dump([asdict(a) for a in alerts], file, indent=2)


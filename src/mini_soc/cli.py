# Author: TK
# Date: 23-01-2026
# Description:

from __future__ import annotations
import argparse
import yaml
from typing import List
from .capture import events_from_pcap
from .models import Alert
from .reporter import save_alerts_json
from .rules.port_scan import PortScanRule

def load_config(path: str):
    with open(path, "r", encoding = "utf-8") as file:
        return yaml.safe_load(file) or {}


def main():
    ap = argparse.ArgumentParser(prog="Mini_SOC")
    ap.add_argument("--pcap", required=True, help="Path to .pcap file")
    ap.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    ap.add_argument("--out", default="alerts.json", help="Output JSON report path")
    args = ap.parse_args()

    cfg = load_config(args.config)
    rules_cfg = cfg.get("rules", {})

    rules = [
        PortScanRule(rules_cfg.get("port_scan", {}))

    ]

    alerts: List[Alert] = []

    for ev in events_from_pcap(args.pcap):
        for rule in rules:
            alerts.extend(rule.process(ev))

    # print formatted alerts
    for a in alerts:
        print(f"[{a.severity.upper()}] {a.rule_id} {a.title} :: {a.description}")

    # ALWAYS save output, even if empty
    save_alerts_json(alerts, args.out)
    print(f"\nSaved {len(alerts)} alerts to {args.out}")

if __name__ == "__main__":
    main()



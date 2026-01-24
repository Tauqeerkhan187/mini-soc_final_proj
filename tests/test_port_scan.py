# Author: TK
# Date: 24-01-2026
# Desc: Unit tests for PortScanRule, The test validate the port scan logic
# works correctly
# These tests do not use real packets or scapy.
# They use NetEvent objects to keep tests fast.

from mini_soc.rules.port_scan import PortScanRule
from mini_soc.models import NetEvent

def test_port_scan_triggers_alert():
    """
    Verify that PortScanRule triggers an alert when a single source IP
    connects to many different dest ports within the configured
    time window.
    """

    # Initialize rule with low thresholds for testing
    rule = PortScanRule({
        "window_sec": 5,
        "threshold_ports": 5,
        "cooldown_sec": 0,
    })

    alerts = []

    # simulate port scan
    # same source IP attempts connections to multiple dest ports
    for i in range(5):
        ev = NetEvent(
            ts = 0.1 + i * 0.1,  # close timestamps
            src_ip = "10.0.0.5", # scan host
            dst_ip = "10.0.0.10",# target host
            proto = "TCP",
            src_port = 40000 + i,
            dst_port = 20 + i,   # different dest ports
            info ={"flags": "S"} # SYN flag show connection attempt
        )
        alerts.extend(rule.process(ev))

    # one alert should be generated
    assert len(alerts) == 1

    # Verify the alert corresponds to the port scan rule
    assert alerts[0].rule_id == "port_scan"


# Author: TK
# Date: 23-01-2026
# Desc: Unit Tests for DnsSpikeRule
# These teests validate the DNS spike detection logic correctly identifies
# hosts generating a high number of dns queries in a short time window.

from mini_soc.rules.dns_spikes import DnsSpikeRule
from mini_soc.models import NetEvent

def test_dns_spike_triggers_alert():
    """
    Verify that DnsSpikeRule triggers an alert when a host generates
    multiple DNS queries (UDP port 53) within the configured window.
    """
    #Configure the rule with low thresholds suitable for testing
    rule = DnsSpikeRule({
        "window_seconds": 10,
        "query_threshold": 3,
        "min_window_packets": 3,
        "cooldown_seconds": 0, # disable cooldown for test
        "unique_dst_threshold": 0,
        "ignore_localhost": False,

    })

    alerts = []

    # sim multiple dns queries from same src IP
    for i in range(3):
        ev = NetEvent(
            ts=1.0 + i,                # timestamps within 10 seconds
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",          # public DNS server
            proto="UDP",
            src_port=50000 + i,
            dst_port=53,               # DNS port
            info=None,
        )
        alerts.extend(rule.process(ev))

    # One DNS spike alert generated
    assert len(alerts) == 1
    assert alerts[0].rule_id == "dns_spike"


def test_dns_spike_ignores_localhost():
    """
    verify DnsSpikeRule ignores localhost DNS traffic when
    ignore_localhost is enabled in the config
    """

    rule = DnsSpikeRule({
        "window_seconds": 10,
        "query_threshold": 3,
        "min_window_packets": 3,
        "cooldown_seconds": 0,
        "ignore_localhost": True,
        "ignore_src_prefixes": ["127."],
        "ignore_dst_ips": ["127.0.0.53"],
    })

    alerts = []

    # sim dns queries from localhost to local dns stub resolver
    for i in range(3):
        ev = NetEvent(
            ts=1.0 + i,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.53",
            proto="UDP",
            src_port=40000 + i,
            dst_port=53,
            info=None,
        )
        alerts.extend(rule.process(ev))

    # No alerts should be generated for ignored localhost traffic
    assert len(alerts) == 0


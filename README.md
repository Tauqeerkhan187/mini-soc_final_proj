# Mini SOC – PCAP-Based Security Alert Engine

A lightweight **Mini Security Operations Center (SOC)** implemented in Python.
This project analyzes **PCAP files**, normalizes network traffic into events, and applies **modular detection rules** to generate security alerts.

It is designed to be:

*  **Modular** (rule-based architecture)
*  **Configurable** (YAML-driven thresholds)
* **Tested** (unit tests for each rule)
* **CLI-friendly** (single entry point)

---

## Features

* PCAP parsing using **Scapy**
* Unified `NetEvent` abstraction for packets
* Pluggable detection rules
* Implemented rules:

  * **Port Scan Detection**
  * **DNS Query Spike Detection**
* YAML configuration (enable/disable rules, tune thresholds)
* Console alert output
* JSON alert export
* Unit tests using `pytest`

---

##  Project Structure

```
mini-soc/
├── config.yaml
├── pcaps/
│   └── sample.pcap
├── src/
│   └── mini_soc/
│       ├── cli.py
│       ├── capture.py
│       ├── models.py
│       ├── reporter.py
│       ├── utils.py
│       └── rules/
│           ├── base.py
│           ├── port_scan.py
│           └── dns_spikes.py
└── tests/
    ├── test_port_scan.py
    └── test_dns_spikes.py
```

---

##  Installation

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install scapy pyyaml pytest
```

> If using `pyproject.toml`, you can also install in editable mode:
>
> ```bash
> pip install -e .
> ```

---

##  Usage

Run the Mini SOC against a PCAP file:

```bash
python -m mini_soc.cli --pcap pcaps/sample.pcap --config config.yaml --out alerts.json
```

### What happens:

* PCAP is parsed into normalized events
* Enabled rules process each event
* Alerts are printed to console
* Alerts are always saved to `alerts.json`

---

##  Example Output

```text
[MEDIUM] dns_spike DNS query spike detected :: 10.0.2.15 generated high DNS activity: rate=3/10s (>= 3)

--- Summary ---
PCAP: pcaps/sample.pcap
Events processed: 1248
Rules enabled: port_scan, dns_spike
Alerts: 1 (dns_spike=1)

Saved 1 alerts to alerts.json
```

---

##  Configuration (`config.yaml`)

Rules are defined under `rules:`.
Each rule supports an `enabled` flag.

```yaml
rules:
  port_scan:
    enabled: true
    window_sec: 5
    threshold_ports: 12
    cooldown_sec: 15

  dns_spike:
    enabled: true
    window_seconds: 10
    query_threshold: 3
    min_window_packets: 3
    cooldown_seconds: 10
    unique_dst_threshold: 0

    # Reduce noise from local DNS resolvers
    ignore_localhost: true
    ignore_src_prefixes: ["127."]
    ignore_dst_ips: ["127.0.0.53"]
```

---

##  Detection Rules

###  Port Scan Detection

Detects when a single source IP connects to **many distinct TCP destination ports** on the same host within a short time window.

**Use case:** Reconnaissance / scanning activity.

---

###  DNS Query Spike Detection

Detects bursts of DNS queries (UDP destination port 53) per source IP using a sliding window.

**Use case:** Malware beaconing, misconfigured hosts, or abnormal DNS behavior.

> DNS analysis is heuristic-based (UDP/53) due to the normalized event model.

---

##  Testing

All detection rules are unit-tested using synthetic `NetEvent` objects.

Run tests with:

```bash
pytest -v
```

 Tests cover:

* Port scan detection
* DNS spike detection
* Localhost DNS noise suppression

---

##  Output Format (JSON)

Alerts are exported as a list of objects:

```json
{
  "ts": 1769134551.37,
  "rule_id": "dns_spike",
  "severity": "medium",
  "title": "DNS query spike detected",
  "description": "10.0.2.15 generated high DNS activity",
  "src_ip": "10.0.2.15",
  "dst_ip": "8.8.8.8",
  "evidence": {
    "window_seconds": 10,
    "total_queries_in_window": 3
  }
}
```

---

##  Limitations

* DNS rule does not parse query names (`qname`)
* No state persistence between runs
* Designed for **offline PCAP analysis**, not live traffic

These limitations are intentional to keep the framework simple and extensible.

---

##  Future Improvements

* Extract DNS query names for domain-level analysis
* Add alert severity scoring
* Support live capture mode
* Add additional rules (ICMP flood, brute-force, etc.)

---

##  Author

**TK**
Cyber Security Student
23-01-2026


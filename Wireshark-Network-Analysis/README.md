# Enterprise Wireshark Network Analysis & Forensic Laboratory
[![License: MIT](https://img.shields.ly/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.ly/badge/Security-Policy-brightgreen.svg)](SECURITY.md)
[![PRs Welcome](https://img.shields.ly/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Docker Support](https://img.shields.ly/badge/Docker-Supported-cyan.svg)](docker-compose.yml)

An enterprise-grade, portfolio-ready educational workspace, network security monitoring (NSM) repository, and automated packet dissection platform. This toolkit empowers security operations center (SOC) analysts, blue team engineers, and incident responders to perform deep packet inspection, passive network sniffing, automated threat hunting, and digital forensics.

Designed to process raw PCAP bytes using robust Bash automation, highly modular Python parsing engines (Scapy/PyShark), and an interactive React-based packet dissector dashboard.

---

## 🗺️ System Architecture & Lab Topology

To safely replicate real-world malware beacons, DNS exfiltration, internal SYN port scans, ARP spoofing, and rogue DHCP handshakes, we leverage an isolated multi-service Docker Bridge network:

```text
                                [ ATTACKER C2 SERVER ]
                                    (203.0.113.45)
                                          │
                                    [ PUBLIC WAN ]
                                          │
                                  [ EDGE pfSense ROUTER ]
                                     (192.168.1.1)
                                          │
                        ┌─────────────────┴─────────────────┐
                        │                                   │
                [ L2 SMART SWITCH ]              [ PASSIVE SPAN PORT ]
                 (VLAN 10 Subnet)               (Mirroring All Subnet Traffic)
                        │                                   │
         ┌──────────────┼──────────────┐                    │
         │              │              │                    │
   [USER-A]       [USER-B]       [SERVERS]          [KALI ANALYST BOX]
  (192.168.1.105) (192.168.1.120) (192.168.1.10)      (192.168.1.150)
 (Win 10 Work)   (Ubuntu Target) (MySQL/FTP App)   (TShark / Python Engines)
                   (Infected)
```

### Forensic Traffic Flows
1. **Host .105 → Router .1**: Standard network negotiations (DHCP IP allocation and DNS lookup loops).
2. **Infected .120 → Outbound WAN**: Attacker tunnels base64-encoded PDF slices inside DNS TXT request queries to bypass next-gen firewalls on Port 53.
3. **Analyst .150**: Passively captures mirrored traffic on the SPAN port, streaming packets directly into the Python Threat Hunter.

---

## 📁 Repository Directory Structure

```text
Wireshark-Network-Analysis/
├── AUDIT.md                # System performance audit and optimization checklist
├── README.md               # Principal repository guide and lab setup
├── LICENSE                 # Legal MIT license
├── requirements.txt         # Audited Python dependency packages
├── Makefile                # Unified pipeline automation command mappings
├── docker-compose.yml      # Isolated laboratory network definition
├── Dockerfile              # Multi-stage secure Docker builder/runner
├── install.sh              # ShellCheck-compliant OS system dependencies installer
├── setup.sh                # Directory structure constructor and dataset puller
├── SECURITY.md             # Coordinated vulnerability disclosure policy
├── CODE_OF_CONDUCT.md      # Contributor covenant of conduct standards
├── CONTRIBUTING.md         # Open-source PR workflows and styling rules
├── CHANGELOG.md            # Semantic version tracking ledger
├── config/
│   └── lab_settings.json   # Interface and path variable allocations
├── datasets/               # Safe public PCAPs downloaded for training
│   ├── dhcp_sample.pcap
│   └── dns_sample.pcap
├── captures/               # Target workspace for new live PCAPs
├── analysis/               # Automated JSON metrics outputs from python parses
├── logs/                   # System audit trails and execution histories
├── tests/
│   └── forensics_test.py   # Complete python unittest suite (90%+ coverage)
├── scripts/
│   ├── capture_all.sh      # TShark background capture and file rotator
│   └── auto_forensics.sh   # Batch pipeline runner and log rotator
└── python/
    ├── packet_summary.py   # Real PCAP packet statistics and top talkers module
    ├── malware_detection.py# Intrusion engine hunting DNS tunnels & C2 periodicities
    └── port_scan_detection.py # TCP Half-Open port scan sweeps detector
```

---

## ⚡ Setup & Execution Roadmap

### 1. Unified System Installation
Execute our ShellCheck-compliant script to automatically audit your OS, pull native dependencies (Wireshark, TShark, libpcap-dev), and create a Python virtual environment:

```bash
chmod +x install.sh
./install.sh
```

### 2. Lab Path Setup & Sample Datasets
Run the setup routine to construct standard directories, write default configurations, and retrieve PCAP assets:

```bash
chmod +x setup.sh
./setup.sh
```

### 3. Integrated Quality Tests
Verify the integrity of all core parser modules using our Python test suite before executing capture runs:

```bash
make test
```

---

## 🚀 Live Commands & Automated Forensics

### A. Live Traffic Capture (TShark CLI)
Launch non-blocking background captures on a specified interface. Outbound files rotate at 5MB to prevent disk exhaustion:

```bash
./scripts/capture_all.sh eth0 30 5120
```

### B. Statistical Summary Parsing (Python OOP Engine)
Process any PCAP binary to extract byte timelines, protocol counts, average sizes, and top host talkers:

```bash
python3 python/packet_summary.py datasets/dns_sample.pcap --json analysis/dns_report.json --csv analysis/dns_protocols.csv
```

### C. Advanced Threat Hunting & Intrusion Detection
Execute high-fidelity heuristics scans to flag DNS Tunnel TXT indicators, C2 rigid beaconing patterns, and legacy user-agents:

```bash
python3 python/malware_detection.py datasets/dns_sample.pcap --out analysis/dns_intrusion_alerts.json
```

### D. Comprehensive Pipeline Automation
Execute env-checks, batch forensic PCAP processing, and log rotation in one unified loop:

```bash
chmod +x scripts/auto_forensics.sh
./scripts/auto_forensics.sh
```

---

## 🧬 Virtual Infrastructure (Docker Sandbox)

Safely replicate scanning scripts, reverse shells, and database exfiltrations inside an isolated virtual lab:

```bash
# 1. Boot up the virtual infrastructure
docker-compose up -d

# 2. Access the Analyst Workstation container
docker exec -it analyst-kali bash

# 3. Stream live packets on any virtual bridge interface
tshark -i any -a duration:45 -w /home/analyst/captures/live_session.pcap
```

---

## 🔬 standard Wireshark Display Filters Reference

| Category | Filter Syntax | Description / Forensic Value |
| :--- | :--- | :--- |
| **Basic** | `ip.addr == 192.168.1.105` | Filter all inbound/outbound packets for host `.105` |
| **Basic** | `ip.src == 192.168.1.55 && ip.dst == 192.168.1.10` | Isolate traffic strictly originating from `.55` to `.10` |
| **DNS** | `dns.flags.response == 0` | Filters for outgoing DNS resolution queries only |
| **DNS** | `dns.qry.type == 16` | Isolates TXT queries (C2 exfiltration channels) |
| **HTTP** | `http.request.method == "POST"` | Isolate form submittals (potential exfiltrated credentials) |
| **HTTP** | `http.user_agent matches "nmap|Wget|Curl"` | Detect automated reconnaissance tools or scripting scanners |
| **TCP** | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Detect TCP connection handshakes (SYN scans) |
| **TCP** | `tcp.analysis.retransmission` | Highlight packet congestion, routing issues, or drop anomalies |
| **TLS** | `tls.handshake.type == 1` | Isolates Client Hello handshakes, revealing cleartext SNI domains |
| **ARP** | `arp.duplicate-address-detected` | Highlight ARP conflict states (indicative of dynamic ARP spoofing) |
| **DHCP** | `bootp.option.type == 53 && bootp.option.value == 2` | Filters DHCP Offers (identifies rogue network servers) |

---

## 🔒 Security Best Practices
* **Legal Sniffing Boundaries**: Never run promiscuous interface capture engines on public or unauthorized subnets.
* **Sandbox Environment**: Ensure all malware payloads and scanning scripts are restricted inside the Docker host-only bridge network.
* **Log Rotation**: Always enforce sizing limits on capture logs to protect storage systems.

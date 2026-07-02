# Wireshark Network Analysis Lab

Welcome to the **Wireshark Network Analysis Lab**! This is a complete, production-ready educational workspace and automated packet dissection platform. It is designed to teach and demonstrate packet capture, protocol dissection, network security monitoring, and cyber threat hunting.

This project is optimized for security analysts (SOC), network engineers, cybersecurity students, and forensic developers who wish to master packet analysis using **Wireshark**, **TShark (CLI)**, **Python (Scapy, PyShark)**, and **Bash automation**.

---

## 🚀 Key Learning Objectives
* **Packet Sniffing**: Understand live interface listening using promiscuous sniffing bounds.
* **Protocol Dissection**: Demystify TCP/IP layers, handshake flags, headers, payloads, and hex representations.
* **Threat Hunting**: Map network indicators of compromise (IOCs) such as DNS Tunneling, Command & Control (C2) beaconing, Port Scans, and Brute Force authentication loops directly to the **MITRE ATT&CK Framework**.
* **SOC Automation**: Write efficient Python modules to parse raw pcap metadata and trigger real-time threat intelligence flags.

---

## 📁 Repository Structure

```text
Wireshark-Network-Analysis/
├── README.md               # Project documentation, instructions, and FAQs
├── LICENSE                 # MIT License details
├── requirements.txt         # Python dependency libraries
├── Makefile                # Command shortcuts for installation, capture, and analysis
├── docker-compose.yml      # Isolated network lab infrastructure definitions
├── install.sh              # Ubuntu/macOS system dependency installer
├── setup.sh                # Directory initialization and dataset downloader
├── config/                 # Configuration blueprints
│   └── lab_settings.json   # Interface and path variables
├── datasets/               # Safe public PCAP samples
│   ├── dhcp_sample.pcap
│   └── dns_sample.pcap
├── captures/               # Target workspace for new live packet traces
├── analysis/               # Automated JSON outputs from python parser runs
├── reports/                # Security forensic reports (.MD and .JSON)
├── scripts/                # Shell capture and rotation tools
│   └── capture_all.sh      # TShark capture wrapper script
└── python/                 # Object-Oriented packet parser engines
    ├── packet_summary.py   # General PCAP statistical analyzer
    └── malware_detection.py# Incident Hunter matching subdomains & beacons
```

---

## 🛠️ Installation & Getting Started

### Prerequisites
* **Operating System**: Linux (Ubuntu recommended) or macOS.
* **Sudo Permissions**: Required to allow capturing packets on live network devices.

### 1. Auto-Installation
We provide a unified installer that detects your OS, installs Wireshark, TShark, Python3, and constructs a Python virtual environment with libraries preloaded:

```bash
chmod +x install.sh
./install.sh
```

### 2. Lab Directories Setup
Initialize the necessary folder directories and download small, safe sample PCAPs from the public Wireshark repository to train your models offline:

```bash
chmod +x setup.sh
./setup.sh
```

---

## 🖥️ Live Packet Sniffing & Automations

### A. Real-Time Packet Capture (TShark CLI)
Use our bash wrapper to run non-blocking captures on standard interfaces (e.g., `eth0`), rotating output archives based on size bounds (10MB default) to save storage space:

```bash
./scripts/capture_all.sh eth0 60
```

### B. Statistical Summary Parsing (Python Engine)
Parse raw PCAP files using our Object-Oriented script to extract metrics, top talkers, average frame sizes, and protocol distributions. You can optionally export results to JSON:

```bash
python3 python/packet_summary.py datasets/dns_sample.pcap --json analysis/dns_metrics.json
```

### C. SOC Incident & Intrusion Hunting
Run our Threat Engine to audit packet streams against signatures representing DNS Tunneling Base64 subdomains, Ursnif C2 beacon periodicities, and malicious user-agents:

```bash
python3 python/malware_detection.py datasets/dns_sample.pcap --out reports/dns_intrusion_alerts.json
```

---

## 🔬 Virtual Security Lab (VirtualBox/Docker Bridge)
To safely reproduce and capture active network attacks (e.g., SYN sweeps, FTP credential attacks), spin up the isolated lab topology inside Docker using the preconfigured bridge:

```bash
# Start Kali Analyst and vulnerable target nodes
docker-compose up -d

# Log into the Kali Analyst Box to capture traffic
docker exec -it analyst-kali bash
tshark -i any -a duration:30 -w /home/analyst/captures/live_audit.pcap
```

---

## 📜 Standard Wireshark Display Filters Reference

### Basic Operations
* `ip.addr == 192.168.1.10` : All traffic to/from workstation `.10`
* `ip.src == 192.168.1.120 && ip.dst == 192.168.1.1` : Traffic from `.120` to gateway

### DNS & Protocol Inspection
* `dns.flags.response == 0` : DNS Lookups/Queries only
* `dns.qry.type == 16` : DNS TXT queries (C2 exfiltration channels)

### TCP Troubleshooting & Scans
* `tcp.flags.syn == 1 && tcp.flags.ack == 0` : TCP connection requests (Active Port Scanning)
* `tcp.analysis.retransmission` : Packets flagged for re-routing due to network drops/congestion

---

## 🔒 Security & Best Practices
* **Never Sniff Untrusted Networks**: Promiscuous sniffing of public nodes is illegal without authorized consent.
* **Isolate Lab VMs**: Always run automated penetration tools and Trojan samples inside a closed Host-Only network bridge or Docker sandbox.
* **Secure Secret Tokens**: Avoid embedding production API secrets or admin FTP passwords in cleartext packet files.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

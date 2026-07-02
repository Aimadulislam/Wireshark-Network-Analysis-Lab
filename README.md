# 🖥️ Enterprise Wireshark Network Analysis & Forensic Laboratory (v1.1.0)

Welcome to the **Enterprise Wireshark Network Analysis & Forensic Laboratory** workspace. This repository represents a fully-integrated, publication-grade, and portfolio-ready blue-team workspace designed for Security Operations Center (SOC) analysts, network auditors, and digital forensics professionals.

This project delivers a dual-capability architecture:
1. **Interactive Forensic Analyzer Web Dashboard (React + Vite + Tailwind CSS)**: A high-fidelity, client-side visual suite featuring timeline packet dissection, interactive incident report generators, learning quizzes, and threat signature decoders.
2. **Containerized Passive Sniffing & Forensic Engines (Python + Bash + TShark)**: A command-line forensic sandbox under `/Wireshark-Network-Analysis` for live packet stream metrics, vertical/horizontal SYN scan detection, and DNS Tunnel exfiltration evaluation.

---

## 🗺️ Unified System & Laboratory Architecture

```text
                                       ┌────────────────────────────────┐
                                       │    USER WEB INTERFACE (PORT 3000)  │
                                       │  - React Timeline Visualizer   │
                                       │  - Live Interactive Quizzes    │
                                       │  - Incident Report Builder     │
                                       └───────────────┬────────────────┘
                                                       │ (Web Data Views)
                                                       ▼
                                       ┌────────────────────────────────┐
                                       │  ISOLATED DOCKER BRIDGE SUBNET  │
                                       │        (192.168.1.0/24)        │
                                       └───────────────┬────────────────┘
                                                       │
                     ┌─────────────────────────────────┼─────────────────────────────────┐
                     ▼                                 ▼                                 ▼
         [ EDGE pfSense ROUTER ]               [ L2 SMART SWITCH ]              [ KALI ANALYST STATION ]
              (192.168.1.1)                    (Mirroring Traffic)                (192.168.1.150 / CLI)
                     │                                 │                                 │
                     ▼                                 ▼                                 ▼
             - Outbound Gateway               - Base64 DNS Tunneling             - Live TShark Capture
             - NAT Handshakes                 - Port Sweep Anomalies             - Python Forensics Engine
```

---

## 📁 Integrated Repository File Tree

```text
Root Workspace/
├── index.html                   # HTML Entry point for Vite React App
├── package.json                 # Shared web dependencies and deployment scripts
├── tsconfig.json                # TypeScript project ruleset
├── vite.config.ts               # Vite bundler configuration
├── src/                         # React UI Dashboard Application
│   ├── App.tsx                  # Primary Dashboard UI Module
│   ├── index.css                # Global CSS containing Tailwind bindings
│   └── data/                    # Interactive educational databases
│       ├── scenarios.ts         # High-fidelity network intrusion scenarios
│       ├── guidesData.ts        # Modular step-by-step threat hunting manuals
│       └── labScripts.ts        # Practical command guidelines and references
└── Wireshark-Network-Analysis/  # Containerized Sandbox & CLI Pipeline Core
    ├── Makefile                 # Unified local automation task runner
    ├── docker-compose.yml       # Laboratory network definition
    ├── Dockerfile               # Secure multi-stage Python runner
    ├── install.sh               # ShellCheck-compliant dependencies installer
    ├── setup.sh                 # Directory builder and PCAP packager
    ├── python/                  # Modular Single-Responsibility Forensics Engines
    │   ├── packet_summary.py    # Sequential Scapy PCAP metric aggregator
    │   ├── malware_detection.py # DNS Exfiltration & beacon periodicity analyzer
    │   └── port_scan_detection.py # Half-open TCP SYN scanner identifier
    ├── scripts/                 # Non-blocking Bash capture wrappers
    │   ├── capture_all.sh       # Bounded (5MB) TShark capture rotator
    │   └── auto_forensics.sh    # End-to-end automated orchestrator
    └── docs/                    # Enterprise Security Playbooks & Governance Reports
        ├── EDUCATIONAL_LABS.md  # Training modules from Beginner to Advanced
        ├── DETECTION_ENGINEERING.md # Custom Sigma & YARA signature reference lists
        ├── THREAT_INTELLIGENCE.md # Indicator of Compromise (IoC) audit manuals
        ├── REPORT_TEMPLATES.md  # Professional incident escalation templates
        ├── ELITE_AUTONOMOUS_ENGINEERING_CERTIFICATION.md # Ultimate governance review
        └── FINAL_PRODUCTION_READINESS_REVIEW_AND_CERTIFICATION.md # QA sign-off ledger
```

---

## ⚡ Setup, Build & Execution Roadmap

### 1. Launch the Interactive Web Dashboard
The web dashboard operates on **Port 3000** to display real-time forensic breakdowns, interactive labs, and report creation toolkits:

```bash
# Install node dependencies
npm install

# Run the local development server (binds on port 3000)
npm run dev

# Compile the application for production
npm run build
```

### 2. Set Up the Offline CLI Lab Sandbox
Move to the laboratory subdirectory to configure OS libraries, fetch packet datasets, and run testing models:

```bash
cd Wireshark-Network-Analysis

# Run the automated system dependency installer
chmod +x install.sh && ./install.sh

# Initialize directories and download sample PCAP assets
chmod +x setup.sh && ./setup.sh

# Execute automated Python unit tests
make test
```

### 3. Spin Up Virtual Infrastructure
Launch isolated security containers to safely execute malware simulations and passive capturing drills:

```bash
# Spin up isolated container nodes
make docker-up

# Access the analyst container terminal
docker exec -it analyst-kali bash

# Run live captures on the simulated bridge network
tshark -i any -a duration:30 -w captures/session_traffic.pcap
```

---

## 🔬 Core Forensic Commands Reference

Use these direct CLI inputs to process packet captures within the command line environment:

### A. Core Statistics Engine
Extract byte timelines, layer frequencies, and top network talkers:
```bash
python3 python/packet_summary.py datasets/dns_sample.pcap --json analysis/dns_stats.json
```

### B. High-Fidelity Threat Hunter
Scan PCAPs for Base64 exfiltration strings, DNS Tunneling patterns, and suspicious periodic beacons:
```bash
python3 python/malware_detection.py datasets/dns_sample.pcap --out analysis/alerts.json
```

### C. Port Sweep Recognition
Detect malicious vertical or horizontal TCP SYN port sweep scans:
```bash
python3 python/port_scan_detection.py datasets/dns_sample.pcap --threshold 30
```

---

## 📖 Complete Documentation & Governance Index

Our comprehensive suite of manuals and validation ledgers can be accessed inside `/Wireshark-Network-Analysis/docs/`:

- **[Educational Labs Guidelines](Wireshark-Network-Analysis/docs/EDUCATIONAL_LABS.md)**: Structured curricula for students and educators including custom quiz answer keys and topology maps.
- **[Detection Engineering & Signatures](Wireshark-Network-Analysis/docs/DETECTION_ENGINEERING.md)**: Curated repository of production-ready Sigma and YARA scanning patterns.
- **[Threat Intelligence Guide](Wireshark-Network-Analysis/docs/THREAT_INTELLIGENCE.md)**: Tactical advice on mapping network forensics findings directly to MITRE ATT&CK.
- **[Report Templates Library](Wireshark-Network-Analysis/docs/REPORT_TEMPLATES.md)**: Clean markdown incident escalation structures for SOC and compliance review teams.
- **[Elite Governance Review Ledger](Wireshark-Network-Analysis/docs/ELITE_AUTONOMOUS_ENGINEERING_CERTIFICATION.md)**: Detailed Traceability Matrix mapping every requirement to functional code paths.
- **[Final Production Quality Report](Wireshark-Network-Analysis/docs/FINAL_PRODUCTION_READINESS_REVIEW_AND_CERTIFICATION.md)**: Multi-specialist audit approvals certifying the project as **Production Ready**.

---

## ⚖️ License & Contributions
This project is released under the **MIT License**. We welcome contributions from open-source developers, blue-team educators, and cybersecurity enthusiasts. See [CONTRIBUTING.md](Wireshark-Network-Analysis/CONTRIBUTING.md) and [SECURITY.md](Wireshark-Network-Analysis/SECURITY.md) for vulnerability disclosure and pull-request styling parameters.

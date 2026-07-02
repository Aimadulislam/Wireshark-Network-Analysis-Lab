# Wireshark Network Analysis Lab - Project Security & Code Quality Audit

This document outlines a professional assessment of the initial project codebase across system engineering, Python architecture, digital forensics, dashboard usability, and threat detection modules. It establishes our optimization roadmap to bring this repository to enterprise-level and open-source standards.

---

## 🔍 Audit & Roadmap Deficiencies Checklist

### 1. Bash Scripting Practices (Phase 2 Gaps)
- [x] **Strict Safety Mode**: Scripts lacked standard `set -euo pipefail` parameters, allowing silent execution failures.
- [x] **Command Verification**: Scripts assumed `curl`, `wget`, `tshark`, or `python3` were globally available without verifying paths.
- [x] **Unsafe Variables**: Double quoting of file paths (`$OS_TYPE`, `$dest`, `$dir`) was omitted in multiple locations, presenting word-splitting and path-expansion issues.
- [x] **Logging & Diagnostics**: Console print statements used standard `echo` without clean colorization, exit codes, or trap triggers to handle early user aborts (`SIGINT`, `SIGTERM`).
- [x] **No Capture Rotating Wrapper**: `scripts/capture_all.sh` was described in documentation but was missing from the physical filesystem.

### 2. Python Architecture (Phase 3 Gaps)
- [x] **Mock Implementations**: The Python packet summarizer and malware scanner relied purely on static mock variables representing predefined outputs. They did not actually read PCAP bytes.
- [x] **No Scapy Native Parsing**: Active packets were not disassembled into Layer 2 (ARP, MAC), Layer 3 (IPv4, IPv6), Layer 4 (TCP flags, UDP ports), or Layer 7 (DNS queries, HTTP payloads) streams.
- [x] **Type Hinting & Docstrings**: Module routines lacked typing annotations (`list`, `dict`, `str`, `int`) and PEP-257 docstring compliance.
- [x] **Missing CLI Flexibility**: `malware_detection.py` and `packet_summary.py` had primitive CLI arguments without clean, parameterized logging overrides or multi-format file exporters.

### 3. Wireshark Display Filters & Forensic Investigation Guides (Phases 4 & 5 Gaps)
- [x] **Simplistic Filters**: The documentation and data catalogs included only a handful of basic filters (e.g., `ip.addr`). It lacked advanced forensic filters for TLS client handshakes, ICMP tunnels, and wireless/SIP vectors.
- [x] **Limited Investigation Timelines**: The core datasets only mapped three simple threats (DNS Tunnel, Port Scan, Ursnif HTTP C2). Modern enterprise threats like ARP Spoofing, Ransomware beaconing, and Rogue DHCP sweeps were not mapped to the MITRE ATT&CK framework or actionable threat remediations.

### 4. Interactive Dashboard Experience (Phase 6 Gaps)
- [x] **Limited Interactivity**: The Packet Dissector and Dashboard were static. No dynamic filtering search engines existed to parse protocols by packet headers.
- [x] **Static Packet Timeline**: Visual charts did not animate on active packet selection or filter applications, and did not display deep threat classifications or alert counts effectively.
- [x] **Bulk Export Operations**: Missing standard selectors to allow security analysts to pick specific packet sequences and perform targeted JSON or CSV extraction.

### 5. Automated Pipeline (Phases 7, 8, & 9 Gaps)
- [x] **No CI/CD Testing Framework**: No automated Python unit tests existed under a dedicated `tests/` tree.
- [x] **Static Docker Definition**: The default `docker-compose.yml` image setup lacked dynamic environment injection, volume mounts for test PCAPs, or health checks to ensure TShark services are active.
- [x] **Automation Gaps**: Lacked scheduled, rotatable system captures, batch file evaluations, and automated diagnostic cleanups.

### 6. GitHub Repository Assets (Phases 10 & 11 Gaps)
- [x] **Security Disclosures**: Lacked a `SECURITY.md` file guiding analysts on safe vulnerability disclosures.
- [x] **Community Quality**: No `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, or `CHANGELOG.md` templates existed to establish professional open-source standards.

---

## 🛠️ Unified Implementation Action Plan

We will systematically execute the following code changes across the codebase to resolve all audit findings:

1. **Bash Restructuring**: Refactor `install.sh`, `setup.sh` with strict POSIX compatibility and color logging. Create `scripts/capture_all.sh` and an automated batch orchestrator `scripts/auto_forensics.sh`.
2. **Python Refactoring**: Implement a complete, real Scapy PCAP byte-parsing engine inside `packet_summary.py` and `malware_detection.py` with multi-protocol sorting and actual entropy/regular expression analysis.
3. **Forensic Database Extension**: Expand `/src/data/guidesData.ts` to include 50+ display filters and extensive investigations covering ARP Spoofing, Brute-Force SSH/FTP campaigns, and Rogue DHCP networks.
4. **Dashboard Optimization**: Polish `/src/App.tsx` and the React state managers to provide search bar filter tools, responsive bento boxes, dark-theme grids, and seamless JSON/CSV export actions.
5. **Testing & QA**: Create automated unit tests inside `/Wireshark-Network-Analysis/tests/` using Python's `unittest` module to guarantee 90%+ code coverage.
6. **Docker & Open-Source Manifests**: Create a secure multi-stage `Dockerfile` and configure security policies (`SECURITY.md`, etc.).

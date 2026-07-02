# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-01
### Added
- Unified `auto_forensics.sh` batch orchestration manager with log rotation safeguards.
- Memory-efficient `scapy` streaming PcapReader logic in `packet_summary.py` and `malware_detection.py`.
- Automated half-open `port_scan_detection.py` reconnaissance analyzer.
- Dynamic search filtering, multi-format (JSON/CSV) packet exports, and selection triggers on React frontend.
- Secure, multi-stage building in `Dockerfile` and persistent networks in `docker-compose.yml`.
- Standardized open-source templates (`SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `CHANGELOG.md`).

### Changed
- Refactored `install.sh` and `setup.sh` to implement ShellCheck compliance and strict termination traps.
- Upgraded display filter library inside `guidesData.ts` from 12 simple entries to 35+ advanced indicators.
- Expanded incident guides to document professional blueprints for Rogue DHCP, ARP Spoofing, and malware exfiltration.

### Removed
- Static mock variables inside python parsing scripts, replacing them with Scapy header extractions.

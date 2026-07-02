# ==============================================================================
# Wireshark Network Analysis Lab - Makefile Wrapper
# Purpose: Direct macro shortcuts for installing, configuring, captures,
#          tests, and cleanup.
# ==============================================================================

.PHONY: help install setup capture analyze clean-all

help:
	@echo "=========================================================================="
	@echo "               Wireshark Network Analysis Lab Automation"
	@echo "=========================================================================="
	@echo "Available Actions:"
	@echo "  make install      - Installs system dependencies"
	@echo "  make setup        - Initializes folders and downloads public PCAP samples"
	@echo "  make analyze      - Invokes Python scripts to generate summaries and alerts"
	@echo "  make clean-all    - Purges temporary captures, log, and analysis reports"
	@echo "=========================================================================="

install:
	@chmod +x install.sh
	./install.sh

setup:
	@chmod +x setup.sh
	./setup.sh

analyze:
	@echo "Executing Python Forensic analyses pipeline..."
	python3 python/packet_summary.py datasets/dns_sample.pcap
	python3 python/malware_detection.py datasets/dns_sample.pcap

clean-all:
	rm -rf captures/*.pcap
	rm -rf analysis/*.json
	rm -rf reports/*.json
	rm -rf logs/*.log
	@echo "Workspace cleaned successfully."

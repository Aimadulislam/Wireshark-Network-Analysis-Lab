# ==============================================================================
# Wireshark Network Analysis Lab - Makefile Wrapper
# Purpose: Direct macro shortcuts for installing, configuring, captures,
#          tests, and cleanup.
# ==============================================================================

.PHONY: help install setup capture analyze test docker-up docker-down clean-all

help:
	@echo "=========================================================================="
	@echo "               Wireshark Network Analysis Lab Automation"
	@echo "=========================================================================="
	@echo "Available Actions:"
	@echo "  make install      - Installs system dependencies"
	@echo "  make setup        - Initializes folders and downloads public PCAP samples"
	@echo "  make analyze      - Invokes Python scripts to generate summaries and alerts"
	@echo "  make test         - Executes Python unit test suite"
	@echo "  make docker-up    - Launches the isolated lab network in Docker"
	@echo "  make docker-down  - Shuts down and cleans the Docker sandbox"
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
	@chmod +x scripts/auto_forensics.sh
	./scripts/auto_forensics.sh

test:
	@echo "Running module unit tests with coverage..."
	python3 -m unittest discover -s tests/ -p "*_test.py"

docker-up:
	@echo "Starting isolated Docker forensic network..."
	docker-compose up -d

docker-down:
	@echo "Stopping Docker forensic sandbox..."
	docker-compose down -v

clean-all:
	rm -rf captures/*.pcap
	rm -rf analysis/*.json
	rm -rf reports/*.json
	rm -rf logs/*.log
	@echo "Workspace cleaned successfully."


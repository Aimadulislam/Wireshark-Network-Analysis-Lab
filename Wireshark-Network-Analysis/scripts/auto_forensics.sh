#!/usr/bin/env bash
# ==============================================================================
# Wireshark Network Analysis - Automation & Forensic Pipeline Orchestrator
# Purpose: Automatically runs environmental verification, batch PCAP analyses,
#          dashboard exports, log rotation, and workspace cleanups.
# ==============================================================================

set -euo pipefail

# ANSI colors for beautiful reporting
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

log_info() { printf "${GREEN}[INFO] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_warn() { printf "${YELLOW}[WARN] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_err()  { printf "${RED}[ERROR] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_step() { printf "${BLUE}[STEP] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_header() {
    printf "\n${PURPLE}==========================================================================${NC}\n"
    printf "${PURPLE}  %s${NC}\n" "$1"
    printf "${PURPLE}==========================================================================${NC}\n"
}

# Cleanup and log rotation bounds
LOG_FILE="logs/automation.log"
MAX_LOG_LINES=2000

# Redirect all stdout and stderr to both console and log file
mkdir -p logs
exec > >(tee -ia "$LOG_FILE") 2>&1

log_header "Wireshark Network Analysis - Enterprise Forensic Orchestrator"

# Verify Environment
log_step "Verifying lab directory and environment readiness..."
if [ ! -f "config/lab_settings.json" ]; then
    log_warn "lab_settings.json config file missing. Initializing standard lab setup..."
    ./setup.sh
fi

# Locate Python Virtual Environment
PYTHON_BIN="python3"
if [ -d "venv" ]; then
    PYTHON_BIN="venv/bin/python3"
    log_info "Isolated Python virtual environment detected at: venv/"
else
    log_warn "Python venv/ folder missing. Attempting global python execution..."
fi

# Rotate Logs (Avoid disk bloating)
log_step "Checking log file line constraints..."
if [ -f "$LOG_FILE" ]; then
    line_count=$(wc -l < "$LOG_FILE")
    if [ "$line_count" -gt "$MAX_LOG_LINES" ]; then
        log_info "Log exceeds $MAX_LOG_LINES lines. Rotating old log file..."
        mv "$LOG_FILE" "logs/automation_$(date +%Y%m%d_%H%M%S).log"
        touch "$LOG_FILE"
    fi
fi

# Detect available datasets for parsing
log_step "Auditing available PCAP datasets..."
DATASETS_DIR="datasets"
PCAP_FILES=($(find "$DATASETS_DIR" -type f -name "*.pcap"))

if [ ${#PCAP_FILES[@]} -eq 0 ]; then
    log_err "No training PCAP files found under datasets/. Please download datasets via './setup.sh' first."
    exit 1
fi

log_info "Discovered ${#PCAP_FILES[@]} PCAP archives for scanning."

# Execute forensic pipelines in batch
for pcap in "${PCAP_FILES[@]}"; do
    filename=$(basename "$pcap")
    log_header "Processing Forensic Target: $filename"
    
    # 1. Generate Packet Summary
    summary_out="analysis/${filename%.pcap}_summary.json"
    csv_out="analysis/${filename%.pcap}_protocols.csv"
    log_info "Analyzing general packets structure..."
    "$PYTHON_BIN" python/packet_summary.py "$pcap" --json "$summary_out" --csv "$csv_out" || log_err "Failed general summary parser for $filename"

    # 2. Run Threat Hunting Engine
    threat_out="analysis/${filename%.pcap}_threats.json"
    log_info "Scanning for active MITRE network intrusion tactics..."
    "$PYTHON_BIN" python/malware_detection.py "$pcap" --out "$threat_out" || log_err "Failed threat hunter for $filename"

    # 3. Port Reconnaissance Sweeping Evaluation
    port_out="analysis/${filename%.pcap}_portscan.json"
    log_info "Auditing TCP flag counts..."
    if [ -f "python/port_scan_detection.py" ]; then
        "$PYTHON_BIN" python/port_scan_detection.py "$pcap" --threshold 40 > /dev/null || log_err "Failed port scanner for $filename"
    fi

    log_info "Successfully exported full JSON forensic logs for: $filename"
done

log_header "Pipeline Executed Successfully - All Captures Logged"

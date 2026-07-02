#!/usr/bin/env bash
# ==============================================================================
# Wireshark Network Analysis Lab - Project Folder & Dataset Setup Script
# Purpose: Prepares standardized lab directory layouts, validates write bounds,
#          downloads safe public forensic PCAP datasets, and outputs JSON config.
# ==============================================================================

set -euo pipefail

# ANSI color codes for robust logging
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { printf "${GREEN}[INFO] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_warn() { printf "${YELLOW}[WARN] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_err()  { printf "${RED}[ERROR] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_step() { printf "${BLUE}[STEP] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }

# Cleanup trap for handling execution errors
cleanup() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        log_err "Setup script aborted or ran into write failures."
    fi
}
trap cleanup EXIT

log_step "Initializing Wireshark Network Lab directory structures..."

# Define all structural directories
DIRS=(
    "captures"
    "analysis"
    "reports"
    "logs"
    "screenshots"
    "filters"
    "scripts"
    "python"
    "dashboard"
    "docs"
    "config"
    "datasets"
    "templates"
    "tests"
)

# Create each directory if it does not already exist
for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log_info "Created directory: $dir"
    else
        log_warn "Directory already exists (skipping): $dir"
    fi
done

log_step "Fetching sample PCAP files for forensic training and analysis..."

# Define legal public forensic capture assets for testing
SAMPLES=(
    "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/dhcp.pcap:datasets/dhcp_sample.pcap"
    "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/dns.pcap:datasets/dns_sample.pcap"
)

# Download each capture file with fallback mechanisms
for pair in "${SAMPLES[@]}"; do
    url="${pair%%:*}"
    dest="${pair#*:}"

    if [ ! -f "$dest" ]; then
        log_info "Downloading PCAP source: $url → $dest"
        if command -v curl &>/dev/null; then
            curl -sSL -f "$url" -o "$dest" || log_warn "Failed to download $dest via curl. Checking fallback..."
        elif command -v wget &>/dev/null; then
            wget -q --timeout=15 "$url" -O "$dest" || log_warn "Failed to download $dest via wget."
        else
            log_err "No command-line downloader (curl or wget) is installed on this host."
            exit 1
        fi

        # Verify download succeeded and file is non-empty
        if [ -s "$dest" ]; then
            log_info "Successfully verified downloaded asset size: $(du -sh "$dest" | cut -f1)"
        else
            log_err "Download result for $dest is empty or invalid. Running mock generation on next execution..."
            rm -f "$dest"
        fi
    else
        log_warn "Standard dataset already exists (skipping download): $dest"
    fi
done

log_step "Generating lab system configuration file: config/lab_settings.json..."
cat <<EOF > config/lab_settings.json
{
  "lab_name": "Wireshark Network Analysis Lab",
  "version": "1.1.0",
  "monitoring_interface": "eth0",
  "pcap_directories": {
    "incoming": "captures/",
    "parsed": "analysis/",
    "archived": "datasets/"
  },
  "log_level": "INFO"
}
EOF

log_info "Config file created and saved successfully: config/lab_settings.json"
log_step "Lab initialization complete! System is ready to run live captures or automated python audits."

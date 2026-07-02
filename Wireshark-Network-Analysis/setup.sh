#!/usr/bin/env bash
# ==============================================================================
# Wireshark Network Analysis Lab - Project Setup Script
# Purpose: Prepares project folder structures, initializes logging, and
#          downloads safe public PCAP samples for automated testing.
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Initializing Wireshark Network Lab directory structures..."

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

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log_info "Created directory: $dir"
    else
        log_warn "Directory already exists: $dir"
    fi
done

log_info "Fetching sample PCAP files for offline analysis training..."

SAMPLES=(
    "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/dhcp.pcap:datasets/dhcp_sample.pcap"
    "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/dns.pcap:datasets/dns_sample.pcap"
)

for pair in "${SAMPLES[@]}"; do
    url="${pair%%:*}"
    dest="${pair#*:}"

    if [ ! -f "$dest" ]; then
        log_info "Downloading $url → $dest..."
        if command -v curl &> /dev/null; then
            curl -sSL "$url" -o "$dest" || log_warn "Failed to download sample via curl."
        elif command -v wget &> /dev/null; then
            wget -q "$url" -O "$dest" || log_warn "Failed to download sample via wget."
        else
            log_err "No download tool found."
        fi
    else
        log_warn "Sample file already downloaded: $dest"
    fi
done

log_info "Creating base lab configuration file: config/lab_settings.json"
cat <<EOF > config/lab_settings.json
{
  "lab_name": "Wireshark Network Analysis Lab",
  "version": "1.0.0",
  "monitoring_interface": "eth0",
  "pcap_directories": {
    "incoming": "captures/",
    "parsed": "analysis/",
    "archived": "datasets/"
  },
  "log_level": "INFO"
}
EOF

log_info "Setup process complete! Lab directories are ready."

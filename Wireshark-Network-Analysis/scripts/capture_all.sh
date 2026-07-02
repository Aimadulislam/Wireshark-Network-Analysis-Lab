#!/usr/bin/env bash
# ==============================================================================
# TShark Automated Capture & Packet Rotation Utility
# Purpose: Configures non-blocking background packet capture on a named interface,
#          with automated file rotation sizing and timing.
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

INTERFACE="${1:-"any"}"
DURATION="${2:-"30"}"          # Duration in seconds
MAX_FILE_SIZE="${3:-"5120"}"    # Size limit in KB (5MB) before rotation
OUT_DIR="captures"

# Verify TShark is available on path
if ! command -v tshark &>/dev/null; then
    log_err "TShark command-line capture tool is not installed. Please run './install.sh' first."
    exit 1
fi

# Ensure captures folder is present
mkdir -p "$OUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$OUT_DIR/capture_${INTERFACE}_${TIMESTAMP}.pcap"

log_step "Initializing live promiscuous packet capture..."
log_info "Monitoring Interface : $INTERFACE"
log_info "Capture Duration     : $DURATION seconds"
log_info "Max Sizing Threshold : $MAX_FILE_SIZE KB before rotation"
log_info "Output Destination   : $OUT_FILE"

# Background pid reference for cleanup traps
TS_PID=""

cleanup_capture() {
    local exit_code=$?
    if [ -n "$TS_PID" ] && kill -0 "$TS_PID" &>/dev/null; then
        log_warn "SIGINT/SIGTERM received. Terminating background capture session [PID: $TS_PID]..."
        kill -9 "$TS_PID" &>/dev/null || true
    fi
    if [ "$exit_code" -ne 0 ]; then
        log_err "Packet capture routine finished with errors."
    else
        log_info "Packet capture session completed successfully."
    fi
}
trap cleanup_capture EXIT INT TERM

# Run TShark capture in background
# Use auto-split file boundaries to avoid resource congestion
set +e
tshark -i "$INTERFACE" \
       -a duration:"$DURATION" \
       -b filesize:"$MAX_FILE_SIZE" \
       -w "$OUT_FILE" \
       -q &
TS_PID=$!
set -e

log_info "TShark daemon running in background [PID: $TS_PID]"
log_info "Capture streaming in progress... Press [CTRL+C] to stop."

# Wait for background TShark to finish
wait "$TS_PID" 2>/dev/null || true

if [ -f "$OUT_FILE" ] && [ -s "$OUT_FILE" ]; then
    log_info "Network capture stored successfully: $OUT_FILE ($(du -sh "$OUT_FILE" | cut -f1))"
else
    log_warn "No packets captured or file was rotated dynamically."
fi

#!/usr/bin/env bash
# ==============================================================================
# Wireshark Network Analysis Lab - Enterprise System Dependency Installer
# Purpose: Detects operating system, validates privileges, handles early abort
#          traps, and installs Wireshark, TShark, Python3, and Pip dependencies.
# ==============================================================================

set -euo pipefail

# ANSI color codes for robust logging
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Modular logging functions
log_info() { printf "${GREEN}[INFO] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_warn() { printf "${YELLOW}[WARN] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_err()  { printf "${RED}[ERROR] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }
log_step() { printf "${BLUE}[STEP] [%s]${NC} %s\n" "$(date +'%H:%M:%S')" "$1"; }

# Cleanup trap for graceful termination on SIGINT/SIGTERM
cleanup() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        log_err "Installer interrupted or failed. Cleaning up temporary operations..."
    else
        log_info "Installer completed its run successfully."
    fi
}
trap cleanup EXIT

print_help() {
    echo "Wireshark Dependency Installer Utility"
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help          Show this helper guide and exit"
    echo "  --non-interactive   Suppresses reconfigure prompts for non-root TShark installation"
}

# Parse CLI arguments
interactive=true
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            print_help
            exit 0
            ;;
        --non-interactive)
            interactive=false
            ;;
    esac
done

log_step "Starting enterprise dependency auditing..."

# Validate python3 is available
if ! command -v python3 &>/dev/null; then
    log_err "Python3 is not installed. Please install Python3 before running this installer."
    exit 1
fi

# Detect Operating System
OS_TYPE="$(uname -s)"
log_info "Detected Host OS: $OS_TYPE"

install_debian_deps() {
    log_step "Configuring Debian/Ubuntu system components..."
    
    # Check if apt-get is available
    if ! command -v apt-get &>/dev/null; then
        log_err "apt-get package manager not found on this Linux system."
        exit 1
    fi

    log_info "Updating apt package listings..."
    sudo apt-get update -y

    log_info "Installing Python3 Virtual Environments, TShark, SQLite3, and network tools..."
    sudo apt-get install -y python3-pip python3-venv sqlite3 tshark tcpdump libpcap-dev

    if [ "$interactive" = false ]; then
        log_info "Setting non-interactive pre-selections for TShark setuid configuration..."
        echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
    fi

    log_info "Configuring Wireshark privileges for non-root capture execution..."
    sudo dpkg-reconfigure -f noninteractive wireshark-common || log_warn "Wireshark packet capture privilege reconfig skipped."

    log_info "Adding $USER to the local wireshark privilege group..."
    sudo usermod -aG wireshark "$USER" || log_warn "Failed to add $USER to wireshark group automatically. Capture privileges may require sudo."
}

install_macos_deps() {
    log_step "Configuring macOS / Darwin system components..."
    
    if ! command -v brew &>/dev/null; then
        log_err "Homebrew package manager not found. Please install Homebrew from https://brew.sh first."
        exit 1
    fi

    log_info "Installing wireshark, tshark, and system utilities..."
    brew install wireshark tshark python3 sqlite3 libpcap
}

# Distribute OS-specific installations
case "$OS_TYPE" in
    Linux)
        if [ -f /etc/debian_version ]; then
            install_debian_deps
        else
            log_err "Unsupported Linux distribution. Please install Wireshark, TShark, and Python3 manually via your default package manager."
            exit 1
        fi
        ;;
    Darwin)
        install_macos_deps
        ;;
    *)
        log_err "Unsupported Operating System: $OS_TYPE. This lab requires Ubuntu/Debian or macOS."
        exit 1
        ;;
esac

# Setting up isolated python virtual workspace
log_step "Setting up isolated virtual python environment..."
python3 -m venv venv
# Ensure latest pip is available inside virtualenv
./venv/bin/python3 -m pip install --upgrade pip

if [ -f "requirements.txt" ]; then
    log_info "Installing requirement packages from requirements.txt..."
    ./venv/bin/pip install -r requirements.txt
else
    log_warn "requirements.txt not found. Triggering manual packages load..."
    ./venv/bin/pip install scapy pyshark pandas matplotlib numpy
fi

log_info "System-level installation complete."
log_info "Proceeding to execute './setup.sh' to establish lab paths and sample PCAP datasets."

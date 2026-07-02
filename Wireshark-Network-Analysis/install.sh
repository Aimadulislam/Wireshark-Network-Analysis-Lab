#!/usr/bin/env bash
# ==============================================================================
# Wireshark Network Analysis Lab - Dependency Installer
# Purpose: Detects OS and automates the installation of Wireshark, TShark,
#          Python3, and all required library packages.
# ==============================================================================

set -euo pipefail

# ANSI color codes for pretty output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

print_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help     Show this help message and exit"
    echo "  --non-interactive  Run without prompting (forces Wireshark system configuration)"
}

# Parse basic CLI arguments
interactive=true
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    print_help
    exit 0
elif [[ "${1:-}" == "--non-interactive" ]]; then
    interactive=false
fi

log_info "Starting Wireshark Network Analysis Lab installer..."

# Detect Operating System
OS_TYPE="$(uname -s)"
log_info "Detected operating system: $OS_TYPE"

install_debian_deps() {
    log_info "Updating apt package index..."
    sudo apt-get update -y

    log_info "Installing Python3, Pip, and SQLite..."
    sudo apt-get install -y python3 python3-pip python3-venv sqlite3 tshark

    log_info "Configuring Wireshark/TShark permissions (non-root execution)..."
    if [ "$interactive" = false ]; then
        echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
    fi
    sudo dpkg-reconfigure -f noninteractive wireshark-common || log_warn "DPKG reconfigure skipped"

    log_info "Adding current user to wireshark group..."
    sudo usermod -aG wireshark "$USER" || log_warn "Failed to add user to wireshark group"
    log_warn "Note: You will need to log out and back in for wireshark group memberships to apply."
}

install_macos_deps() {
    if ! command -v brew &> /dev/null; then
        log_err "Homebrew not found! Please install Homebrew first (https://brew.sh) or install Wireshark manually."
        exit 1
    fi
    log_info "Installing wireshark, tshark, and python3 via Homebrew..."
    brew install wireshark tshark python3 sqlite
}

case "$OS_TYPE" in
    Linux)
        if [ -f /etc/debian_version ]; then
            install_debian_deps
        else
            log_err "Unsupported Linux distribution. Please install Wireshark, TShark, and Python3 manually."
            exit 1
        fi
        ;;
    Darwin)
        install_macos_deps
        ;;
    *)
        log_err "Unsupported OS: $OS_TYPE. This lab is optimized for Ubuntu/Debian and macOS."
        exit 1
        ;;
esac

# Setting up virtual environment
log_info "Setting up Python3 virtual environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip

if [ -f "requirements.txt" ]; then
    log_info "Installing python requirements from requirements.txt..."
    ./venv/bin/pip install -r requirements.txt
else
    log_warn "requirements.txt not found. Installing primary packages manually..."
    ./venv/bin/pip install scapy pyshark pandas matplotlib
fi

log_info "Installation completed successfully! Welcome to the Network Analysis Lab."
log_info "Run './setup.sh' next to initialize capturing directories and retrieve sample datasets."

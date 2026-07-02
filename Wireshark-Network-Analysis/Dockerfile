# ==============================================================================
# Wireshark Network Analysis - Enterprise Multi-Stage Build Manifest
# ==============================================================================

# --- Stage 1: Builder & Dependency Auditer ---
FROM python:3.11-slim AS builder

WORKDIR /app

# Install compilation tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Pre-compile Python wheels to speed up building
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Production Hardened Forensics Runtime ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Install security utilities, TShark, tcpdump
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    sqlite3 \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled python site packages from builder
COPY --from=builder /root/.local /root/.local
COPY . .

# Environment Configuration
ENV PATH=/root/.local/bin:$PATH
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Expose capture folders as secure mounts
VOLUME [ "/app/captures", "/app/reports", "/app/logs" ]

# Set up non-root execution capabilities for packet capture
RUN groupadd -g 1500 wireshark_grp && \
    usermod -aG wireshark_grp root && \
    chgrp wireshark_grp /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap

# Basic health assurance check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD ["tshark", "--version"]

# Run the forensics orchestrator script
ENTRYPOINT [ "bash", "./scripts/auto_forensics.sh" ]

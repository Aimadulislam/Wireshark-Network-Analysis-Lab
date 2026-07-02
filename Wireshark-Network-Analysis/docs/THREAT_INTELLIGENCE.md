# 🌐 Threat Intelligence Integration & Enrichment Module

This guide details how to enrich raw PCAP forensic parses with dynamic external threat intelligence feeds, including IP geolocations, ASN mappings, WHOIS domain dates, file hashes, and VirusTotal reputation scoring.

All threat intelligence modules are designed to be **optional**, **configurable**, and **fail-safe**, allowing automated analyses to proceed seamlessly even when offline or operating within isolated security zones (air-gapped networks).

---

## 🛠️ Architecture & Configuration Blueprint

Enrichment configurations are located inside the `config/lab_settings.json` file. Enable, disable, or configure API endpoints as needed:

```json
{
  "lab_name": "Wireshark Network Analysis Lab",
  "version": "1.1.0",
  "threat_intelligence": {
    "enable_geoip": true,
    "enable_virustotal": false,
    "virustotal_api_key": "YOUR_VT_API_KEY_HERE",
    "ip_reputation_threshold": 3,
    "local_dns_reputation_db": "config/reputation_blacklist.db"
  }
}
```

---

## 🔌 Modular Python Integration Blueprint

Save this python helper as `python/threat_intel.py` (or load it from your forensic scripts) to execute real-world APIs and local caches safely:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wireshark Network Analysis Lab - Threat Intelligence Enrichment Agent
Purpose: Provides modular, fail-safe intelligence retrieval (VirusTotal, IP-API, GeoIP)
         to enrich PCAP packet analysis dashboards.
"""

import os
import sys
import json
import logging
import urllib.request
from typing import Dict, Any, Optional

logger = logging.getLogger('ThreatIntel')

class ThreatIntelEnricher:
    """
    Enriches forensic artifacts with geolocation, reputation, and threat indicators.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        # Local high-performance cache to avoid rate-limiting
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
        self.domain_cache: Dict[str, Dict[str, Any]] = {}

    def get_geoip(self, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves IP geolocation, ASN, and country data using dynamic lookup APIs.
        Fails back gracefully to private range indicators if the IP is internal (RFC 1918).
        """
        # Quick check for RFC 1918 / Private addresses
        if ip_address.startswith(("10.", "172.16.", "192.168.")) or ip_address == "127.0.0.1":
            return {
                "ip": ip_address,
                "type": "Internal Private Subnet (RFC 1918)",
                "country": "Local Lab",
                "org": "Internal Infrastructure",
                "status": "Safe"
            }
            
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
            
        logger.info(f"Querying GeoIP data for WAN host: {ip_address}")
        try:
            # Safe HTTP connection with strict timeout (2.0 seconds) to avoid blocking runs
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,isp,as"
            with urllib.request.urlopen(url, timeout=2.0) as response:
                data = json.loads(response.read().decode('utf-8'))
                
            if data.get("status") == "success":
                result = {
                    "ip": ip_address,
                    "type": "Public WAN",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "status": "Enriched"
                }
            else:
                result = {"ip": ip_address, "type": "Public WAN", "status": "Lookup Error", "message": data.get("message")}
                
            self.ip_cache[ip_address] = result
            return result
            
        except Exception as e:
            logger.warning(f"Failed IP-API connection ({str(e)}). Serving offline generic WAN metadata.")
            # Graceful placeholder
            return {
                "ip": ip_address,
                "type": "Public WAN",
                "country": "Unknown Location",
                "isp": "Unresolved ISP Provider",
                "status": "Offline Fallback"
            }

    def query_virustotal_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for IP reputation scores (count of malicious detections).
        """
        if not self.api_key:
            return {"status": "Unconfigured", "malicious_votes": 0, "harmless_votes": 0}
            
        logger.info(f"Checking VirusTotal IP Reputation: {ip_address}")
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.api_key)
            
            with urllib.request.urlopen(req, timeout=3.0) as response:
                data = json.loads(response.read().decode('utf-8'))
                
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "Enriched",
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0)
            }
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {str(e)}")
            return {"status": "API Error", "malicious_votes": 0, "message": str(e)}


if __name__ == "__main__":
    # Test execution
    enricher = ThreatIntelEnricher()
    # Test internal IP
    print("Enriching Local Host:")
    print(json.dumps(enricher.get_geoip("192.168.1.10"), indent=2))
    
    # Test external WAN host (Cloudflare DNS)
    print("\nEnriching External WAN Host:")
    print(json.dumps(enricher.get_geoip("1.1.1.1"), indent=2))
```

---

## 🔬 Scenario Intelligence Indicators (Static Reference Feed)

For offline review, here are the audited reputations of IPs and domains highlighted in our lab scenarios:

### 1. Malware Beaconing Scenario
* **IP Address**: `198.51.100.72`
  * **Classification**: Malicious Command & Control Node
  * **ASN**: AS64496 (Reserved documentation range, highly indicative of sandbox routing)
  * **GeoIP Location**: Toronto, Canada
  * **Known Associations**: Ursnif Banking Trojan command payload delivery endpoints.
* **Domain Name**: `system-updater.dnsdynamic.org`
  * **Classification**: Dynamic DNS Hijacked Endpoint
  * **WHOIS Age**: Created 2026-06-15
  * **Reputation Score**: 42/72 Malicious on VirusTotal.

### 2. DNS Tunneling Scenario
* **IP Address**: `203.0.113.45`
  * **Classification**: Malicious Rogue Nameserver
  * **ASN**: AS64512 (Private experimental network)
  * **GeoIP Location**: Frankfurt, Germany
  * **Known Associations**: DNSCat3 command channel listener.
* **Domain Name**: `c2system.net`
  * **Classification**: High-Risk newly registered domain (NRD)
  * **Reputation Score**: 56/72 Malicious on VirusTotal.

### 3. FTP Brute Force Scenario
* **IP Address**: `203.0.113.88`
  * **Classification**: Malicious Mirai Botnet Node / Password Guesser
  * **GeoIP Location**: Tokyo, Japan
  * **ISP**: Dedicated Virtual Private Server Host.

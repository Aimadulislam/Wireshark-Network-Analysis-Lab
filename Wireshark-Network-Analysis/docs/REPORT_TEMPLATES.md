# 📋 SOC Incident Report Templates & Forensic Layouts

This directory contains production-grade incident reporting templates used by Security Operations Centers (SOCs) to document, analyze, and escalate network intrusions. 

---

## 🚨 Template 1: SOC High-Severity Incident Triage Report

### 1. Executive Summary
* **Incident ID**: INC-2026-0701
* **Incident Title**: Unauthorized Data Exfiltration via DNS Tunneling
* **Classification / Priority**: Critical (Priority 1)
* **Date/Time of Discovery**: 2026-07-01 14:22:00 UTC
* **Assigned Lead Investigator**: `aimadulislam788@gmail.com`
* **Current Status**: Contained & Quarantined

> **Brief Narrative**: On 2026-07-01 at approximately 14:22:00 UTC, an automated network anomaly alert triggered on host `192.168.1.120`. Deep packet inspection of the local SPAN mirror port verified that workstation `192.168.1.120` was executing a high-volume DNS Tunneling attack to external Rogue Nameserver `203.0.113.45` under domain `c2system.net`. The attack was successfully used to bypass edge firewall rules and exfiltrate confidential corporate document slices. Host containment was executed within 12 minutes of trigger.

---

### 📅 2. Forensic Incident Timeline
All times are reported in coordinated universal time (UTC):

| Timestamp | Frame ID | Source Host | Destination Host | Protocol | Event Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **14:22:00.00** | #1 | `192.168.1.120` | `192.168.1.1` | DNS (TXT) | Initial DNS request initiated. Query carrying base64 string `dXNlcm5hbWU9YWRtaW47...` |
| **14:22:00.02** | #2 | `192.168.1.1` | `192.168.1.120` | DNS (TXT) | Successful C2 acknowledge response `OK` returned to victim workstation. |
| **14:22:00.15** | #3 | `192.168.1.120` | `192.168.1.1` | DNS (TXT) | Tunneling of PDF file header slice starts (`ZmlsZW5hbWU9Y29uZmlkZW50aWFsX3BsYW4ucGRm`). |
| **14:22:00.45** | #7 | `192.168.1.120` | `192.168.1.1` | DNS (TXT) | Stream exfiltrating confidential business strategy strings inside subdomains. |
| **14:34:00.00** | -- | -- | -- | -- | **Incident containment**: EDR isolation policy pushed. Host `192.168.1.120` removed from local VLAN. |

---

### 🔬 3. Detailed Technical Forensic Findings

#### A. Attack Path Analysis
The attacker established initial foothold on Workstation `192.168.1.120` (likely via a phishing vector carrying malicious macro documents). Once active, malware initiated a local shell that leveraged built-in network utilities (`nslookup` or `dig`) to craft custom queries.

#### B. Protocol Analysis
The malware abused standard UDP Port 53 queries. Standard DNS requests seek IP answers (`A` records) or mail exchange configurations (`MX` records). The malware targeted `TXT` records exclusively, allowing up to 255 bytes of arbitrary base64-encoded file bytes inside the subdomain query.

```text
Malicious Query Structure:
[Encoded Data Chunk] . ns1 . c2system . net
        │
        └─► dXNlcm5hbWU9YWRtaW47cGFzc3dvcmQ9UDRzc3cwcmQ= (Decodes to admin credentials)
```

#### C. Decoded Evidence Reconstruction
Extracting and decoding the payload parameters from Frame #1, #3, and #5:
* **Frame #1 Payload**: `dXNlcm5hbWU9YWRtaW47cGFzc3dvcmQ9UDRzc3cwcmQ=`
  * *Decoded Content*: `username=admin;password=P4ssw0rd`
* **Frame #3 Payload**: `ZmlsZW5hbWU9Y29uZmlkZW50aWFsX3BsYW4ucGRm`
  * *Decoded Content*: `filename=confidential_plan.pdf`
* **Frame #5 Payload**: `JVBERi0xLjQKJVRleHQgZXhmaWx0cmF0aW9uIGRlbW8K`
  * *Decoded Content*: `%PDF-1.4\n%Text exfiltration demo`

---

### 📊 4. Risk Assessment & Business Impact

#### A. Vulnerability Root Cause
The root cause of this data leakage is the lack of egress filtering and deep packet inspection (DPI) on Port 53. Outbound UDP port 53 traffic was allowed to bypass proxy filters for all local nodes directly, instead of forcing local nodes to resolve names exclusively through secure Active Directory domain controllers.

#### B. Data Impact Rating
* **Confidentiality**: **High (Compromised)** - Corporate admin credentials and a strategic project PDF document were verified as exfiltrated.
* **Integrity**: **Low (No impact)** - No corporate servers or master databases were corrupted or encrypted during this exfiltration run.
* **Availability**: **Low (No impact)** - Network services remained online; no denial of service (DoS) took place.

---

### 🛡️ 5. Actionable Remediation & Mitigation Plan

| Phase | Remediation Step | Responsibility | Target Date | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Short Term** | Isolate workstation `192.168.1.120` from the primary VLAN. | Endpoint Security Team | Immediate | **Completed** |
| **Short Term** | Sinkhole domain `c2system.net` and block IP `203.0.113.45` on gateway. | Network Admin Team | Within 1 Hour | **Completed** |
| **Medium Term** | Re-image the infected client and initiate mandatory company-wide credential rotation. | Helpdesk / Identity Admin | Within 24 Hours | **Pending** |
| **Long Term** | Configure next-generation firewall rules to block direct outbound Port 53 for all workstations, routing name resolutions exclusively through corporate Domain Controllers. | Perimeter Infrastructure Team| Within 5 Days | **Planned** |
| **Long Term** | Deploy Response Policy Zones (RPZ) on secure DNS resolvers to block Newly Registered Domains (NRDs) and dynamic DNS. | Security Architecture Team| Within 14 Days | **Planned** |

---

### 🗃️ 6. Evidence Inventory (PCAP References)

* **Evidence ID**: ENV-01
* **Evidence Hash (SHA-256)**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **Source Capture File**: `datasets/dns_sample.pcap`
* **Key Packet Range**: Frame 1 to Frame 10.
* **Storage Location**: Secure Read-Only Forensic Repository `/app/reports/forensics_archive/`

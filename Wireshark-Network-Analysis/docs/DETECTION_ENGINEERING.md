# 🧬 Detection Engineering & Threat Hunting Playbook

This document outlines industry-standard detection content, alert rules, and playbooks designed to translate raw network packets into high-fidelity actionable security alerts. Each module corresponds directly to traffic traces from our laboratory scenarios.

---

## 🗺️ Framework Mappings

Our detections target critical stages of the intrusion lifecycle, mapped to the **MITRE ATT&CK®** and **MITRE D3FEND™** frameworks:

| Threat Scenario | ATT&CK Tactic | ATT&CK Technique | D3FEND Countermeasure |
| :--- | :--- | :--- | :--- |
| **DNS Tunneling** | Exfiltration (TA0010) | [T1048.003 Exfiltration Over Alternative Protocol: DNS](https://attack.mitre.org/techniques/T1048/003/) | [D3-DNAR DNS Authority Network Analysis](https://d3fend.mitre.org/technique/d3f:DNSAuthorityNetworkAnalysis/) |
| **Port Scanning** | Discovery (TA0007) | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | [D3-IFA IP Filtering Analysis](https://d3fend.mitre.org/technique/d3f:IPFilteringAnalysis/) |
| **FTP Brute Force** | Credential Access (TA0006) | [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | [D3-UAB User Account Brute-force Detection](https://d3fend.mitre.org/technique/d3f:UserAccountBrute-forceDetection/) |
| **C2 Beaconing** | Command & Control (TA0011) | [T1102.001 Web Service: Bidirectional Connection](https://attack.mitre.org/techniques/T1102/001/) | [D3-SDA Network Traffic Session Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficSessionAnalysis/) |

---

## 📝 Sigma Rules (System Event Detection)

These open-source Sigma rules can be converted into queries for modern SIEM systems (Splunk, Elastic, Sentinel) to flag the packet activities observed in our lab captures.

### 1. DNS Tunneling & High-Entropy Subdomains
```yaml
title: Anomalous High-Length Subdomain DNS Queries
id: 5b6c8d32-9c44-411a-821f-84639cbfa231
status: experimental
description: Detects unusually long subdomain requests seeking TXT records, indicating potential base64 DNS exfiltration.
author: Blue Team Forensics Lab
date: 2026/07/01
logsource:
    category: dns
    product: zeek  # Zeek / Corelight / DNS logs
detection:
    selection:
        query_type: 'TXT'
    filter_length:
        query_length|gt: 55
    filter_trusted:
        query|endswith:
            - '.google.com'
            - '.microsoft.com'
            - '.amazonaws.com'
    condition: selection and filter_length and not filter_trusted
fields:
    - src_ip
    - query
    - query_type
falsepositives:
    - Legacy anti-virus software updates executing secure handshakes.
    - Highly customized internal corporate routing agents.
level: high
```

### 2. TCP SYN Sweep (Port Scanning)
```yaml
title: Rapid TCP SYN Scan Sequence
id: d178593a-86c3-4ab0-b47c-6e2bb74b0fa5
status: stable
description: Detects a rapid burst of TCP connection initialization flags (SYN) to multiple distinct ports without complete handshakes.
author: SOC Detection Team
date: 2026/07/01
logsource:
    category: firewall
    product: linux  # iptables / nftables logs
detection:
    selection:
        flags: 'S'  # TCP SYN flag
        action: 'REJECT'  # High count of rejected ports
    timeframe: 2s
    count|gt: 30
    condition: selection
fields:
    - src_ip
    - dst_ip
    - dst_port
falsepositives:
    - Misconfigured database cluster heartbeat checkers.
level: medium
```

---

## 🔍 YARA Rules (Network Payload Inspecting)

These YARA rules can scan captured packet stream dumps (pcap or raw packet bytes) in memory or disk to flag active command-and-control payloads.

### 1. DNS Tunneling Subdomain Signature
```yara
rule DNS_Tunnel_Exfiltration_Signature
{
    meta:
        author = "Forensic Analyst Team"
        description = "Detects long base64-encoded PDF or text headers inside DNS requests targeting c2system.net"
        reference = "MITRE T1048.003"
        severity = "Critical"

    strings:
        $domain = ".ns1.c2system.net" ascii wide nocase
        $b64_pdf = "JVBERi" ascii wide  // %PDF header in base64
        $b64_username = "dXNlcm5hbWU" ascii wide // "username" in base64

    condition:
        $domain and ($b64_pdf or $b64_username)
}
```

### 2. Ursnif Trojan Command Beacon
```yara
rule Ursnif_C2_Web_Beacon
{
    meta:
        author = "Threat Intelligence Team"
        description = "Detects Ursnif banking malware request and control loops over raw HTTP"
        reference = "MITRE T1102.001"
        severity = "High"

    strings:
        $user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii wide
        $query_uri = "/updates/agent.php?id=" ascii wide
        $c2_noop = "COMMAND=NOOP" ascii wide
        $c2_download = "COMMAND=DOWNLOAD" ascii wide

    condition:
        $user_agent and $query_uri and ($c2_noop or $c2_download)
}
```

---

## 📖 Incident Response (IR) Playbooks

When an alert triggers, follow these step-by-step SOC triage guidelines:

### 🚨 Playbook A: DNS Tunneling Exfiltration Identified
1. **Immediate Quarantine**: Issue an API command to the network switch or endpoint protection agent (EDR) to isolate host `192.168.1.120` from the network.
2. **DNS Blackholing**: Enforce Response Policy Zones (RPZ) on internal DNS forwarders to redirect queries for `c2system.net` and its subdomains to a local sinkhole (`127.0.0.1`).
3. **Dump Memory**: Log into the console of `192.168.1.120` out-of-band and generate a RAM memory dump to extract active cryptographic keys and process memory.
4. **Identify Parent Process**: Audit local process creation trees (Sysmon Event ID 1) to determine which running executable initiated the DNS Tunnel (e.g., look for suspicious PowerShell, python, or unsigned binary threads).
5. **Analyze Leaked Data**: Use python to decode base64 strings collected from the DNS queries. Identify compromised records (PDF schemas, corporate keys, credentials).
6. **Remediation**: Re-image the compromised host. Review edge firewall rules and enforce explicit DNS forwarders only, blocking outgoing traffic on Port 53 originating from non-domain controllers.

### 🚨 Playbook B: Internal TCP Port Scan Detected
1. **Source Assessment**: Check if the scanner IP `192.168.1.55` is an authorized internal vulnerability scanner (e.g., Nessus, Qualys) executing a scheduled sweep.
2. **Host Containment**: If unauthorized, isolate `192.168.1.55` via firewall block policies on the local managed switch port.
3. **Target Verification**: Review active ports on the victim `192.168.1.10`. Specifically check if port 22 (SSH) or port 3306 (MySQL) received successful login sessions from `192.168.1.55` right after the scan.
4. **Credential Rotation**: If any port returned authentication logs, initiate a mandatory credential rotation for all system accounts on the database.
5. **Logs Audit**: Verify host-based audit logs (`/var/log/auth.log` or Windows Event ID 4624) on `192.168.1.10` to guarantee no anomalous logins succeeded.

---

## 🛠️ Threat Hunting Queries

Quick queries to copy and execute in your forensic engines:

### TShark (Command Line Packet Hunting)
```bash
# 1. Hunt for the top DNS querying hosts in a capture
tshark -r datasets/dns_sample.pcap -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -rn

# 2. Extract base64 subdomains for DNS TXT queries (to feed to a decoder)
tshark -r datasets/dns_sample.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name | cut -d'.' -f1

# 3. Hunt for TCP half-open port sweeps (SYN sent, no ACK received back)
tshark -r datasets/dhcp_sample.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.dst -e tcp.dstport
```

### Splunk / ELK Query Language
```sql
// Splunk query for DNS exfiltration hunting
index=network sourcetype=zeek_dns
| eval query_len=len(query)
| where query_len > 40 AND qtype="TXT"
| stats count by src_ip, query, qtype
| sort - count
```

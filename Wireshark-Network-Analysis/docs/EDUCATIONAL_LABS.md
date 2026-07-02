# 🎓 Cybersecurity Educational Curriculum & Lab Guide

Welcome to the Wireshark Forensic Laboratory! This syllabus offers a hands-on curriculum divided into Beginner, Intermediate, and Advanced skill tiers. It includes blueprint exercises, Capture the Flag (CTF) packet challenges, quizzes with detailed answer keys, and behavioral SOC Analyst interview preparation cards.

---

## 🎚️ Section 1: Practical Laboratories

### 🟢 Lab 1 (Beginner): Exploring Network Foundations (ARP & DHCP)
* **Goal**: Learn to isolate basic local network setup handshakes and resolve physical host addresses.
* **Dataset Target**: `datasets/dhcp_sample.pcap`
* **Task List**:
  1. Open the PCAP file. Find the first broadcast frame sent. What is its destination MAC?
  2. Find the DHCP IP Lease Request packet. What transaction ID did the workstation generate?
  3. Determine the IP address leased to the workstation. Which router gateway IP authorized the lease?
* **Answers & Clues**:
  * Broadcast packets target MAC `ff:ff:ff:ff:ff:ff`.
  * The DHCP request uses protocol bootstrap protocol (`bootp` filter) containing a randomized transaction ID (e.g., `0x3f1a2e9d`).
  * Look for the `DHCP ACK` message containing the option `IP Address Client: 192.168.1.105` and option `Server Identifier: 192.168.1.1`.

### 🟡 Lab 2 (Intermediate): Port Scan Reconstruction & Target Audit
* **Goal**: Isolate stealth scans and compile an inventory of vulnerable open ports on target assets.
* **Dataset Target**: Simulated Port Scan scenario.
* **Task List**:
  1. Determine the source IP initiating the scans. How many distinct ports did it probe?
  2. Identify the differences in flags returned by closed ports versus open ports.
  3. Formulate a list of open services mapped to the server.
* **Step-by-Step Walkthrough**:
  * Filter for `tcp.flags.syn == 1 && tcp.flags.ack == 0`. Notice a flood of requests originating from `192.168.1.55` targeting `192.168.1.10` on ascending destination ports (21, 22, 80, 443...).
  * Closed ports respond with `tcp.flags.reset == 1` (TCP Reset connection terminated).
  * Open ports respond with `tcp.flags.syn == 1 && tcp.flags.ack == 1` (SYN-ACK). Notice ports `22` and `3306` are the only targets returning SYN-ACK, marking SSH and MySQL as active services.

### 🔴 Lab 3 (Advanced): Reconstructing Cryptographic & Tunneling Intrusion
* **Goal**: Audit DNS Tunneling streams to extract and decode exfiltrated corporate files.
* **Dataset Target**: Simulated DNS Tunneling scenario.
* **Task List**:
  1. Filter out all non-malicious DNS queries. Find the base domain of the external Nameserver.
  2. Isolate the TXT record queries. Identify the character length of the subdomains. Why are they randomized?
  3. Export and decode the base64 query payloads. Reconstruct the stolen document's file type.
* **Step-by-Step Walkthrough**:
  * Execute filter `dns.qry.type == 16`. Isolate queries targeting subdomains of `c2system.net`.
  * Notice subdomains are long, high-entropy strings representing data packets chunked in Base64 (e.g., `JVBERi0xLjQKJVRleHQ...`).
  * Copy the base64 string and run it through a decoder:
    ```bash
    echo "JVBERi0xLjQKJVRleHQ..." | base64 -d
    ```
    The decoded output begins with `%PDF-1.4`, verifying that a corporate PDF document was exfiltrated piece-by-piece inside standard DNS queries.

---

## 🏆 Section 2: Capture-the-Flag (CTF) Challenges

### Challenge 1: The Outdated Browser Spy
* **Scenario**: An alert states that an employee workstation is browsing utilizing an ancient User Agent string, a signature behavior of the Ursnif banking malware.
* **Your Mission**: Identify the IP address of the compromised workstation, determine the domain name of the C2 command node, and extract the name of the secondary payload binary downloaded by the malware.
* **Flag Format**: `flag{ClientIP_C2Domain_PayloadName}`
* **Clue**: Execute the filter `http.user_agent matches "MSIE"` and inspect the TCP streams following successful GET loops.

---

## 📝 Section 3: Interactive Quizzes

### Question 1
**An attacker is performing an active Man-In-The-Middle (MITM) attack. You notice a flood of ARP Replies declaring that the gateway IP `192.168.1.1` is located at MAC `00:0c:29:ab:cd:12`. Simultaneously, you know that the pfSense firewall is at `00:50:56:c0:00:08`. What filter isolates this conflict state?**
* A) `arp.opcode == 1`
* B) `arp.duplicate-address-detected`
* C) `ip.addr == 192.168.1.1`
* D) `tcp.flags.reset == 1`
* **Correct Answer**: **B**. Wireshark's built-in Expert Info system flags `arp.duplicate-address-detected` when it notices multiple MAC addresses claiming to own a single IP address in the local tables.

### Question 2
**Why is DNS tunneling on Port 53 a popular egress exfiltration channel for advanced persistent threats (APTs)?**
* A) DNS packets are naturally encrypted, hiding payloads.
* B) Port 53 is rarely inspected or blocked by enterprise outbound firewalls, as local servers need it to resolve public addresses.
* C) It operates faster than standard HTTP or FTP transfers.
* D) DNS is a Layer 2 protocol, bypassing IP firewalls completely.
* **Correct Answer**: **B**. Corporate boundaries often block or inspect standard outbound HTTP/HTTPS ports, but let Port 53 flow freely to ensure name resolution succeeds. This makes it an ideal exfiltration channel.

---

## 💼 Section 4: SOC Analyst Interview Prep Sheets

 h3>Question 1: "Explain how you would detect a slow, low-and-slow vertical port scan using Wireshark vs a fast horizontal scan."
* **Superb Response**: 
  > "A horizontal scan attempts to locate a single open port (like port 22/SSH) across thousands of distinct machines on a subnet. In Wireshark, I look for a single destination port with multiple distinct destination IP addresses. 
  > A vertical scan maps multiple ports on a single machine. For a 'low-and-slow' vertical scan, standard rate-limiting thresholds might miss it. I would filter for a single source IP and a single destination IP, and analyze the TCP SYN requests over an expanded timeframe (hours instead of seconds). I would also group packets by unique destination port. If the window size is constant across diverse ports and the TCP sequence numbers are linear, it indicates a scanning engine like Nmap."

### Question 2: "If you notice an outbound packet stream following port 443 with an SSL Client Hello SNI field of 'malicious-domain.com', but you cannot view the HTTP payload because it's encrypted, what are your next triage steps?"
* **Superb Response**: 
  > "Even without SSL/TLS decryption keys, the cleartext Server Name Indication (SNI) in the TLS Handshake (Type 1 - Client Hello) gives me immediate threat confirmation. 
  > First, I would query the domain reputation on Threat Intelligence feeds (like VirusTotal, Talos, or Shodan) to verify the threat rating. 
  > Second, I would pivot to host-based logs (EDR or Sysmon Event ID 3 - Network Connections) on the originating workstation to identify which binary file opened that socket. 
  > Third, I would check if the connection was followed by a large volume of bytes, indicating data leakage. 
  > Finally, I would isolate the workstation and block the IP/domain at our perimeter gateway."

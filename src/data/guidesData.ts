export interface FilterItem {
  id: string;
  category: string;
  filter: string;
  description: string;
  example: string;
  expectedOutput: string;
}

export interface InvestigationItem {
  id: string;
  title: string;
  background: string;
  steps: string[];
  filters: { title: string; cmd: string; explanation: string }[];
  expectedFindings: string;
  mitreMapping: string;
  recommendations: string[];
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  structure: {
    sectionName: string;
    placeholder: string;
    type: 'text' | 'textarea' | 'select';
    options?: string[];
  }[];
}

export const FILTERS_LIBRARY: FilterItem[] = [
  {
    id: 'f1',
    category: 'Basic',
    filter: 'ip.addr == 192.168.1.105',
    description: 'Filters all packets where the IP address is either the source or destination.',
    example: 'ip.addr == 192.168.1.105',
    expectedOutput: 'A list of packets flowing to or from 192.168.1.105, regardless of protocol (TCP, HTTP, DNS, etc.).'
  },
  {
    id: 'f2',
    category: 'Basic',
    filter: 'ip.src == 192.168.1.55 && ip.dst == 192.168.1.10',
    description: 'Filters packets travelling from a specific source IP to a specific destination IP.',
    example: 'ip.src == 192.168.1.55 && ip.dst == 192.168.1.10',
    expectedOutput: 'Traffic stream originating strictly from host .55 going to server .10.'
  },
  {
    id: 'f3',
    category: 'DNS',
    filter: 'dns.flags.response == 0',
    description: 'Filters for DNS query packets only.',
    example: 'dns.flags.response == 0',
    expectedOutput: 'All DNS lookups initiated by internal client devices.'
  },
  {
    id: 'f4',
    category: 'DNS',
    filter: 'dns.flags.response == 1 && dns.flags.rcode != 0',
    description: 'Filters for DNS responses indicating an error (such as NXDOMAIN - No Such Name).',
    example: 'dns.flags.rcode == 3',
    expectedOutput: 'DNS server responses returning error code 3 (NXDOMAIN), commonly searched for in domain-generation-algorithm (DGA) or command & control discovery.'
  },
  {
    id: 'f5',
    category: 'HTTP',
    filter: 'http.request.method == "POST"',
    description: 'Filters for all HTTP POST requests (often containing user logins, form submittals, or malware exfiltration payloads).',
    example: 'http.request.method == "POST"',
    expectedOutput: 'HTTP headers showing endpoint targeted and content lengths of submitted data.'
  },
  {
    id: 'f6',
    category: 'HTTP',
    filter: 'http.user_agent matches "Wget|Curl|Python|nmap"',
    description: 'Filters for HTTP requests containing non-standard or command-line scripting User Agents, indicating automated scraping or tools scanning.',
    example: 'http.user_agent matches "nmap"',
    expectedOutput: 'Packet info showing request headers with the offending user agent string.'
  },
  {
    id: 'f7',
    category: 'TCP',
    filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
    description: 'Filters for TCP connection requests (SYN only). Extremely useful for port scan detection.',
    example: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
    expectedOutput: 'A high frequency of these packets targeting many destination ports indicates an active port scan.'
  },
  {
    id: 'f8',
    category: 'TCP',
    filter: 'tcp.analysis.retransmission || tcp.analysis.duplicate_ack',
    description: 'Filters for TCP anomalies including retransmissions and duplicate ACKs. Standard indicators of network congestion or packet loss.',
    example: 'tcp.analysis.retransmission',
    expectedOutput: 'Highlighting frames in dark grey/red that indicate network errors, bad connections, or performance degradation.'
  },
  {
    id: 'f9',
    category: 'TLS / HTTPS',
    filter: 'tls.handshake.type == 1',
    description: 'Filters for TLS Client Hello handshakes. Useful to map and identify secure domains requested over SNI (Server Name Indication).',
    example: 'tls.handshake.extension.type == 0',
    expectedOutput: 'Shows the Client Hello handshake packets, containing cleartext Server Name Indication (SNI) indicating which secure domain the workstation is connecting to.'
  },
  {
    id: 'f10',
    category: 'ARP',
    filter: 'arp.opcode == 2 && arp.duplicate-address-detected',
    description: 'Filters for ARP reply packets where a duplicate IP address conflict has been resolved. Highly indicative of ARP spoofing.',
    example: 'arp.opcode == 2',
    expectedOutput: 'ARP replies claiming to own an IP that already belongs to another MAC address.'
  },
  {
    id: 'f11',
    category: 'DHCP',
    filter: 'bootp.option.type == 53 && bootp.option.value == 2',
    description: 'Filters for DHCP Offer messages. Can be used to scan and detect unauthorized Rogue DHCP Servers operating on local subnets.',
    example: 'bootp.option.value == 2',
    expectedOutput: 'A DHCP Offer packet sent from a source IP address that does not match the corporate DHCP helper range.'
  },
  {
    id: 'f12',
    category: 'Malware',
    filter: 'dns.qry.name.len > 40 && dns.qry.type == 16',
    description: 'Filters for DNS query lengths greater than 40 characters requesting TXT records, an indicator of DNS tunneling and exfiltration.',
    example: 'dns.qry.name.len > 40 && dns.qry.type == 16',
    expectedOutput: 'Suspiciously long DNS queries containing subdomains of encoded bytes requesting TXT profiles.'
  }
];

export const INVESTIGATIONS: InvestigationItem[] = [
  {
    id: 'dns_tunnel',
    title: 'DNS Tunneling & Data Exfiltration Investigation',
    background: 'DNS Tunneling is a technique where an attacker abuses the DNS protocol (usually TXT, CNAME, or NULL records) to tunnel non-DNS protocols (such as SSH, HTTP, or raw data payload) through corporate firewalls, which rarely block port 53.',
    steps: [
      'Identify anomalous DNS traffic volume originating from a single internal client workstation.',
      'Check the packet lengths and distribution of record types (TXT and C2 systems prefer TXT due to maximum payload capacity).',
      'Examine the entropy of subdomains: randomized, high-character count subdomains (e.g., dXNlci5wZGY=.ns1.attacker.com) represent data chunks encoded in Base64 or Hex.',
      'Correlate the timestamps: standard DNS requests occur in bursts based on web browsing, while DNS tunneling is constant, automated, and exhibits rigid periodicity.'
    ],
    filters: [
      { title: 'Identify all TXT queries', cmd: 'dns.qry.type == 16', explanation: 'Filters for TXT query records, the preferred data container for DNS exfiltration and C2 tools like DNSCat3.' },
      { title: 'Anomalous long subdomain names', cmd: 'dns.qry.name.len > 50', explanation: 'Filters for extremely long domain queries which frequently carry encoded documents or command buffers.' },
      { title: 'Count DNS traffic per source IP (TShark CLI)', cmd: 'tshark -r capture.pcap -q -z hosts', explanation: 'Generates an IP-to-hostname translation list and session statistics to pin down the top talker.' }
    ],
    expectedFindings: 'Workstation 192.168.1.120 sent over 800 DNS TXT queries to c2system.net in 1 minute. Decoding the subdomains reveals cleartext indicators: USERNAME, PASSWORD, and header bytes of a PDF file (%PDF-1.4).',
    mitreMapping: 'Exfiltration (TA0010) → Exfiltration Over Alternative Protocol (T1048.003)',
    recommendations: [
      'Isolate the infected workstation (192.168.1.120) from the subnet.',
      'Blackhole the malicious root domain (c2system.net) on internal DNS forwarders.',
      'Deploy DNS security policies (RPZ - Response Policy Zones) to block lookups of dynamic DNS and newly registered domains.',
      'Establish length thresholds on local DNS resolvers (e.g., raise alerts for queries > 60 characters).'
    ]
  },
  {
    id: 'port_scan',
    title: 'Internal Reconnaissance & Port Scanning',
    background: 'Port scanning is a crucial first step in lateral movement and threat expansion. Attackers use tools like Nmap to perform rapid TCP SYN scans (half-open stealth scans) to identify active hosts and open server ports inside a compromised network.',
    steps: [
      'Search for high-volume, rapid TCP connection initiation packets (SYN) sent to multiple distinct destination ports.',
      'Look for the response ratio: a closed port will respond with a TCP RST (Reset) packet, while an open port will respond with a SYN-ACK.',
      'Examine the TCP Window size: scanning engines often use static window sizes (e.g., 1024, 2048, or 3072) across all probes to save memory.',
      'Check for completed handshakes: scanners rarely complete the handshake. Once a port responds with SYN-ACK, the scanner immediately sends a RST to abort the connection and save scanning duration.'
    ],
    filters: [
      { title: 'Detect half-open SYN scan attempts', cmd: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', explanation: 'Isolates connection request packages. Look for high counts of these targeting multiple ports on a server.' },
      { title: 'Map connection terminations (Closed Ports)', cmd: 'tcp.flags.reset == 1 && tcp.flags.ack == 1', explanation: 'Identifies ports returning a Reset back to the scanner, verifying the destination ports were inactive/blocked.' },
      { title: 'Verify active open TCP ports (Completed Scans)', cmd: 'tcp.flags.syn == 1 && tcp.flags.ack == 1', explanation: 'Finds ports that returned a successful SYN-ACK, mapping exactly which services are active on the victim machine.' }
    ],
    expectedFindings: 'Host 192.168.1.55 sent SYN requests to over 500 ports of Database Server 192.168.1.10 in less than 2 seconds. The server responded with RST-ACK on 498 ports. Ports 22 (SSH) and 3306 (MySQL) responded with SYN-ACK, marking them as open.',
    mitreMapping: 'Discovery (TA0007) → Network Service Discovery (T1046)',
    recommendations: [
      'Configure host-based firewalls (iptables/Windows Defender) on database servers to reject unsolicited connections.',
      'Isolate scanning client 192.168.1.55 and inspect active terminal history for nmap or custom python scan scripts.',
      'Deploy Intrusion Detection Systems (IDS) with automated threshold rules to block source IPs initiating connections exceeding 10 ports/second.'
    ]
  },
  {
    id: 'malware_c2',
    title: 'Ursnif Banking Trojan Command & Control Analysis',
    background: 'Command and Control (C2) traffic represents communication channels established by compromised hosts to pull task instructions from external command servers and dump stolen credential profiles.',
    steps: [
      'Locate HTTP packets and extract the requested URI paths and host headers.',
      'Analyze the periodicity of GET/POST traffic: beaconing malware executes on strict cron/thread timer schedules to poll tasks.',
      'Inspect the User-Agent header: malware developers often hardcode outdated user-agents or introduce minor typos (e.g., trailing spaces) into headers.',
      'Look for executable and encrypted file deliveries over clear HTTP streams.'
    ],
    filters: [
      { title: 'Extract all HTTP GET queries', cmd: 'http.request.method == "GET"', explanation: 'Isolates HTTP retrieval actions. Used to find polling requests.' },
      { title: 'Identify anomalous User-Agents', cmd: 'http.user_agent matches "MSIE 6.0|Wget|Curl|Python"', explanation: 'Locates traffic requesting web pages using scripting languages or ancient browser agents.' },
      { title: 'Filter secure TLS domains requested', cmd: 'tls.handshake.extension.type == 0', explanation: 'Identifies the SNI domain requests, mapping background SSL domains even if traffic payload is encrypted.' }
    ],
    expectedFindings: 'Workstation 192.168.1.105 established a connection to system-updater.dnsdynamic.org every 30 seconds exactly. The HTTP header shows a legacy IE6 User-Agent string. On the third beacon, the server issued a DOWNLOAD command resulting in a binary retrieval (/bin/payload.bin).',
    mitreMapping: 'Command and Control (TA0011) → Web Service (T1102.001)',
    recommendations: [
      'Quarantine host 192.168.1.105 from accessing internal or external subnets.',
      'Extract payload hash of "/bin/payload.bin" and query VirusTotal or local threat repositories.',
      'Enable SSL/TLS decryption on the boundary proxy server to monitor encrypted payload payloads.',
      'Implement User-Agent white-listing: block all outbound user agent headers that do not match current standard enterprise browsers.'
    ]
  }
];

export const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    id: 'incident',
    name: 'Standard Security Incident Report',
    description: 'A formal security forensic report used by SOC analysts to document a network intrusion, security breach, or policy violation discovered via packet analysis.',
    structure: [
      { sectionName: 'Incident Title', placeholder: 'e.g., Data Leakage via DNS Tunneling on Workstation .120', type: 'text' },
      { sectionName: 'Severity Level', placeholder: 'Select severity...', type: 'select', options: ['Low', 'Medium', 'High', 'Critical'] },
      { sectionName: 'Threat Vector / Protocol', placeholder: 'e.g., DNS, TCP SYN Scan, HTTP Malware', type: 'text' },
      { sectionName: 'Source IP (Attacker/Host)', placeholder: 'e.g., 192.168.1.120', type: 'text' },
      { sectionName: 'Destination IP (Victim/C2)', placeholder: 'e.g., 203.0.113.45', type: 'text' },
      { sectionName: 'Key Wireshark/TShark Filters Used', placeholder: 'e.g., dns.qry.type == 16 && dns.qry.name.len > 40', type: 'textarea' },
      { sectionName: 'Technical Forensic Findings', placeholder: 'Describe step-by-step what was observed in the packets. Reference specific frame numbers and payload bytes...', type: 'textarea' },
      { sectionName: 'Impact & Business Risk', placeholder: 'What data was compromised? What systems were vulnerable?', type: 'textarea' },
      { sectionName: 'Actionable Mitigation Steps', placeholder: '1. Isolate IP...\n2. Block domain...\n3. Enforce policy...', type: 'textarea' }
    ]
  },
  {
    id: 'perf',
    name: 'TCP Performance & Troubleshooting Assessment',
    description: 'A structural report used by Network Engineers to assess network congestion, packet drop, and round-trip bottlenecks based on TCP analysis.',
    structure: [
      { sectionName: 'Report Title', placeholder: 'e.g., Database Server Connection Retransmission Audit', type: 'text' },
      { sectionName: 'Impact Classification', placeholder: 'Select priority...', type: 'select', options: ['Low Priority', 'Normal Congestion', 'High Packet Loss', 'Severe Outage'] },
      { sectionName: 'Target Service & Subnet', placeholder: 'e.g., 192.168.1.10 MySQL Service', type: 'text' },
      { sectionName: 'Average Round-Trip Time (RTT)', placeholder: 'e.g., 120ms', type: 'text' },
      { sectionName: 'Filters for TCP Packet Analysis', placeholder: 'e.g., tcp.analysis.retransmission || tcp.analysis.duplicate_ack', type: 'textarea' },
      { sectionName: 'Bottleneck Investigation Details', placeholder: 'Describe packet retransmissions, TCP window size changes, or connection resets noticed in the capture...', type: 'textarea' },
      { sectionName: 'Identified Root Cause', placeholder: 'e.g., Router queue buffer-bloat, packet corruption, faulty ethernet switch port...', type: 'textarea' },
      { sectionName: 'Remediation Plan', placeholder: '1. Replace patch cable...\n2. Configure QoS policing...\n3. Optimize TCP window scale...', type: 'textarea' }
    ]
  }
];

export const VIRTUAL_LAB_GUIDE = {
  ipAddressPlan: [
    { hostname: 'Gateway Router', ip: '192.168.1.1', subnet: '255.255.255.0', type: 'Router Interface', OS: 'pfSense / Cisco iOS' },
    { hostname: 'Primary DNS & DHCP Server', ip: '192.168.1.1', subnet: '255.255.255.0', type: 'Local Utility Service', OS: 'Linux Ubuntu Server' },
    { hostname: 'Corporate Web / DB Server', ip: '192.168.1.10', subnet: '255.255.255.0', type: 'Server Asset', OS: 'Ubuntu 22.04 LTS (MySQL & FTP)' },
    { hostname: 'Finance Workstation', ip: '192.168.1.105', subnet: '255.255.255.0', type: 'Client User Device', OS: 'Windows 10 Enterprise' },
    { hostname: 'Marketing Workstation', ip: '192.168.1.112', subnet: '255.255.255.0', type: 'Client User Device', OS: 'macOS Sonoma' },
    { hostname: 'Development Workstation', ip: '192.168.1.120', subnet: '255.255.255.0', type: 'Client User Device (Infected)', OS: 'Ubuntu Desktop 20.04' },
    { hostname: 'Cybersecurity Analyst Box', ip: '192.168.1.150', subnet: '255.255.255.0', type: 'Monitoring/Analysis Lab', OS: 'Kali Linux (Wireshark/TShark)' },
    { hostname: 'Rogue C2 Server', ip: '203.0.113.45', subnet: 'External WAN IP', type: 'Malicious External Host', OS: 'Debian (Attacker Control Node)' },
    { hostname: 'External Brute-Force Botnet IP', ip: '203.0.113.88', subnet: 'External WAN IP', type: 'Malicious External Host', OS: 'Alpine Linux (Mirai infection)' }
  ],
  labTopology: `
========================================
     VIRTUAL NETWORK TOPOLOGY DIAGRAM
========================================

                 [ ATTACKER C2 SERVER ]
                     (203.0.113.45)
                           │
                     [ PUBLIC WAN ]
                           │
                     [ INTERNET ]
                           │
                   [ EDGE FIREWALL ]
                    (pfSense Router)
                     (192.168.1.1)
                           │
              ┌────────────┴────────────┐
              │                         │
      [ L2 SMART SWITCH ]      [ MONITORING SPAN PORT ]
        (VLAN 10 Subnet)        (Mirroring all traffic)
              │                         │
   ┌──────────┼──────────┐              │
   │          │          │              │
[USER-A]   [USER-B]   [SERVERS]   [KALI ANALYST]
 .105       .120        .10        (Wireshark/TShark)
(Win 10)  (Ubuntu)    (Linux)         .150
            (Infected) (MySQL/FTP)
  `,
  trafficFlows: [
    { flow: 'User .105 → Router .1', protocol: 'DHCP/DNS/ARP', direction: 'Internal Network Control', function: 'Initial IP lease request and gateway resolution' },
    { flow: 'Infected .120 → Router .1 → WAN C2', protocol: 'DNS Tunneling', direction: 'Outbound Exfiltration', function: 'Leaking base64 credentials inside DNS TXT request subdomains' },
    { flow: 'Analyst .150 (SPANNED)', protocol: 'Passive Promiscuous Monitoring', direction: 'Inward Listening', function: 'TShark daemon captures all subnet frames for live threat parsing' }
  ]
};

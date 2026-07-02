export interface Packet {
  id: number;
  time: number; // relative time in seconds
  source: string;
  destination: string;
  protocol: 'HTTP' | 'HTTPS' | 'DNS' | 'TCP' | 'UDP' | 'ARP' | 'DHCP' | 'SSH' | 'FTP' | 'ICMP';
  length: number;
  info: string;
  flags?: string;
  payload?: string;
  suspicious?: boolean;
}

export interface Conversation {
  src: string;
  dst: string;
  packets: number;
  bytes: number;
  duration: number;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  threatLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  mitreMapping?: {
    id: string;
    name: string;
    tactic: string;
  };
  stats: {
    protocolDistribution: { name: string; value: number; color: string }[];
    topIps: { ip: string; packets: number; role: string }[];
    topDomains: { domain: string; count: number; status: 'Clean' | 'Suspicious' }[];
    topPorts: { port: string; service: string; count: number }[];
    bandwidthTimeline: { time: string; bytes: number; packets: number }[];
  };
  conversations: Conversation[];
  alerts: {
    id: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    source: string;
    destination: string;
    matchingFilter: string;
    mitigation: string;
  }[];
  packets: Packet[];
}

export const SCENARIOS: Record<string, Scenario> = {
  normal: {
    id: 'normal',
    name: 'Normal Enterprise Traffic',
    description: 'A standard 5-minute snapshot of an enterprise network subnet. Features normal web browsing (HTTPS/HTTP), local name resolutions (DNS), dynamic address assignment (DHCP), and local address resolution (ARP).',
    threatLevel: 'Low',
    stats: {
      protocolDistribution: [
        { name: 'HTTPS', value: 580, color: '#3b82f6' },
        { name: 'HTTP', value: 120, color: '#60a5fa' },
        { name: 'DNS', value: 95, color: '#10b981' },
        { name: 'TCP (control)', value: 85, color: '#f59e0b' },
        { name: 'UDP (other)', value: 45, color: '#ec4899' },
        { name: 'ARP', value: 30, color: '#8b5cf6' },
        { name: 'DHCP', value: 10, color: '#a78bfa' }
      ],
      topIps: [
        { ip: '192.168.1.105', packets: 420, role: 'Workstation (User)' },
        { ip: '104.244.42.129', packets: 340, role: 'Twitter Inc. (HTTPS)' },
        { ip: '192.168.1.1', packets: 140, role: 'Default Gateway (DHCP/DNS)' },
        { ip: '192.168.1.112', packets: 95, role: 'Workstation (User)' },
        { ip: '8.8.8.8', packets: 90, role: 'Google Public DNS' }
      ],
      topDomains: [
        { domain: 'google.com', count: 42, status: 'Clean' },
        { domain: 'github.com', count: 28, status: 'Clean' },
        { domain: 'microsoft.com', count: 21, status: 'Clean' },
        { domain: 'slack.com', count: 18, status: 'Clean' },
        { domain: 'aws.amazon.com', count: 12, status: 'Clean' }
      ],
      topPorts: [
        { port: '443', service: 'HTTPS', count: 580 },
        { port: '80', service: 'HTTP', count: 120 },
        { port: '53', service: 'DNS', count: 95 },
        { port: '67/68', service: 'DHCP', count: 10 },
        { port: '123', service: 'NTP', count: 8 }
      ],
      bandwidthTimeline: [
        { time: '10:00:00', bytes: 45000, packets: 85 },
        { time: '10:00:10', bytes: 128000, packets: 142 },
        { time: '10:00:20', bytes: 320000, packets: 210 },
        { time: '10:00:30', bytes: 95000, packets: 112 },
        { time: '10:00:40', bytes: 540000, packets: 340 },
        { time: '10:00:50', bytes: 180000, packets: 160 },
        { time: '10:01:00', bytes: 62000, packets: 95 }
      ]
    },
    conversations: [
      { src: '192.168.1.105', dst: '104.244.42.129', packets: 340, bytes: 485000, duration: 42.5 },
      { src: '192.168.1.105', dst: '192.168.1.1', packets: 82, bytes: 8400, duration: 58.1 },
      { src: '192.168.1.112', dst: '8.8.8.8', packets: 56, bytes: 6200, duration: 55.4 },
      { src: '192.168.1.105', dst: '142.250.190.46', packets: 120, bytes: 145000, duration: 18.2 }
    ],
    alerts: [],
    packets: [
      { id: 1, time: 0.0000, source: '00:11:22:33:44:55', destination: 'ff:ff:ff:ff:ff:ff', protocol: 'ARP', length: 60, info: 'Who has 192.168.1.1? Tell 192.168.1.105' },
      { id: 2, time: 0.0012, source: '00:11:22:33:aa:bb', destination: '00:11:22:33:44:55', protocol: 'ARP', length: 60, info: '192.168.1.1 is at 00:11:22:33:aa:bb' },
      { id: 3, time: 0.0450, source: '0.0.0.0', destination: '255.255.255.255', protocol: 'DHCP', length: 342, info: 'DHCP Request - Transaction ID 0x3f1a2e9d' },
      { id: 4, time: 0.0910, source: '192.168.1.1', destination: '192.168.1.105', protocol: 'DHCP', length: 342, info: 'DHCP ACK - IP: 192.168.1.105, Lease: 86400s' },
      { id: 5, time: 1.1240, source: '192.168.1.105', destination: '192.168.1.1', protocol: 'DNS', length: 74, info: 'Standard query 0x5fa1 A google.com' },
      { id: 6, time: 1.1410, source: '192.168.1.1', destination: '192.168.1.105', protocol: 'DNS', length: 90, info: 'Standard query response 0x5fa1 A google.com A 142.250.190.46' },
      { id: 7, time: 1.1520, source: '192.168.1.105', destination: '142.250.190.46', protocol: 'TCP', length: 74, info: '49152 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460' },
      { id: 8, time: 1.1680, source: '142.250.190.46', destination: '192.168.1.105', protocol: 'TCP', length: 74, info: '443 → 49152 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1430' },
      { id: 9, time: 1.1685, source: '192.168.1.105', destination: '142.250.190.46', protocol: 'TCP', length: 66, info: '49152 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0' },
      { id: 10, time: 1.1820, source: '192.168.1.105', destination: '142.250.190.46', protocol: 'HTTPS', length: 517, info: 'Client Hello (TLSv1.3)' },
      { id: 11, time: 1.1990, source: '142.250.190.46', destination: '192.168.1.105', protocol: 'HTTPS', length: 1430, info: 'Server Hello, Change Cipher Spec, Encrypted Extensions' },
      { id: 12, time: 1.2500, source: '192.168.1.105', destination: '142.250.190.46', protocol: 'HTTPS', length: 120, info: 'Application Data (HTTP/2 GET /)' },
      { id: 13, time: 1.2720, source: '142.250.190.46', destination: '192.168.1.105', protocol: 'HTTPS', length: 980, info: 'Application Data (HTTP/2 200 OK)' },
      { id: 14, time: 5.4300, source: '192.168.1.112', destination: '8.8.8.8', protocol: 'DNS', length: 74, info: 'Standard query 0x77ab A github.com' },
      { id: 15, time: 5.4520, source: '8.8.8.8', destination: '192.168.1.112', protocol: 'DNS', length: 90, info: 'Standard query response 0x77ab A github.com A 140.82.121.4' },
      { id: 16, time: 15.1100, source: '192.168.1.105', destination: '192.168.1.1', protocol: 'ICMP', length: 74, info: 'Echo (ping) request id=0x03ea, seq=1, ttl=64' },
      { id: 17, time: 15.1112, source: '192.168.1.1', destination: '192.168.1.105', protocol: 'ICMP', length: 74, info: 'Echo (ping) reply id=0x03ea, seq=1, ttl=64 (reply in 1.2ms)' }
    ]
  },
  dns_tunneling: {
    id: 'dns_tunneling',
    name: 'DNS Tunneling & Data Exfiltration',
    description: 'A critical data exfiltration scenario where malware installed on internal workstation 192.168.1.120 uses the DNS protocol to bypass local firewalls and leak sensitive company documentation (in Base64 subdomains) to an attacker-controlled external domain.',
    threatLevel: 'Critical',
    mitreMapping: {
      id: 'T1048.003',
      name: 'Exfiltration Over Alternative Protocol: DNS',
      tactic: 'Exfiltration'
    },
    stats: {
      protocolDistribution: [
        { name: 'DNS', value: 850, color: '#10b981' },
        { name: 'HTTPS', value: 140, color: '#3b82f6' },
        { name: 'TCP (control)', value: 45, color: '#f59e0b' },
        { name: 'ARP', value: 15, color: '#8b5cf6' }
      ],
      topIps: [
        { ip: '192.168.1.120', packets: 875, role: 'Infected Host (Workstation)' },
        { ip: '192.168.1.1', packets: 850, role: 'DNS Forwarder (Gateway)' },
        { ip: '203.0.113.45', packets: 850, role: 'Rogue Nameserver (Attacker C2)' },
        { ip: '192.168.1.105', packets: 42, role: 'Workstation (User)' },
        { ip: '142.250.190.46', packets: 30, role: 'Google Server' }
      ],
      topDomains: [
        { domain: '*.ns1.c2system.net', count: 812, status: 'Suspicious' },
        { domain: 'google.com', count: 18, status: 'Clean' },
        { domain: 'github.com', count: 12, status: 'Clean' },
        { domain: 'update.windows.com', count: 8, status: 'Clean' }
      ],
      topPorts: [
        { port: '53', service: 'DNS', count: 850 },
        { port: '443', service: 'HTTPS', count: 140 },
        { port: '80', service: 'HTTP', count: 20 }
      ],
      bandwidthTimeline: [
        { time: '14:22:00', bytes: 12000, packets: 80 },
        { time: '14:22:10', bytes: 94000, packets: 310 },
        { time: '14:22:20', bytes: 112000, packets: 340 },
        { time: '14:22:30', bytes: 108000, packets: 330 },
        { time: '14:22:40', bytes: 84000, packets: 280 },
        { time: '14:22:50', bytes: 14000, packets: 90 },
        { time: '14:23:00', bytes: 8000, packets: 40 }
      ]
    },
    conversations: [
      { src: '192.168.1.120', dst: '192.168.1.1', packets: 850, bytes: 218000, duration: 65.4 },
      { src: '192.168.1.1', dst: '203.0.113.45', packets: 850, bytes: 218000, duration: 65.4 },
      { src: '192.168.1.120', dst: '104.244.42.129', packets: 40, bytes: 64000, duration: 12.3 }
    ],
    alerts: [
      {
        id: 'AL-DNS-001',
        severity: 'critical',
        title: 'High-Frequency Subdomain Queries (DNS Tunneling)',
        description: 'Detected anomalous burst of TXT and A queries targeting heavily randomized subdomains under "c2system.net". Character lengths of subdomains consistently exceed 50 characters, containing high-entropy alphanumeric characters (Base64 signature).',
        source: '192.168.1.120',
        destination: '192.168.1.1 (and forwarded to C2 Nameserver 203.0.113.45)',
        matchingFilter: 'dns.qry.name matches "\\.[a-zA-Z0-9-]{30,}\\.c2system\\.net$" or dns.qry.type == 16',
        mitigation: 'Isolate host 192.168.1.120 from the network immediately. Block the domain "c2system.net" and IP "203.0.113.45" at the perimeter firewall. Inspect host process memory for running remote access agents (e.g. Cobalt Strike, DNSCat3).'
      }
    ],
    packets: [
      { id: 1, time: 0.0000, source: '192.168.1.120', destination: '192.168.1.1', protocol: 'DNS', length: 110, info: 'Standard query 0x14ea TXT dXNlcm5hbWU9YWRtaW47cGFzc3dvcmQ9UDRzc3cwcmQ=.ns1.c2system.net', payload: 'dXNlcm5hbWU9YWRtaW47cGFzc3dvcmQ9UDRzc3cwcmQ=', suspicious: true },
      { id: 2, time: 0.0210, source: '192.168.1.1', destination: '192.168.1.120', protocol: 'DNS', length: 130, info: 'Standard query response 0x14ea TXT OK.ns1.c2system.net', payload: 'OK', suspicious: true },
      { id: 3, time: 0.1500, source: '192.168.1.120', destination: '192.168.1.1', protocol: 'DNS', length: 125, info: 'Standard query 0x14eb TXT ZmlsZW5hbWU9Y29uZmlkZW50aWFsX3BsYW4ucGRm.ns1.c2system.net', payload: 'ZmlsZW5hbWU9Y29uZmlkZW50aWFsX3BsYW4ucGRm', suspicious: true },
      { id: 4, time: 0.1740, source: '192.168.1.1', destination: '192.168.1.120', protocol: 'DNS', length: 135, info: 'Standard query response 0x14eb TXT OK.ns1.c2system.net', payload: 'OK', suspicious: true },
      { id: 5, time: 0.3100, source: '192.168.1.120', destination: '192.168.1.1', protocol: 'DNS', length: 145, info: 'Standard query 0x14ec TXT JVBERi0xLjQKJVRleHQgZXhmaWx0cmF0aW9uIGRlbW8K.ns1.c2system.net', payload: 'JVBERi0xLjQKJVRleHQgZXhmaWx0cmF0aW9uIGRlbW8K', suspicious: true },
      { id: 6, time: 0.3390, source: '192.168.1.1', destination: '192.168.1.120', protocol: 'DNS', length: 155, info: 'Standard query response 0x14ec TXT ACK_SEQ_1', payload: 'ACK_SEQ_1', suspicious: true },
      { id: 7, time: 0.4500, source: '192.168.1.120', destination: '192.168.1.1', protocol: 'DNS', length: 152, info: 'Standard query 0x14ed TXT MDA0IDU2Nzg5IGFjYmRlZiBjb25maWRlbnRpYWwgc3RyYXRlZ3k=.ns1.c2system.net', payload: 'MDA0IDU2Nzg5IGFjYmRlZiBjb25maWRlbnRpYWwgc3RyYXRlZ3k=', suspicious: true },
      { id: 8, time: 0.4710, source: '192.168.1.1', destination: '192.168.1.120', protocol: 'DNS', length: 152, info: 'Standard query response 0x14ed TXT ACK_SEQ_2', payload: 'ACK_SEQ_2', suspicious: true },
      { id: 9, time: 2.1050, source: '192.168.1.105', destination: '192.168.1.1', protocol: 'DNS', length: 74, info: 'Standard query 0x8aef A internal-wiki.local' },
      { id: 10, time: 2.1120, source: '192.168.1.1', destination: '192.168.1.105', protocol: 'DNS', length: 90, info: 'Standard query response 0x8aef A internal-wiki.local A 192.168.1.10' }
    ]
  },
  port_scan: {
    id: 'port_scan',
    name: 'Reconnaissance & Port Scan',
    description: 'A lateral reconnaissance scan where an internal malicious actor (or compromised workstation 192.168.1.55) runs an automated SYN scan (Nmap) mapping active services on critical Database Server 192.168.1.10.',
    threatLevel: 'Medium',
    mitreMapping: {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery'
    },
    stats: {
      protocolDistribution: [
        { name: 'TCP (control)', value: 920, color: '#f59e0b' },
        { name: 'DNS', value: 20, color: '#10b981' },
        { name: 'ARP', value: 12, color: '#8b5cf6' }
      ],
      topIps: [
        { ip: '192.168.1.55', packets: 920, role: 'Attacker Host (Scans)' },
        { ip: '192.168.1.10', packets: 480, role: 'Database Server (Target)' },
        { ip: '192.168.1.1', packets: 12, role: 'Default Gateway' }
      ],
      topDomains: [
        { domain: 'None (Direct IP connections)', count: 0, status: 'Clean' }
      ],
      topPorts: [
        { port: '80', service: 'HTTP (Closed)', count: 42 },
        { port: '443', service: 'HTTPS (Closed)', count: 42 },
        { port: '22', service: 'SSH (Open - Active)', count: 38 },
        { port: '3306', service: 'MySQL (Open - Active)', count: 38 },
        { port: '1433', service: 'MSSQL (Closed)', count: 32 }
      ],
      bandwidthTimeline: [
        { time: '02:11:40', bytes: 18000, packets: 300 },
        { time: '02:11:41', bytes: 24000, packets: 400 },
        { time: '02:11:42', bytes: 14000, packets: 240 },
        { time: '02:11:43', bytes: 1200, packets: 20 }
      ]
    },
    conversations: [
      { src: '192.168.1.55', dst: '192.168.1.10', packets: 910, bytes: 54600, duration: 2.1 }
    ],
    alerts: [
      {
        id: 'AL-SCAN-002',
        severity: 'medium',
        title: 'TCP SYN Port Scan Detected',
        description: 'An aggressive, high-speed TCP port scan has been identified originating from 192.168.1.55 targeting 192.168.1.10. Over 50 unique ports were probed in under 2 seconds, with an abnormally high ratio of SYN packets to RST packets (indicates half-open stealth scanning).',
        source: '192.168.1.55',
        destination: '192.168.1.10',
        matchingFilter: 'tcp.flags.syn == 1 and tcp.flags.ack == 0 and (count(tcp.dstport) > 20 in 5s)',
        mitigation: 'Implement dynamic host blocking (shun) on the attacker IP 192.168.1.55. Inspect local logs on 192.168.1.10 to ensure no connections successfully completed and authenticated.'
      }
    ],
    packets: [
      { id: 1, time: 0.0000, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52011 → 21 [SYN] Seq=0 Win=1024 Len=0', flags: 'SYN', suspicious: true },
      { id: 2, time: 0.0004, source: '192.168.1.10', destination: '192.168.1.55', protocol: 'TCP', length: 60, info: '21 → 52011 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0', flags: 'RST, ACK', suspicious: true },
      { id: 3, time: 0.0080, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52012 → 22 [SYN] Seq=0 Win=1024 Len=0', flags: 'SYN', suspicious: true },
      { id: 4, time: 0.0084, source: '192.168.1.10', destination: '192.168.1.55', protocol: 'TCP', length: 60, info: '22 → 52012 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0', flags: 'SYN, ACK', suspicious: true },
      { id: 5, time: 0.0090, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52012 → 22 [RST] Seq=1 Win=0 Len=0', flags: 'RST', suspicious: true },
      { id: 6, time: 0.0120, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52013 → 80 [SYN] Seq=0 Win=1024 Len=0', flags: 'SYN', suspicious: true },
      { id: 7, time: 0.0124, source: '192.168.1.10', destination: '192.168.1.55', protocol: 'TCP', length: 60, info: '80 → 52013 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0', flags: 'RST, ACK', suspicious: true },
      { id: 8, time: 0.0160, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52014 → 443 [SYN] Seq=0 Win=1024 Len=0', flags: 'SYN', suspicious: true },
      { id: 9, time: 0.0163, source: '192.168.1.10', destination: '192.168.1.55', protocol: 'TCP', length: 60, info: '443 → 52014 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0', flags: 'RST, ACK', suspicious: true },
      { id: 10, time: 0.0210, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52015 → 3306 [SYN] Seq=0 Win=1024 Len=0', flags: 'SYN', suspicious: true },
      { id: 11, time: 0.0215, source: '192.168.1.10', destination: '192.168.1.55', protocol: 'TCP', length: 60, info: '3306 → 52015 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0', flags: 'SYN, ACK', suspicious: true },
      { id: 12, time: 0.0220, source: '192.168.1.55', destination: '192.168.1.10', protocol: 'TCP', length: 60, info: '52015 → 3306 [RST] Seq=1 Win=0 Len=0', flags: 'RST', suspicious: true }
    ]
  },
  brute_force: {
    id: 'brute_force',
    name: 'Brute Force Login Attack',
    description: 'An aggressive credential-stuffing attack targeting FTP server port 21. An external brute-force bot (203.0.113.88) issues thousands of connection requests attempting standard default credentials on the root user of internal asset 192.168.1.10.',
    threatLevel: 'High',
    mitreMapping: {
      id: 'T1110.001',
      name: 'Brute Force: Password Guessing',
      tactic: 'Credential Access'
    },
    stats: {
      protocolDistribution: [
        { name: 'FTP', value: 720, color: '#ec4899' },
        { name: 'TCP (control)', value: 410, color: '#f59e0b' },
        { name: 'DNS', value: 12, color: '#10b981' },
        { name: 'HTTPS', value: 8, color: '#3b82f6' }
      ],
      topIps: [
        { ip: '203.0.113.88', packets: 1130, role: 'Attacker (External)' },
        { ip: '192.168.1.10', packets: 1120, role: 'FTP Server (Victim)' },
        { ip: '192.168.1.1', packets: 15, role: 'Default Gateway' }
      ],
      topDomains: [
        { domain: 'None (Direct IP connections)', count: 0, status: 'Clean' }
      ],
      topPorts: [
        { port: '21', service: 'FTP', count: 720 },
        { port: '443', service: 'HTTPS', count: 8 }
      ],
      bandwidthTimeline: [
        { time: '08:44:00', bytes: 14000, packets: 110 },
        { time: '08:44:05', bytes: 64000, packets: 420 },
        { time: '08:44:10', bytes: 72000, packets: 480 },
        { time: '08:44:15', bytes: 31000, packets: 210 }
      ]
    },
    conversations: [
      { src: '203.0.113.88', dst: '192.168.1.10', packets: 1130, bytes: 181000, duration: 15.2 }
    ],
    alerts: [
      {
        id: 'AL-BRUTE-003',
        severity: 'high',
        title: 'FTP Brute Force Login Attack',
        description: 'Detected a large wave of credential failures targeting the FTP service on 192.168.1.10. An external IP 203.0.113.88 completed over 300 authentication loops with command "USER root" followed by "PASS [masked]", each resulting in "530 Login incorrect".',
        source: '203.0.113.88',
        destination: '192.168.1.10',
        matchingFilter: 'ftp.response.code == 530 and count(ftp.response.code) > 10 in 10s',
        mitigation: 'Implement IP address blocking at the edge firewall for 203.0.113.88. Enforce strong account lockout policies and configure SSH/FTP server to use public-key-only authentication, disabling password-based root access.'
      }
    ],
    packets: [
      { id: 1, time: 0.0000, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'TCP', length: 74, info: '38192 → 21 [SYN] Seq=0 Win=14600 Len=0' },
      { id: 2, time: 0.0310, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'TCP', length: 74, info: '21 → 38192 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0' },
      { id: 3, time: 0.0620, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'TCP', length: 66, info: '38192 → 21 [ACK] Seq=1 Ack=1 Win=14600 Len=0' },
      { id: 4, time: 0.0750, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'FTP', length: 90, info: 'Response: 220 Welcome to proftpd 1.3.5' },
      { id: 5, time: 0.1120, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'FTP', length: 80, info: 'Request: USER root', payload: 'USER root', suspicious: true },
      { id: 6, time: 0.1430, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'FTP', length: 85, info: 'Response: 331 Password required for root' },
      { id: 7, time: 0.1800, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'FTP', length: 82, info: 'Request: PASS admin', payload: 'PASS admin', suspicious: true },
      { id: 8, time: 0.2200, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'FTP', length: 92, info: 'Response: 530 Login incorrect', payload: '530 Login incorrect', suspicious: true },
      { id: 9, time: 0.2310, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'TCP', length: 66, info: '38192 → 21 [FIN, ACK] Seq=25 Ack=45 Win=14600' },
      { id: 10, time: 0.2600, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'TCP', length: 74, info: '38194 → 21 [SYN] Seq=0 Win=14600 Len=0' },
      { id: 11, time: 0.3120, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'FTP', length: 80, info: 'Request: USER root', payload: 'USER root', suspicious: true },
      { id: 12, time: 0.3800, source: '203.0.113.88', destination: '192.168.1.10', protocol: 'FTP', length: 82, info: 'Request: PASS password', payload: 'PASS password', suspicious: true },
      { id: 13, time: 0.4100, source: '192.168.1.10', destination: '203.0.113.88', protocol: 'FTP', length: 92, info: 'Response: 530 Login incorrect', payload: '530 Login incorrect', suspicious: true }
    ]
  },
  malware_beacon: {
    id: 'malware_beacon',
    name: 'Command & Control Malware Beaconing',
    description: 'An advanced persistent threat (APT) scenario where workstation 192.168.1.105, infected with banking trojan Ursnif, conducts rigid, periodic beaconing routines over HTTP to a dynamic Command and Control server.',
    threatLevel: 'High',
    mitreMapping: {
      id: 'T1102.001',
      name: 'Command and Control: Web Service',
      tactic: 'Command and Control'
    },
    stats: {
      protocolDistribution: [
        { name: 'HTTP', value: 340, color: '#60a5fa' },
        { name: 'HTTPS', value: 210, color: '#3b82f6' },
        { name: 'DNS', value: 45, color: '#10b981' },
        { name: 'TCP (control)', value: 65, color: '#f59e0b' }
      ],
      topIps: [
        { ip: '192.168.1.105', packets: 660, role: 'Infected Host (Ursnif)' },
        { ip: '198.51.100.72', packets: 340, role: 'C2 Control Server (Rogue IP)' },
        { ip: '192.168.1.1', packets: 45, role: 'Default Gateway' }
      ],
      topDomains: [
        { domain: 'system-updater.dnsdynamic.org', count: 32, status: 'Suspicious' },
        { domain: 'google.com', count: 8, status: 'Clean' }
      ],
      topPorts: [
        { port: '80', service: 'HTTP', count: 340 },
        { port: '443', service: 'HTTPS', count: 210 },
        { port: '53', service: 'DNS', count: 45 }
      ],
      bandwidthTimeline: [
        { time: '12:00:00', bytes: 8400, packets: 12 },
        { time: '12:00:30', bytes: 8400, packets: 12 },
        { time: '12:01:00', bytes: 8400, packets: 12 },
        { time: '12:01:30', bytes: 8400, packets: 12 },
        { time: '12:02:00', bytes: 8400, packets: 12 },
        { time: '12:02:30', bytes: 8400, packets: 12 }
      ]
    },
    conversations: [
      { src: '192.168.1.105', dst: '198.51.100.72', packets: 340, bytes: 50400, duration: 150.0 }
    ],
    alerts: [
      {
        id: 'AL-MAL-004',
        severity: 'high',
        title: 'Highly Rigid HTTP Beaconing Behavior',
        description: 'Detected rigid, structured periodic HTTP GET requests from 192.168.1.105 to 198.51.100.72 exactly every 30.0 seconds (+/- 0.1s jitter). This is indicative of malware agent pull requests polling for task instructions from a Command & Control handler.',
        source: '192.168.1.105',
        destination: '198.51.100.72',
        matchingFilter: 'http.request.method == "GET" and http.user_agent matches "Wget" or (periodicity_analysis == "rigid")',
        mitigation: 'Block IP 198.51.100.72 immediately on the gateway. Isolate 192.168.1.105 and run a full forensic analysis of active system handles, listening processes, and registry startup keys.'
      },
      {
        id: 'AL-MAL-005',
        severity: 'medium',
        title: 'Suspicious User-Agent Header',
        description: 'The HTTP GET query targeting "system-updater.dnsdynamic.org" uses a highly outdated or non-standard User-Agent header string: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" running from a modern subnet, a common malware indicator.',
        source: '192.168.1.105',
        destination: '198.51.100.72',
        matchingFilter: 'http.user_agent == "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"',
        mitigation: 'Block matching User-Agents at the corporate proxy server level. Implement TLS interception to prevent command and control channels from shifting to HTTPS.'
      }
    ],
    packets: [
      { id: 1, time: 0.0000, source: '192.168.1.105', destination: '198.51.100.72', protocol: 'HTTP', length: 280, info: 'GET /updates/agent.php?id=8812 HTTP/1.1 (UA: MSIE 6.0)', payload: 'GET /updates/agent.php?id=8812 HTTP/1.1\r\nHost: system-updater.dnsdynamic.org\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\nAccept: */*\r\nConnection: Close\r\n\r\n', suspicious: true },
      { id: 2, time: 0.0820, source: '198.51.100.72', destination: '192.168.1.105', protocol: 'HTTP', length: 320, info: 'HTTP/1.1 200 OK (text/html) [Command: NOOP]', payload: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\nConnection: Close\r\n\r\nCOMMAND=NOOP', suspicious: true },
      { id: 3, time: 30.0010, source: '192.168.1.105', destination: '198.51.100.72', protocol: 'HTTP', length: 280, info: 'GET /updates/agent.php?id=8812 HTTP/1.1 (UA: MSIE 6.0)', payload: 'GET /updates/agent.php?id=8812 HTTP/1.1\r\nHost: system-updater.dnsdynamic.org\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\nAccept: */*\r\nConnection: Close\r\n\r\n', suspicious: true },
      { id: 4, time: 30.0840, source: '198.51.100.72', destination: '192.168.1.105', protocol: 'HTTP', length: 320, info: 'HTTP/1.1 200 OK (text/html) [Command: NOOP]', payload: 'HTTP/1.1 200 OK\r\nCOMMAND=NOOP', suspicious: true },
      { id: 5, time: 60.0020, source: '192.168.1.105', destination: '198.51.100.72', protocol: 'HTTP', length: 280, info: 'GET /updates/agent.php?id=8812 HTTP/1.1 (UA: MSIE 6.0)', payload: 'GET /updates/agent.php?id=8812 HTTP/1.1\r\nHost: system-updater.dnsdynamic.org\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n\r\n', suspicious: true },
      { id: 6, time: 60.0850, source: '198.51.100.72', destination: '192.168.1.105', protocol: 'HTTP', length: 320, info: 'HTTP/1.1 200 OK (text/html) [Command: DOWNLOAD payload.bin]', payload: 'HTTP/1.1 200 OK\r\nCOMMAND=DOWNLOAD url=http://198.51.100.72/bin/payload.bin', suspicious: true },
      { id: 7, time: 61.1200, source: '192.168.1.105', destination: '198.51.100.72', protocol: 'HTTP', length: 210, info: 'GET /bin/payload.bin HTTP/1.1', payload: 'GET /bin/payload.bin HTTP/1.1\r\nHost: system-updater.dnsdynamic.org\r\n', suspicious: true },
      { id: 8, time: 61.2200, source: '198.51.100.72', destination: '192.168.1.105', protocol: 'HTTP', length: 1450, info: 'HTTP/1.1 200 OK (application/octet-stream) [1024 bytes payload]', payload: 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n[Binary content of trojan execution payload]', suspicious: true }
    ]
  }
};

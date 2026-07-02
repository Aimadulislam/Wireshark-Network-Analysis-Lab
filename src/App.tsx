import React, { useState, useMemo } from 'react';
import { 
  Network, 
  ShieldAlert, 
  Activity, 
  FileSpreadsheet, 
  Terminal, 
  BookOpen, 
  FileCode, 
  CheckCircle2, 
  AlertCircle, 
  XCircle, 
  Search, 
  Filter, 
  Download, 
  Copy, 
  Play, 
  RefreshCw, 
  Cpu, 
  Server, 
  Database,
  ArrowRight,
  ChevronRight,
  HelpCircle
} from 'lucide-react';

import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Legend, 
  LineChart, 
  Line, 
  AreaChart, 
  Area 
} from 'recharts';

import { SCENARIOS, Scenario, Packet } from './data/scenarios';
import { FILTERS_LIBRARY, INVESTIGATIONS, REPORT_TEMPLATES, VIRTUAL_LAB_GUIDE } from './data/guidesData';
import { LAB_SCRIPTS } from './data/labScripts';

export default function App() {
  // Navigation Tabs
  const [activeTab, setActiveTab] = useState<'dashboard' | 'analyzer' | 'threats' | 'lab' | 'filters' | 'scripts' | 'reports'>('dashboard');
  
  // Active Scenario Configuration
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('dns_tunneling');
  const scenario = useMemo(() => SCENARIOS[selectedScenarioId] || SCENARIOS.normal, [selectedScenarioId]);

  // Search & Filter state for packets
  const [wiresharkFilter, setWiresharkFilter] = useState<string>('');
  const [appliedFilter, setAppliedFilter] = useState<string>('');
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(scenario.packets[0] || null);

  // Report Form state
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('incident');
  const activeTemplate = useMemo(() => REPORT_TEMPLATES.find(t => t.id === selectedTemplateId) || REPORT_TEMPLATES[0], [selectedTemplateId]);
  const [reportFormData, setReportFormData] = useState<Record<string, string>>({});
  const [generatedReport, setGeneratedReport] = useState<string>('');

  // Active Script State
  const [selectedScriptIndex, setSelectedScriptIndex] = useState<number>(0);
  const activeScript = LAB_SCRIPTS[selectedScriptIndex] || LAB_SCRIPTS[0];
  const [copiedScript, setCopiedScript] = useState<boolean>(false);

  // Status Alerts
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Wireshark filter execution simulator
  const filteredPackets = useMemo(() => {
    if (!appliedFilter.trim()) return scenario.packets;
    
    const query = appliedFilter.trim().toLowerCase();
    
    return scenario.packets.filter(pkt => {
      // Direct matches
      if (query === 'dns' && pkt.protocol === 'DNS') return true;
      if (query === 'http' && (pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS')) return true;
      if (query === 'tcp' && pkt.protocol === 'TCP') return true;
      if (query === 'udp' && pkt.protocol === 'UDP') return true;
      if (query === 'arp' && pkt.protocol === 'ARP') return true;
      if (query === 'dhcp' && pkt.protocol === 'DHCP') return true;
      if (query === 'ssh' && pkt.protocol === 'SSH') return true;
      if (query === 'ftp' && pkt.protocol === 'FTP') return true;
      if (query === 'icmp' && pkt.protocol === 'ICMP') return true;
      
      // IP filters e.g. "ip.addr == 192.168.1.10" or "ip.src == 192.168.1.120"
      if (query.includes('ip.addr')) {
        const parts = query.split('==');
        if (parts.length > 1) {
          const ip = parts[1].replace(/['"\s]/g, '');
          return pkt.source === ip || pkt.destination === ip;
        }
      }
      if (query.includes('ip.src')) {
        const parts = query.split('==');
        if (parts.length > 1) {
          const ip = parts[1].replace(/['"\s]/g, '');
          return pkt.source === ip;
        }
      }
      if (query.includes('ip.dst')) {
        const parts = query.split('==');
        if (parts.length > 1) {
          const ip = parts[1].replace(/['"\s]/g, '');
          return pkt.destination === ip;
        }
      }

      // Payload strings
      if (query.includes('contains') || query.includes('matches')) {
        const searchStr = query.replace(/.*(contains|matches)\s+['"]?([^'"]+)['"]?.*/, '$2');
        return pkt.info.toLowerCase().includes(searchStr) || 
               (pkt.payload && pkt.payload.toLowerCase().includes(searchStr)) || false;
      }
      
      // Fallback: general query string match across all packet attributes
      return pkt.source.toLowerCase().includes(query) ||
             pkt.destination.toLowerCase().includes(query) ||
             pkt.protocol.toLowerCase().includes(query) ||
             pkt.info.toLowerCase().includes(query);
    });
  }, [scenario.packets, appliedFilter]);

  // Reset filter
  const handleClearFilter = () => {
    setWiresharkFilter('');
    setAppliedFilter('');
  };

  // Compile Report Markdown
  const handleGenerateReport = (e: React.FormEvent) => {
    e.preventDefault();
    let md = `# SECURITY FORENSIC ASSESSMENT REPORT\n`;
    md += `*Generated via Wireshark Network Analysis Lab Report Engine*\n`;
    md += `*Timestamp: ${new Date().toISOString()}*\n\n`;
    md += `## 1. Executive Summary\n`;
    md += `This report outlines the technical forensic capture analysis of the **${scenario.name}** scenario.\n\n`;
    
    md += `## 2. Investigation Attributes\n`;
    activeTemplate.structure.forEach(field => {
      const val = reportFormData[field.sectionName] || 'Not specified';
      md += `* **${field.sectionName}**: ${val}\n`;
    });
    md += `\n`;

    md += `## 3. Threat Metrics & Indicators\n`;
    md += `* **Subnet Scope**: 192.168.1.0/24\n`;
    md += `* **Identified Severity Level**: ${scenario.threatLevel}\n`;
    if (scenario.mitreMapping) {
      md += `* **MITRE ATT&CK Mapping**: [${scenario.mitreMapping.id}] ${scenario.mitreMapping.name} - ${scenario.mitreMapping.tactic}\n`;
    }
    md += `* **Total Packets Logged**: ${scenario.packets.length} packets resolved\n\n`;

    md += `## 4. Analysis & Forensic Timeline (PCAP Highlights)\n`;
    md += `| Frame | Time (s) | Source IP | Destination IP | Protocol | Summary Information |\n`;
    md += `|---|---|---|---|---|---|\n`;
    scenario.packets.slice(0, 8).forEach(p => {
      md += `| ${p.id} | ${p.time.toFixed(4)} | ${p.source} | ${p.destination} | ${p.protocol} | ${p.info} |\n`;
    });
    md += `\n`;

    md += `## 5. Security Recommendations & Hardening\n`;
    if (scenario.alerts.length > 0) {
      scenario.alerts.forEach((alert, i) => {
        md += `### Alert ${i+1}: ${alert.title}\n`;
        md += `* **Observed Threat**: ${alert.description}\n`;
        md += `* **Countermeasure Policy**: ${alert.mitigation}\n\n`;
      });
    } else {
      md += `* No critical intrusion signatures matched standard network logs. Standard port validation and lease rotation advised.\n`;
    }

    setGeneratedReport(md);
    triggerToast("Forensic Report successfully compiled!");
  };

  const handleCopyReport = () => {
    navigator.clipboard.writeText(generatedReport);
    triggerToast("Report copied to clipboard!");
  };

  const handleCopyScript = () => {
    navigator.clipboard.writeText(activeScript.code);
    setCopiedScript(true);
    triggerToast("Script content copied to clipboard!");
    setTimeout(() => setCopiedScript(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-900">
      
      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed top-4 right-4 z-50 bg-cyan-500 text-slate-950 px-4 py-3 rounded-lg shadow-2xl flex items-center gap-2 border border-cyan-400 text-sm font-medium animate-bounce">
          <CheckCircle2 className="w-5 h-5" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Main Header / Control Center */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 sticky top-0 z-40">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-br from-cyan-500 to-blue-600 p-2.5 rounded-lg shadow-lg shadow-cyan-500/20">
            <Network className="w-6 h-6 text-slate-950" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              Wireshark Network Analysis Lab
              <span className="text-[10px] bg-cyan-500/20 text-cyan-400 font-mono px-2 py-0.5 rounded border border-cyan-500/30">
                PRO EDITION
              </span>
            </h1>
            <p className="text-xs text-slate-400">SOC Forensic Training & Simulated Traffic Playground</p>
          </div>
        </div>

        {/* Active Scenario Selector */}
        <div className="flex items-center gap-3 bg-slate-950 p-1.5 rounded-xl border border-slate-800">
          <span className="text-xs text-slate-400 px-2 font-medium hidden lg:inline">Lab Scenario:</span>
          <select 
            value={selectedScenarioId}
            onChange={(e) => {
              setSelectedScenarioId(e.target.value);
              setWiresharkFilter('');
              setAppliedFilter('');
              setSelectedPacket(SCENARIOS[e.target.value]?.packets[0] || null);
              triggerToast(`Switched lab context to: ${SCENARIOS[e.target.value]?.name}`);
            }}
            className="bg-slate-900 text-sm text-cyan-400 font-medium rounded-lg border border-slate-700 py-1.5 px-3 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
          >
            <option value="normal">Normal Background Subnet Traffic</option>
            <option value="dns_tunneling">Threat: DNS Tunnel Exfiltration (TXT)</option>
            <option value="port_scan">Threat: Internal TCP SYN Port Scan</option>
            <option value="brute_force">Threat: FTP Password Brute Force</option>
            <option value="malware_beacon">Threat: Ursnif C2 HTTP Beaconing</option>
          </select>
        </div>
      </header>

      {/* Primary Layout Block */}
      <div className="flex flex-1 flex-col lg:flex-row">
        
        {/* Navigation Rail */}
        <aside className="w-full lg:w-64 border-b lg:border-b-0 lg:border-r border-slate-800 bg-slate-900/30 flex flex-col">
          <nav className="p-4 space-y-1.5 flex-1 overflow-y-auto">
            <button 
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'dashboard' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Live Dashboards</span>
            </button>

            <button 
              onClick={() => setActiveTab('analyzer')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'analyzer' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Packet Dissector</span>
            </button>

            <button 
              onClick={() => setActiveTab('threats')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'threats' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Threat Hunting Desk</span>
              {scenario.alerts.length > 0 && (
                <span className="ml-auto bg-red-500 text-white text-[10px] px-1.5 py-0.5 rounded-full font-bold">
                  {scenario.alerts.length}
                </span>
              )}
            </button>

            <button 
              onClick={() => setActiveTab('lab')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'lab' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Network className="w-4 h-4" />
              <span>Virtual Lab Plan</span>
            </button>

            <button 
              onClick={() => setActiveTab('filters')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'filters' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Filter Library</span>
            </button>

            <button 
              onClick={() => setActiveTab('scripts')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'scripts' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>Automation Scripts</span>
            </button>

            <button 
              onClick={() => setActiveTab('reports')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'reports' 
                  ? 'bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <FileSpreadsheet className="w-4 h-4" />
              <span>Report Architect</span>
            </button>
          </nav>

          {/* Quick Active Scenario Overview */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/50">
            <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-1">Active Scenario Profile</h4>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-white truncate max-w-[120px]">{scenario.name}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${
                scenario.threatLevel === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                scenario.threatLevel === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                scenario.threatLevel === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                'bg-green-500/20 text-green-400 border border-green-500/30'
              }`}>
                {scenario.threatLevel}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal line-clamp-2">{scenario.description}</p>
          </div>
        </aside>

        {/* Primary Screen Area */}
        <main className="flex-1 p-6 overflow-y-auto max-w-full">

          {/* TAB 1: LIVE DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              
              {/* Scenario Quick Stats Callout */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs text-slate-400">Incident Severity Status</p>
                    <h3 className={`text-xl font-bold mt-1 ${
                      scenario.threatLevel === 'Critical' ? 'text-red-500' :
                      scenario.threatLevel === 'High' ? 'text-orange-400' :
                      scenario.threatLevel === 'Medium' ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      {scenario.threatLevel}
                    </h3>
                  </div>
                  <div className={`p-2.5 rounded-lg ${
                    scenario.threatLevel === 'Critical' ? 'bg-red-500/10 text-red-500' :
                    scenario.threatLevel === 'High' ? 'bg-orange-500/10 text-orange-500' :
                    'bg-cyan-500/10 text-cyan-400'
                  }`}>
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs text-slate-400">Total Simulated Packets</p>
                    <h3 className="text-xl font-extrabold mt-1 text-white">
                      {scenario.packets.length}
                    </h3>
                  </div>
                  <div className="p-2.5 bg-blue-500/10 text-blue-400 rounded-lg">
                    <Terminal className="w-5 h-5" />
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs text-slate-400">Distinct Active Endpoints</p>
                    <h3 className="text-xl font-extrabold mt-1 text-white">
                      {scenario.stats.topIps.length}
                    </h3>
                  </div>
                  <div className="p-2.5 bg-green-500/10 text-green-400 rounded-lg">
                    <Network className="w-5 h-5" />
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs text-slate-400">Critical SOC Alerts</p>
                    <h3 className={`text-xl font-extrabold mt-1 ${scenario.alerts.length > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                      {scenario.alerts.length}
                    </h3>
                  </div>
                  <div className={`p-2.5 rounded-lg ${scenario.alerts.length > 0 ? 'bg-red-500/10 text-red-400' : 'bg-slate-800 text-slate-500'}`}>
                    <AlertCircle className="w-5 h-5" />
                  </div>
                </div>
              </div>

              {/* Charts Section */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Protocol Distribution Pie */}
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl lg:col-span-5 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200">Protocol Distribution (Packets Count)</h3>
                    <p className="text-xs text-slate-400 mb-4">Percentage allocation based on tshark trace parsing</p>
                  </div>
                  <div className="h-64 flex justify-center items-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={scenario.stats.protocolDistribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {scenario.stats.protocolDistribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#fff' }} />
                        <Legend wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Traffic Timeline Chart */}
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl lg:col-span-7 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200">Network Bandwidth Timeline</h3>
                    <p className="text-xs text-slate-400 mb-4">Real-time throughput metrics (Bytes vs Time)</p>
                  </div>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={scenario.stats.bandwidthTimeline}>
                        <defs>
                          <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                            <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                        <YAxis stroke="#64748b" fontSize={10} label={{ value: 'Bytes', angle: -90, position: 'insideLeft', style: { fill: '#64748b', fontSize: 10 } }} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} />
                        <Area type="monotone" dataKey="bytes" name="Througput (Bytes)" stroke="#06b6d4" fillOpacity={1} fill="url(#colorBytes)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              {/* Endpoints & Domains Info Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Top IP Talkers */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-slate-200 mb-1">Top Network Talkers (Hosts)</h3>
                  <p className="text-xs text-slate-400 mb-4">Devices with largest packet footprints on subnetwork</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2">IP Address</th>
                          <th className="py-2 text-right">Packets Streamed</th>
                          <th className="py-2 pl-4">Identified Subnet Role</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scenario.stats.topIps.map((host, i) => (
                          <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/20">
                            <td className="py-2.5 font-mono text-cyan-400 font-semibold">{host.ip}</td>
                            <td className="py-2.5 text-right text-white font-mono">{host.packets}</td>
                            <td className="py-2.5 pl-4 text-slate-300 font-medium">{host.role}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* DNS Lookup Statistics */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-slate-200 mb-1">Resolved DNS Domains</h3>
                  <p className="text-xs text-slate-400 mb-4">Top queries extracted from UDP/53 frame captures</p>
                  {scenario.stats.topDomains.length > 0 && scenario.stats.topDomains[0].count > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2">Query Target Domain</th>
                            <th className="py-2 text-right">Query Frequency</th>
                            <th className="py-2 pl-4">Security Classification</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scenario.stats.topDomains.map((dom, i) => (
                            <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/20">
                              <td className="py-2.5 font-mono text-white truncate max-w-xs">{dom.domain}</td>
                              <td className="py-2.5 text-right font-mono text-slate-400">{dom.count}</td>
                              <td className="py-2.5 pl-4">
                                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                  dom.status === 'Suspicious' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                                }`}>
                                  {dom.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8 text-center bg-slate-950/30 rounded-lg">
                      <HelpCircle className="w-8 h-8 text-slate-600 mb-2" />
                      <p className="text-xs text-slate-500">No active DNS resolution statistics matching this scenario profile.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Mitigation and MITRE Mapping Center */}
              {scenario.mitreMapping && (
                <div className="bg-gradient-to-r from-red-950/40 to-slate-900 border border-red-500/20 rounded-xl p-5 flex flex-col md:flex-row gap-4 items-start">
                  <div className="bg-red-500/10 p-3 rounded-lg text-red-400">
                    <ShieldAlert className="w-6 h-6" />
                  </div>
                  <div>
                    <span className="text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded uppercase">
                      MITRE ATT&CK Correlation Match
                    </span>
                    <h3 className="text-base font-bold text-white mt-1.5">
                      [{scenario.mitreMapping.id}] {scenario.mitreMapping.name}
                    </h3>
                    <p className="text-xs text-slate-300 mt-1">
                      <strong>Tactic Domain:</strong> {scenario.mitreMapping.tactic}. Threat analysis reveals patterns matching standard threat techniques used by persistent threat actors during exfiltration/recon operations.
                    </p>
                    <div className="mt-4 flex gap-3">
                      <button 
                        onClick={() => setActiveTab('threats')}
                        className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 transition"
                      >
                        Examine Alerts & Guidance
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: PACKET DISSECTOR (THE ANALYZER) */}
          {activeTab === 'analyzer' && (
            <div className="space-y-4 h-[calc(100vh-140px)] flex flex-col">
              
              {/* Filter Row */}
              <div className="bg-slate-900 border border-slate-800 p-3 rounded-xl flex flex-col md:flex-row gap-3 items-center">
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono w-full md:w-auto">
                  <Filter className="w-4 h-4 text-cyan-400" />
                  <span>Wireshark Filter:</span>
                </div>
                
                <div className="relative flex-1 w-full">
                  <input 
                    type="text" 
                    value={wiresharkFilter}
                    onChange={(e) => setWiresharkFilter(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        setAppliedFilter(wiresharkFilter);
                      }
                    }}
                    placeholder='Enter filter syntax e.g. "dns", "ip.addr == 192.168.1.10", "tcp", "http" (Press Enter to apply)'
                    className="w-full bg-slate-950 border border-slate-700 text-cyan-400 font-mono text-xs rounded-lg pl-3 pr-20 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                  <div className="absolute right-1 top-1 flex gap-1">
                    {appliedFilter && (
                      <button 
                        onClick={handleClearFilter}
                        className="text-[10px] font-bold bg-slate-800 hover:bg-slate-700 text-slate-400 px-2 py-1 rounded"
                      >
                        Clear
                      </button>
                    )}
                    <button 
                      onClick={() => setAppliedFilter(wiresharkFilter)}
                      className="text-[10px] font-bold bg-cyan-500 hover:bg-cyan-600 text-slate-950 px-3 py-1 rounded"
                    >
                      Apply
                    </button>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 font-mono">
                  Showing {filteredPackets.length} of {scenario.packets.length} frames
                </div>
              </div>

              {/* Split Screen Layout (Packets vs Dissections) */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-0">
                
                {/* Upper/Left Panel: List of packets */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl lg:col-span-7 flex flex-col overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Simulated Capture Frame Queue</h3>
                    <span className="text-[10px] bg-slate-950 text-cyan-400 font-mono px-2 py-0.5 rounded border border-slate-800">
                      Promiscuous Mode
                    </span>
                  </div>
                  
                  <div className="flex-1 overflow-y-auto font-mono text-[11px]">
                    <table className="w-full text-left border-collapse">
                      <thead className="sticky top-0 bg-slate-950 text-slate-400 shadow">
                        <tr className="border-b border-slate-800">
                          <th className="py-2 px-3">No.</th>
                          <th className="py-2 px-2">Time</th>
                          <th className="py-2 px-2">Source</th>
                          <th className="py-2 px-2">Destination</th>
                          <th className="py-2 px-2">Protocol</th>
                          <th className="py-2 px-2 text-right">Len</th>
                          <th className="py-2 px-3">Info Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPackets.map((pkt) => {
                          const isSelected = selectedPacket?.id === pkt.id;
                          return (
                            <tr 
                              key={pkt.id}
                              onClick={() => setSelectedPacket(pkt)}
                              className={`cursor-pointer transition border-b border-slate-800/40 ${
                                isSelected 
                                  ? 'bg-cyan-500/20 text-white font-semibold' 
                                  : pkt.suspicious 
                                    ? 'bg-red-950/20 text-red-300 hover:bg-slate-800/30' 
                                    : 'text-slate-300 hover:bg-slate-800/30'
                              }`}
                            >
                              <td className="py-2 px-3 font-semibold">{pkt.id}</td>
                              <td className="py-2 px-2">{pkt.time.toFixed(4)}</td>
                              <td className="py-2 px-2 truncate max-w-[110px]" title={pkt.source}>{pkt.source}</td>
                              <td className="py-2 px-2 truncate max-w-[110px]" title={pkt.destination}>{pkt.destination}</td>
                              <td className="py-2 px-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  pkt.protocol === 'DNS' ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                                  pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                                  pkt.protocol === 'TCP' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                                  pkt.protocol === 'ARP' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' :
                                  'bg-slate-800 text-slate-300'
                                }`}>
                                  {pkt.protocol}
                                </span>
                              </td>
                              <td className="py-2 px-2 text-right">{pkt.length}</td>
                              <td className="py-2 px-3 truncate max-w-xs" title={pkt.info}>{pkt.info}</td>
                            </tr>
                          );
                        })}
                        {filteredPackets.length === 0 && (
                          <tr>
                            <td colSpan={7} className="py-12 text-center text-slate-500 text-xs">
                              No frames matched the active filter expression. Try "dns" or "tcp".
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Right Panel: Selected Packet Inspection */}
                <div className="lg:col-span-5 flex flex-col gap-4 min-h-0">
                  
                  {/* Protocol Tree */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex-1 flex flex-col overflow-hidden">
                    <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 border-b border-slate-800 pb-2">
                      Wireshark Protocol Tree Dissection
                    </h3>
                    
                    {selectedPacket ? (
                      <div className="flex-1 overflow-y-auto space-y-3 font-mono text-[11px] text-slate-300">
                        
                        {/* Layer 1 Frame */}
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                          <p className="text-cyan-400 font-semibold mb-1">▶ Frame {selectedPacket.id}: {selectedPacket.length} bytes on wire</p>
                          <ul className="pl-4 space-y-0.5 text-slate-400 text-[10.5px]">
                            <li>Capture Interface: eth0</li>
                            <li>Arrival Time: July 1, 2026, 10:14:20 UTC</li>
                            <li>Epoch Time: {selectedPacket.time.toFixed(6)} seconds</li>
                          </ul>
                        </div>

                        {/* Layer 2 Ethernet */}
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                          <p className="text-blue-400 font-semibold mb-1">▶ Ethernet II (MAC Addresses)</p>
                          <ul className="pl-4 space-y-0.5 text-slate-400 text-[10.5px]">
                            <li>Destination: {selectedPacket.destination.includes(':') ? selectedPacket.destination : '00:11:22:33:44:55'}</li>
                            <li>Source: {selectedPacket.source.includes(':') ? selectedPacket.source : '00:11:22:33:aa:bb'}</li>
                            <li>Type: IPv4 (0x0800)</li>
                          </ul>
                        </div>

                        {/* Layer 3 Internet Protocol */}
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                          <p className="text-green-400 font-semibold mb-1">▶ Internet Protocol Version 4 (IPv4)</p>
                          <ul className="pl-4 space-y-0.5 text-slate-400 text-[10.5px]">
                            <li>Source IP: {!selectedPacket.source.includes(':') ? selectedPacket.source : '192.168.1.105'}</li>
                            <li>Destination IP: {!selectedPacket.destination.includes(':') ? selectedPacket.destination : '192.168.1.1'}</li>
                            <li>Time to Live (TTL): 64</li>
                            <li>Header Checksum: 0x3af4 [Validation: Verified]</li>
                            <li>Protocol: {selectedPacket.protocol === 'UDP' || selectedPacket.protocol === 'DNS' ? 'UDP (17)' : 'TCP (6)'}</li>
                          </ul>
                        </div>

                        {/* Layer 4 / Payload details */}
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                          <p className="text-yellow-400 font-semibold mb-1">
                            ▶ {selectedPacket.protocol} Protocol Layer Dissection
                          </p>
                          <ul className="pl-4 space-y-0.5 text-slate-400 text-[10.5px]">
                            <li>Dissected Info: {selectedPacket.info}</li>
                            {selectedPacket.flags && <li>TCP Flags: {selectedPacket.flags}</li>}
                            {selectedPacket.payload && (
                              <li className="text-orange-400 font-semibold break-all">
                                Payload: {selectedPacket.payload.substring(0, 150)}
                                {selectedPacket.payload.length > 150 ? '...' : ''}
                              </li>
                            )}
                          </ul>
                        </div>

                      </div>
                    ) : (
                      <div className="flex-1 flex items-center justify-center text-slate-500 text-xs">
                        Select a packet from the queue to dissect its protocols
                      </div>
                    )}
                  </div>

                  {/* Hex & ASCII Dump view */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 h-44 flex flex-col overflow-hidden">
                    <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 border-b border-slate-800 pb-2">
                      Hexadecimal & Raw ASCII dump
                    </h3>
                    
                    {selectedPacket ? (
                      <div className="flex-1 overflow-y-auto bg-slate-950 p-2.5 rounded font-mono text-[10px] leading-relaxed text-cyan-500">
                        <div className="grid grid-cols-12 gap-1">
                          <div className="col-span-3 text-slate-500">0000  00 11 22 33 44 55</div>
                          <div className="col-span-6 text-cyan-600">00 11 22 33 aa bb 08 00 45 00</div>
                          <div className="col-span-3 text-slate-400">..&quot;3DU...E.</div>
                          
                          <div className="col-span-3 text-slate-500">0010  00 3c 1c 46 40 00</div>
                          <div className="col-span-6 text-cyan-600">40 06 b1 e6 c0 a8 01 69 c0 a8</div>
                          <div className="col-span-3 text-slate-400">.&lt;.F@.@.....i..</div>

                          <div className="col-span-3 text-slate-500">0020  01 0a c0 00 01 bb</div>
                          <div className="col-span-6 text-cyan-600">a0 12 b4 a3 00 00 00 00 50 02</div>
                          <div className="col-span-3 text-slate-400">........P.</div>

                          {selectedPacket.payload && (
                            <div className="col-span-12 mt-2 pt-2 border-t border-slate-800/80 text-orange-400 break-all text-[9.5px]">
                              # Plaintext: {selectedPacket.payload}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 flex items-center justify-center text-slate-500 text-xs">
                        Waiting for packet selection...
                      </div>
                    )}
                  </div>

                </div>

              </div>
            </div>
          )}

          {/* TAB 3: THREAT HUNTING DESK */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="text-red-500 w-5 h-5" />
                  SOC Threat Hunting Desk
                </h2>
                <p className="text-xs text-slate-400">Automated packet inspection alerts mapped to MITRE ATT&CK Framework guidelines.</p>
              </div>

              {/* Alert Items */}
              {scenario.alerts.length > 0 ? (
                <div className="space-y-4">
                  {scenario.alerts.map((alert, index) => (
                    <div 
                      key={alert.id}
                      className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl hover:border-slate-700 transition flex flex-col md:flex-row gap-5"
                    >
                      {/* Left: Severity Column */}
                      <div className="flex flex-row md:flex-col items-center gap-2 md:w-28 shrink-0">
                        <span className={`w-full text-center text-[10px] font-extrabold tracking-wider py-1 rounded border uppercase ${
                          alert.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                          alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                          'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                        }`}>
                          {alert.severity}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500 font-bold">{alert.id}</span>
                      </div>

                      {/* Right: Contents */}
                      <div className="flex-1 space-y-3">
                        <div>
                          <h3 className="text-base font-bold text-white">{alert.title}</h3>
                          <p className="text-xs text-slate-300 mt-1">{alert.description}</p>
                        </div>

                        {/* IPs involved */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950 p-3 rounded-lg border border-slate-800/60 text-xs font-mono">
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-bold">Threat Source IP</span>
                            <span className="text-cyan-400 font-semibold">{alert.source}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-bold">Target Destination</span>
                            <span className="text-white font-semibold">{alert.destination}</span>
                          </div>
                        </div>

                        {/* Match Criteria */}
                        <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-xs font-mono">
                          <span className="text-slate-500 block text-[10px] uppercase font-bold mb-1">Matching Wireshark Filter Rule</span>
                          <span className="text-emerald-400 font-medium break-all">{alert.matchingFilter}</span>
                        </div>

                        {/* Mitigation guidance */}
                        <div className="bg-emerald-950/20 border border-emerald-500/10 p-3.5 rounded-lg">
                          <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-1">Actionable Mitigation Policy</h4>
                          <p className="text-xs text-slate-300 leading-normal">{alert.mitigation}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 text-center space-y-3">
                  <div className="bg-green-500/10 text-green-400 w-12 h-12 rounded-full flex items-center justify-center mx-auto border border-green-500/20">
                    <CheckCircle2 className="w-6 h-6" />
                  </div>
                  <h3 className="text-base font-semibold text-white">No Threat Alerts Triggered</h3>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    The active scenario represents normal baseline corporate traffic. Packet inspections have validated that protocol flags, lengths, and DNS domains are compliant.
                  </p>
                </div>
              )}

              {/* Threat Hunting Walkthrough Guide */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3">Security Investigations & Methodologies</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {INVESTIGATIONS.map(inv => (
                    <div key={inv.id} className="bg-slate-950 border border-slate-800 p-4 rounded-lg flex flex-col justify-between">
                      <div>
                        <span className="text-[9px] font-mono font-bold bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-500/20">
                          {inv.mitreMapping}
                        </span>
                        <h4 className="text-xs font-bold text-white mt-2 mb-1">{inv.title}</h4>
                        <p className="text-[11px] text-slate-400 line-clamp-3 leading-normal">{inv.background}</p>
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-800/60">
                        <button 
                          onClick={() => {
                            setSelectedScenarioId(inv.id === 'dns_tunnel' ? 'dns_tunneling' : inv.id === 'port_scan' ? 'port_scan' : 'malware_beacon');
                            setActiveTab('dashboard');
                            triggerToast(`Loading investigational scenario for ${inv.title}`);
                          }}
                          className="text-[10px] text-cyan-400 font-bold hover:text-cyan-300 flex items-center gap-1"
                        >
                          Launch Active Investigation
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

          {/* TAB 4: VIRTUAL LAB PLAN */}
          {activeTab === 'lab' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Network className="text-cyan-400 w-5 h-5" />
                  Virtual Forensic Lab Infrastructure
                </h2>
                <p className="text-xs text-slate-400">Blueprint, network layout, and IP mapping lists to build your own local packet training lab.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Lab Diagram */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-7 flex flex-col">
                  <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-3">Subnet Topology Architecture</h3>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-[11px] leading-relaxed text-cyan-500 flex-1 whitespace-pre">
                    {VIRTUAL_LAB_GUIDE.labTopology}
                  </div>
                </div>

                {/* Subnet details */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-5 space-y-4">
                  <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Subnet Configuration Details</h3>
                  <div className="space-y-3 text-xs">
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                      <span className="text-slate-500 font-mono text-[10px] block font-bold uppercase">Subnet Range</span>
                      <span className="text-white font-mono font-semibold">192.168.1.0 / 24</span>
                    </div>
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                      <span className="text-slate-500 font-mono text-[10px] block font-bold uppercase">Assigned Router / Gateway</span>
                      <span className="text-white font-mono font-semibold">192.168.1.1</span>
                    </div>
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                      <span className="text-slate-500 font-mono text-[10px] block font-bold uppercase">Sniffing Interface Style</span>
                      <span className="text-white font-mono font-semibold">SPAN / Mirror Port (Promiscuous Mode)</span>
                    </div>
                  </div>
                </div>

              </div>

              {/* IP Table */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-1">Corporate Subnet IP Address Allocation</h3>
                <p className="text-xs text-slate-400 mb-4">Complete IP allocation directory for configuring local virtual machines (VirtualBox/VMware/Docker).</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-mono">
                        <th className="py-2 px-3">Hostname</th>
                        <th className="py-2 px-3">IP Address</th>
                        <th className="py-2 px-3">OS / Platform</th>
                        <th className="py-2 px-3">Allocation Class</th>
                      </tr>
                    </thead>
                    <tbody>
                      {VIRTUAL_LAB_GUIDE.ipAddressPlan.map((node, i) => (
                        <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/20 font-mono">
                          <td className="py-3 px-3 text-white font-bold">{node.hostname}</td>
                          <td className="py-3 px-3 text-cyan-400">{node.ip}</td>
                          <td className="py-3 px-3 text-slate-300">{node.OS}</td>
                          <td className="py-3 px-3 text-slate-400">{node.type}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: FILTERS REFERENCE LIBRARY */}
          {activeTab === 'filters' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <BookOpen className="text-cyan-400 w-5 h-5" />
                  Wireshark & TShark Filter Reference Library
                </h2>
                <p className="text-xs text-slate-400">Searchable catalog of essential display filters for protocol dissecting, performance audits, and cyber investigations.</p>
              </div>

              {/* Filters list */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {FILTERS_LIBRARY.map((item) => (
                  <div 
                    key={item.id}
                    className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-lg hover:border-slate-700 transition flex flex-col justify-between"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded">
                          {item.category}
                        </span>
                      </div>
                      
                      <div>
                        <h4 className="text-xs font-semibold text-slate-200">Filter String</h4>
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] font-mono text-emerald-400 mt-1 select-all select-text break-all">
                          {item.filter}
                        </div>
                      </div>

                      <p className="text-xs text-slate-400 leading-normal">{item.description}</p>
                    </div>

                    <div className="mt-5 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                      <button 
                        onClick={() => {
                          setWiresharkFilter(item.filter);
                          setAppliedFilter(item.filter);
                          setActiveTab('analyzer');
                          triggerToast(`Injected filter into dissector: ${item.filter}`);
                        }}
                        className="text-[11px] text-cyan-400 font-bold hover:text-cyan-300 flex items-center gap-1"
                      >
                        Try in Packet Dissector
                        <ChevronRight className="w-4 h-4" />
                      </button>

                      <button 
                        onClick={() => {
                          navigator.clipboard.writeText(item.filter);
                          triggerToast("Filter copied!");
                        }}
                        className="text-slate-500 hover:text-white p-1 rounded"
                        title="Copy filter to clipboard"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 6: AUTOMATION SCRIPT CENTRE */}
          {activeTab === 'scripts' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileCode className="text-cyan-400 w-5 h-5" />
                  Lab Automation Repository
                </h2>
                <p className="text-xs text-slate-400">Complete, runnable Python network dissector modules and Shell automation capture scripts stored inside your lab folder.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Script Tree / List */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 lg:col-span-4 space-y-2">
                  <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 px-2">Script Directory</h3>
                  <div className="space-y-1.5">
                    {LAB_SCRIPTS.map((script, index) => (
                      <button
                        key={index}
                        onClick={() => setSelectedScriptIndex(index)}
                        className={`w-full text-left p-2.5 rounded-lg text-xs font-medium transition flex items-center gap-2.5 ${
                          selectedScriptIndex === index 
                            ? 'bg-gradient-to-r from-cyan-950/40 to-slate-800 border border-cyan-500/20 text-cyan-400' 
                            : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                        }`}
                      >
                        <FileCode className="w-4 h-4 shrink-0" />
                        <div className="truncate">
                          <span className="block font-semibold font-mono text-[11px]">{script.filename}</span>
                          <span className="text-[10px] text-slate-500 font-normal truncate block">{script.purpose}</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Code Viewer */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl lg:col-span-8 flex flex-col overflow-hidden">
                  <div className="px-5 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
                    <div>
                      <h3 className="text-xs font-semibold text-white font-mono">{activeScript.path}</h3>
                      <p className="text-[10px] text-slate-400 mt-0.5">{activeScript.purpose}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono bg-slate-950 text-cyan-400 border border-slate-800 px-2.5 py-0.5 rounded font-bold uppercase">
                        {activeScript.language}
                      </span>
                      <button
                        onClick={handleCopyScript}
                        className="p-1.5 bg-slate-950 hover:bg-slate-800 rounded border border-slate-800 text-slate-400 hover:text-white transition flex items-center gap-1 text-[11px] font-semibold"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        {copiedScript ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-5 overflow-auto font-mono text-xs leading-relaxed text-slate-300 max-h-[500px]">
                    <pre className="whitespace-pre">{activeScript.code}</pre>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* TAB 7: REPORT BUILDER */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileSpreadsheet className="text-cyan-400 w-5 h-5" />
                  Forensic Report Architect
                </h2>
                <p className="text-xs text-slate-400">Instantly generate structured incident, threat intelligence, and performance audits reports mapping your network evidence.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Inputs Pane */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-5 space-y-4">
                  <div className="flex gap-2">
                    {REPORT_TEMPLATES.map(t => (
                      <button
                        key={t.id}
                        onClick={() => {
                          setSelectedTemplateId(t.id);
                          setReportFormData({});
                          setGeneratedReport('');
                        }}
                        className={`flex-1 py-2 px-3 rounded-lg text-xs font-bold border transition ${
                          selectedTemplateId === t.id 
                            ? 'bg-cyan-500 text-slate-950 border-cyan-400' 
                            : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {t.name}
                      </button>
                    ))}
                  </div>

                  <form onSubmit={handleGenerateReport} className="space-y-4">
                    {activeTemplate.structure.map((field, i) => (
                      <div key={i} className="space-y-1">
                        <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                          {field.sectionName}
                        </label>
                        {field.type === 'select' ? (
                          <select
                            value={reportFormData[field.sectionName] || ''}
                            onChange={(e) => setReportFormData({...reportFormData, [field.sectionName]: e.target.value})}
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-white focus:ring-1 focus:ring-cyan-500 focus:outline-none cursor-pointer"
                            required
                          >
                            <option value="">{field.placeholder}</option>
                            {field.options?.map((opt, oIdx) => (
                              <option key={oIdx} value={opt}>{opt}</option>
                            ))}
                          </select>
                        ) : field.type === 'textarea' ? (
                          <textarea
                            value={reportFormData[field.sectionName] || ''}
                            onChange={(e) => setReportFormData({...reportFormData, [field.sectionName]: e.target.value})}
                            placeholder={field.placeholder}
                            rows={3}
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-white font-mono focus:ring-1 focus:ring-cyan-500 focus:outline-none"
                            required
                          />
                        ) : (
                          <input
                            type="text"
                            value={reportFormData[field.sectionName] || ''}
                            onChange={(e) => setReportFormData({...reportFormData, [field.sectionName]: e.target.value})}
                            placeholder={field.placeholder}
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-white focus:ring-1 focus:ring-cyan-500 focus:outline-none"
                            required
                          />
                        )}
                      </div>
                    ))}

                    <button
                      type="submit"
                      className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-slate-950 font-extrabold text-xs rounded-xl shadow-lg hover:shadow-cyan-500/20 transition duration-300"
                    >
                      Compile Scientific Assessment
                    </button>
                  </form>
                </div>

                {/* Compiled output */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl lg:col-span-7 flex flex-col overflow-hidden min-h-[450px]">
                  <div className="px-5 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Forensic Report Output (.MD)</h3>
                    {generatedReport && (
                      <button
                        onClick={handleCopyReport}
                        className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 rounded border border-slate-800 transition text-[11px] font-bold flex items-center gap-1"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        Copy Report
                      </button>
                    )}
                  </div>

                  <div className="bg-slate-950 p-5 overflow-y-auto flex-1 font-mono text-xs text-slate-300">
                    {generatedReport ? (
                      <pre className="whitespace-pre-wrap">{generatedReport}</pre>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 py-12">
                        <FileSpreadsheet className="w-12 h-12 mb-3 text-slate-700" />
                        <p className="text-xs font-medium">No report generated yet.</p>
                        <p className="text-[11px] text-slate-600 max-w-xs mt-1">Complete the fields on the left and click &quot;Compile Scientific Assessment&quot; to review the formal output.</p>
                      </div>
                    )}
                  </div>
                </div>

              </div>
            </div>
          )}

        </main>
      </div>

      {/* Footer System Status details */}
      <footer className="border-t border-slate-800 bg-slate-950 px-6 py-3 flex flex-col sm:flex-row items-center justify-between gap-2 text-[10px] font-mono text-slate-500">
        <div className="flex items-center gap-4">
          <span>Active Interface: <span className="text-slate-400">eth0 (PROMISC)</span></span>
          <span>PCAP Source: <span className="text-slate-400">{scenario.name}</span></span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
          <span>SYSTEM DISSECTOR SERVICE: <span className="text-cyan-400 font-bold">ONLINE</span></span>
        </div>
      </footer>

    </div>
  );
}

// Realistic IDS/IPS Mock Data - Simulating Snort/Suricata logs

export interface AlertLog {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  signature: string;
  signatureId: number;
  category: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  action: 'Allowed' | 'Blocked';
  is_pcap?: number;
}

export interface NetworkStats {
  label: string;
  value: number;
  unit: string;
  change: number;
  status: 'normal' | 'warning' | 'critical';
}

export interface TrafficData {
  time: string;
  normal: number;
  suspicious: number;
  malicious: number;
}

export interface ThroughputData {
  time: string;
  value: number;
  anomaly: boolean;
}

export interface TopAttacker {
  ip: string;
  country: string;
  attacks: number;
  lastSeen: string;
  type: string;
}

export interface PCAPResult {
  totalPackets: number;
  protocols: { name: string; count: number; percentage: number }[];
  topSourceIPs: { ip: string; packets: number }[];
  topDestIPs: { ip: string; packets: number }[];
  threats: { name: string; severity: string; count: number }[];
  suspiciousPackets: number;
}

// Generate realistic timestamps
const generateTimestamp = (hoursAgo: number, minutesAgo: number = 0): string => {
  const date = new Date();
  date.setHours(date.getHours() - hoursAgo);
  date.setMinutes(date.getMinutes() - minutesAgo);
  return date.toISOString().replace('T', ' ').substring(0, 19);
};

// Realistic alert logs
export const alertLogs: AlertLog[] = [
  {
    id: 'ALT-001',
    timestamp: generateTimestamp(0, 2),
    severity: 'CRITICAL',
    signature: 'ET POLICY Suspicious Inbound SSH Connection',
    signatureId: 2010935,
    category: 'Attempted Admin Access',
    srcIp: '185.224.128.45',
    srcPort: 54321,
    dstIp: '10.0.0.5',
    dstPort: 22,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-002',
    timestamp: generateTimestamp(0, 5),
    severity: 'HIGH',
    signature: 'ET SCAN Potential SSH Brute Force Attack',
    signatureId: 2001339,
    category: 'Brute Force Attack',
    srcIp: '45.33.32.156',
    srcPort: 42891,
    dstIp: '10.0.0.15',
    dstPort: 22,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-003',
    timestamp: generateTimestamp(0, 8),
    severity: 'HIGH',
    signature: 'ET MALWARE WannaCry Ransomware Activity Detected',
    signatureId: 2024299,
    category: 'Malware Activity',
    srcIp: '192.168.1.105',
    srcPort: 49152,
    dstIp: '104.16.132.229',
    dstPort: 445,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-004',
    timestamp: generateTimestamp(0, 12),
    severity: 'MEDIUM',
    signature: 'ET SCAN NMAP SYN Scan Detection',
    signatureId: 2010065,
    category: 'Reconnaissance',
    srcIp: '91.121.87.18',
    srcPort: 34567,
    dstIp: '10.0.0.0/24',
    dstPort: 1,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-005',
    timestamp: generateTimestamp(0, 15),
    severity: 'CRITICAL',
    signature: 'ET EXPLOIT Possible Log4j Exploitation Attempt',
    signatureId: 2034905,
    category: 'Remote Code Execution',
    srcIp: '103.75.201.2',
    srcPort: 51234,
    dstIp: '10.0.0.25',
    dstPort: 8080,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-006',
    timestamp: generateTimestamp(0, 18),
    severity: 'LOW',
    signature: 'ET INFO SSH Server Detected',
    signatureId: 2001340,
    category: 'Information Gathering',
    srcIp: '10.0.0.50',
    srcPort: 22,
    dstIp: '192.168.2.100',
    dstPort: 52341,
    protocol: 'TCP',
    action: 'Allowed'
  },
  {
    id: 'ALT-007',
    timestamp: generateTimestamp(0, 22),
    severity: 'HIGH',
    signature: 'ET TROJAN Cobalt Strike Beacon Activity',
    signatureId: 2023401,
    category: 'Command & Control',
    srcIp: '10.0.0.88',
    srcPort: 49321,
    dstIp: '185.56.80.65',
    dstPort: 443,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-008',
    timestamp: generateTimestamp(0, 25),
    severity: 'MEDIUM',
    signature: 'ET SCAN Suspicious DNS Query Volume',
    signatureId: 2012971,
    category: 'DNS Tunneling',
    srcIp: '10.0.0.42',
    srcPort: 53,
    dstIp: '8.8.8.8',
    dstPort: 53,
    protocol: 'UDP',
    action: 'Allowed'
  },
  {
    id: 'ALT-009',
    timestamp: generateTimestamp(0, 30),
    severity: 'CRITICAL',
    signature: 'ET EXPLOIT MS17-010 EternalBlue Exploitation',
    signatureId: 2024218,
    category: 'Remote Code Execution',
    srcIp: '23.129.64.210',
    srcPort: 41523,
    dstIp: '10.0.0.12',
    dstPort: 445,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-010',
    timestamp: generateTimestamp(0, 35),
    severity: 'HIGH',
    signature: 'ET WEB_SERVER SQL Injection Attempt',
    signatureId: 2012980,
    category: 'Web Application Attack',
    srcIp: '195.154.167.33',
    srcPort: 58923,
    dstIp: '10.0.0.30',
    dstPort: 443,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-011',
    timestamp: generateTimestamp(0, 42),
    severity: 'LOW',
    signature: 'ET INFO HTTP Server Response Header',
    signatureId: 2013028,
    category: 'Information Gathering',
    srcIp: '10.0.0.30',
    srcPort: 443,
    dstIp: '192.168.1.50',
    dstPort: 52891,
    protocol: 'TCP',
    action: 'Allowed'
  },
  {
    id: 'ALT-012',
    timestamp: generateTimestamp(0, 48),
    severity: 'MEDIUM',
    signature: 'ET POLICY TLS Certificate with Suspicious Attributes',
    signatureId: 2014651,
    category: 'Policy Violation',
    srcIp: '10.0.0.65',
    srcPort: 49821,
    dstIp: '45.77.65.211',
    dstPort: 443,
    protocol: 'TCP',
    action: 'Allowed'
  },
  {
    id: 'ALT-013',
    timestamp: generateTimestamp(0, 55),
    severity: 'HIGH',
    signature: 'ET BOTNET Mirai Botnet C2 Communication',
    signatureId: 2024862,
    category: 'Botnet Activity',
    srcIp: '10.0.0.110',
    srcPort: 23,
    dstIp: '198.98.56.126',
    dstPort: 23,
    protocol: 'TCP',
    action: 'Blocked'
  },
  {
    id: 'ALT-014',
    timestamp: generateTimestamp(1, 5),
    severity: 'MEDIUM',
    signature: 'ET SCAN Unusual ICMP Activity',
    signatureId: 2001341,
    category: 'Reconnaissance',
    srcIp: '77.247.181.163',
    srcPort: 0,
    dstIp: '10.0.0.0/24',
    dstPort: 0,
    protocol: 'ICMP',
    action: 'Blocked'
  },
  {
    id: 'ALT-015',
    timestamp: generateTimestamp(1, 15),
    severity: 'CRITICAL',
    signature: 'ET EXPLOIT Apache Struts Remote Code Execution',
    signatureId: 2025702,
    category: 'Remote Code Execution',
    srcIp: '141.98.80.26',
    srcPort: 54123,
    dstIp: '10.0.0.35',
    dstPort: 8443,
    protocol: 'TCP',
    action: 'Blocked'
  }
];

// Network statistics
export const networkStats: NetworkStats[] = [
  { label: 'Scan Coverage', value: 98.7, unit: '%', change: 0.3, status: 'normal' },
  { label: 'Threat Level', value: 67, unit: '%', change: 12, status: 'warning' },
  { label: 'Packet Loss', value: 0.02, unit: '%', change: -0.01, status: 'normal' },
  { label: 'Response Time', value: 12, unit: 'ms', change: -3, status: 'normal' }
];

// Traffic data for charts (last 24 hours)
export const trafficData: TrafficData[] = [
  { time: '00:00', normal: 4500, suspicious: 120, malicious: 23 },
  { time: '02:00', normal: 3200, suspicious: 85, malicious: 12 },
  { time: '04:00', normal: 2800, suspicious: 95, malicious: 18 },
  { time: '06:00', normal: 3500, suspicious: 110, malicious: 15 },
  { time: '08:00', normal: 5200, suspicious: 180, malicious: 28 },
  { time: '10:00', normal: 6800, suspicious: 220, malicious: 35 },
  { time: '12:00', normal: 7200, suspicious: 195, malicious: 42 },
  { time: '14:00', normal: 7500, suspicious: 240, malicious: 48 },
  { time: '16:00', normal: 6900, suspicious: 210, malicious: 38 },
  { time: '18:00', normal: 6200, suspicious: 185, malicious: 32 },
  { time: '20:00', normal: 5800, suspicious: 165, malicious: 28 },
  { time: '22:00', normal: 4900, suspicious: 140, malicious: 22 }
];

// Throughput data
export const throughputData: ThroughputData[] = [
  { time: '00:00', value: 850, anomaly: false },
  { time: '01:00', value: 820, anomaly: false },
  { time: '02:00', value: 780, anomaly: false },
  { time: '03:00', value: 750, anomaly: false },
  { time: '04:00', value: 720, anomaly: false },
  { time: '05:00', value: 710, anomaly: false },
  { time: '06:00', value: 780, anomaly: false },
  { time: '07:00', value: 890, anomaly: false },
  { time: '08:00', value: 1100, anomaly: false },
  { time: '09:00', value: 1250, anomaly: false },
  { time: '10:00', value: 1380, anomaly: false },
  { time: '11:00', value: 1450, anomaly: false },
  { time: '12:00', value: 1520, anomaly: false },
  { time: '13:00', value: 1480, anomaly: false },
  { time: '14:00', value: 1650, anomaly: true },
  { time: '15:00', value: 1420, anomaly: false },
  { time: '16:00', value: 1380, anomaly: false },
  { time: '17:00', value: 1290, anomaly: false },
  { time: '18:00', value: 1150, anomaly: false },
  { time: '19:00', value: 1080, anomaly: false },
  { time: '20:00', value: 980, anomaly: false },
  { time: '21:00', value: 920, anomaly: false },
  { time: '22:00', value: 880, anomaly: false },
  { time: '23:00', value: 860, anomaly: false }
];

// Top attackers
export const topAttackers: TopAttacker[] = [
  { ip: '185.224.128.45', country: 'Romania', attacks: 1247, lastSeen: generateTimestamp(0, 2), type: 'SSH Brute Force' },
  { ip: '103.75.201.2', country: 'Hong Kong', attacks: 892, lastSeen: generateTimestamp(0, 15), type: 'RCE Exploits' },
  { ip: '45.33.32.156', country: 'USA', attacks: 756, lastSeen: generateTimestamp(0, 5), type: 'Port Scanning' },
  { ip: '23.129.64.210', country: 'Russia', attacks: 634, lastSeen: generateTimestamp(0, 30), type: 'SMB Exploits' },
  { ip: '141.98.80.26', country: 'Bulgaria', attacks: 521, lastSeen: generateTimestamp(1, 15), type: 'Web Exploits' },
  { ip: '195.154.167.33', country: 'France', attacks: 489, lastSeen: generateTimestamp(0, 35), type: 'SQL Injection' },
  { ip: '77.247.181.163', country: 'Netherlands', attacks: 412, lastSeen: generateTimestamp(1, 5), type: 'ICMP Flood' },
  { ip: '91.121.87.18', country: 'France', attacks: 378, lastSeen: generateTimestamp(0, 12), type: 'Network Scan' }
];

// PCAP analysis mock result
export const pcapAnalysisResult: PCAPResult = {
  totalPackets: 156789,
  protocols: [
    { name: 'TCP', count: 98456, percentage: 62.8 },
    { name: 'UDP', count: 45231, percentage: 28.9 },
    { name: 'ICMP', count: 8762, percentage: 5.6 },
    { name: 'Other', count: 4340, percentage: 2.7 }
  ],
  topSourceIPs: [
    { ip: '192.168.1.105', packets: 12450 },
    { ip: '10.0.0.50', packets: 9876 },
    { ip: '185.224.128.45', packets: 8234 },
    { ip: '103.75.201.2', packets: 6521 },
    { ip: '10.0.0.88', packets: 5432 }
  ],
  topDestIPs: [
    { ip: '10.0.0.5', packets: 15678 },
    { ip: '10.0.0.30', packets: 11234 },
    { ip: '10.0.0.15', packets: 8765 },
    { ip: '8.8.8.8', packets: 7654 },
    { ip: '10.0.0.42', packets: 6543 }
  ],
  threats: [
    { name: 'SSH Brute Force Attempt', severity: 'HIGH', count: 47 },
    { name: 'DNS Tunneling Activity', severity: 'MEDIUM', count: 23 },
    { name: 'Port Scan Detected', severity: 'MEDIUM', count: 18 },
    { name: 'Malware C2 Communication', severity: 'CRITICAL', count: 8 },
    { name: 'SQL Injection Attempt', severity: 'HIGH', count: 12 }
  ],
  suspiciousPackets: 2847
};

// System status
export const systemStatus = {
  gatewayStatus: 'stable',
  loadStatus: 'elevated',
  uptime: '47 days, 12 hours',
  signatureVersion: '2987.4',
  lastUpdate: generateTimestamp(0, 35),
  cpuUsage: 42,
  memoryUsage: 68,
  diskUsage: 35,
  idsStatus: 'active',
  ipsStatus: 'active'
};

// Alert counts by severity
export const alertCounts = {
  critical: 4,
  high: 5,
  medium: 4,
  low: 2,
  total: 15
};

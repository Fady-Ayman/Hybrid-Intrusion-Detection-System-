import { useState, useEffect } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line
} from 'recharts';
import {
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  TrendingUp,
  TrendingDown,
  Ban,
  Eye,
  Target
} from 'lucide-react';
import { fetchDashboardStats, fetchSystemInfo } from '../data/api';

export default function Dashboard() {
  const [currentTime, setCurrentTime] = useState(new Date());

  const [liveAlerts, setLiveAlerts] = useState<any[]>([]);
  const [networkStats, setNetworkStats] = useState<any[]>([]);
  const [trafficData, setTrafficData] = useState<any[]>([]);
  const [throughputData, setThroughputData] = useState<any[]>([]);
  const [topAttackers, setTopAttackers] = useState<any[]>([]);
  const [alertCounts, setAlertCounts] = useState<any>({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [systemStatus, setSystemStatus] = useState<any>({ gatewayStatus: 'stable', loadStatus: 'normal' });

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      const stats = await fetchDashboardStats();
      if (stats) {
        setLiveAlerts(stats.liveAlerts || []);
        setNetworkStats((stats.networkStats || []).filter((s: any) => !s.label.toLowerCase().includes('response time')));
        setTrafficData(stats.trafficData || []);
        setThroughputData(stats.throughputData || []);
        setTopAttackers(stats.topAttackers || []);
        setAlertCounts(stats.alertCounts || { critical: 0, high: 0, medium: 0, low: 0, total: 0 });
      }
      const sys = await fetchSystemInfo();
      if (sys && sys.system) {
        setSystemStatus({
          gatewayStatus: sys.capture.running ? 'stable' : 'warning',
          loadStatus: sys.system.cpu_percent > 80 ? 'elevated' : 'normal'
        });
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/20 border-red-500/50';
      case 'HIGH': return 'text-orange-500 bg-orange-500/20 border-orange-500/50';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/20 border-yellow-500/50';
      case 'LOW': return 'text-green-500 bg-green-500/20 border-green-500/50';
      default: return 'text-gray-500 bg-gray-500/20 border-gray-500/50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'normal': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'critical': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getSourceBadge = (source: string) => {
    switch (source?.toUpperCase()) {
      case 'ML':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border text-indigo-400 bg-indigo-500/20 border-indigo-500/50">
            ML
          </span>
        );
      case 'SNORT':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border text-rose-400 bg-rose-500/20 border-rose-500/50">
            Snort
          </span>
        );
      case 'HYBRID':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border text-amber-400 bg-amber-500/20 border-amber-500/50">
            Hybrid
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border text-indigo-400 bg-indigo-500/20 border-indigo-500/50">
            ML
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="text-cyan-400" />
            Cyberhawk IDS
          </h1>
          <p className="text-gray-400 mt-1">Security Operations Center Dashboard</p>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-slate-800/50 border border-cyan-500/20">
            <div className={`w-3 h-3 rounded-full ${systemStatus.gatewayStatus === 'stable' ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-gray-300">Gateway: <span className={systemStatus.gatewayStatus === 'stable' ? 'text-green-400' : 'text-red-400'}>{systemStatus.gatewayStatus.toUpperCase()}</span></span>
          </div>
          <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-slate-800/50 border border-yellow-500/20">
            <div className={`w-3 h-3 rounded-full ${systemStatus.loadStatus === 'elevated' ? 'bg-yellow-500' : 'bg-green-500'} animate-pulse`} />
            <span className="text-gray-300">Load: <span className={systemStatus.loadStatus === 'elevated' ? 'text-yellow-400' : 'text-green-400'}>{systemStatus.loadStatus.toUpperCase()}</span></span>
          </div>
          <div className="text-right">
            <p className="text-2xl font-mono text-cyan-400">{currentTime.toLocaleTimeString()}</p>
            <p className="text-sm text-gray-500">{currentTime.toLocaleDateString()}</p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 gap-6 mb-8">
        {networkStats.map((stat, index) => (
          <div
            key={index}
            className="relative overflow-hidden rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6 hover:border-cyan-500/50 transition-all duration-300 group"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-400 text-sm font-medium">{stat.label}</span>
                <div className={`flex items-center gap-1 ${stat.change >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                  {stat.change >= 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                  <span className="text-xs">{Math.abs(stat.change)}%</span>
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className={`text-4xl font-bold ${getStatusColor(stat.status)}`}>
                  {stat.value}
                </span>
                <span className="text-gray-500 text-sm">{stat.unit}</span>
              </div>
              <div className="mt-4 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${stat.status === 'normal' ? 'bg-green-500' : stat.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                  style={{ width: `${Math.min(stat.value, 100)}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Alert Summary */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="rounded-xl bg-red-500/10 border border-red-500/30 p-4 flex items-center gap-4">
          <AlertTriangle className="text-red-500" size={32} />
          <div>
            <p className="text-3xl font-bold text-red-500">{alertCounts.critical}</p>
            <p className="text-sm text-gray-400">Critical Alerts</p>
          </div>
        </div>
        <div className="rounded-xl bg-orange-500/10 border border-orange-500/30 p-4 flex items-center gap-4">
          <AlertTriangle className="text-orange-500" size={32} />
          <div>
            <p className="text-3xl font-bold text-orange-500">{alertCounts.high}</p>
            <p className="text-sm text-gray-400">High Alerts</p>
          </div>
        </div>
        <div className="rounded-xl bg-yellow-500/10 border border-yellow-500/30 p-4 flex items-center gap-4">
          <Activity className="text-yellow-500" size={32} />
          <div>
            <p className="text-3xl font-bold text-yellow-500">{alertCounts.medium}</p>
            <p className="text-sm text-gray-400">Medium Alerts</p>
          </div>
        </div>
        <div className="rounded-xl bg-green-500/10 border border-green-500/30 p-4 flex items-center gap-4">
          <Shield className="text-green-500" size={32} />
          <div>
            <p className="text-3xl font-bold text-green-500">{alertCounts.low}</p>
            <p className="text-sm text-gray-400">Low Alerts</p>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-6 mb-8">
        {/* Network Traffic Chart */}
        <div className="col-span-2 rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="text-cyan-400" size={20} />
            Network Traffic (24h)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="normalGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="suspiciousGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="maliciousGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px'
                }}
              />
              <Area type="monotone" dataKey="normal" stackId="1" stroke="#22c55e" fill="url(#normalGradient)" name="Normal" />
              <Area type="monotone" dataKey="suspicious" stackId="1" stroke="#eab308" fill="url(#suspiciousGradient)" name="Suspicious" />
              <Area type="monotone" dataKey="malicious" stackId="1" stroke="#ef4444" fill="url(#maliciousGradient)" name="Malicious" />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-center gap-6 mt-4">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-green-500" />
              <span className="text-sm text-gray-400">Normal</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-yellow-500" />
              <span className="text-sm text-gray-400">Suspicious</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <span className="text-sm text-gray-400">Malicious</span>
            </div>
          </div>
        </div>

        {/* Throughput Graph */}
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Clock className="text-cyan-400" size={20} />
            Throughput (Mbps)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={throughputData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px'
                }}
              />
              <Line
                type="monotone"
                dataKey="value"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={(props) => {
                  const { cx, cy, payload } = props;
                  if (payload.anomaly) {
                    return (
                      <circle cx={cx} cy={cy} r={6} fill="#ef4444" stroke="#ef4444" strokeWidth={2} className="animate-pulse" />
                    );
                  }
                  return <circle cx={cx} cy={cy} r={3} fill="#06b6d4" />;
                }}
              />
            </LineChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-center gap-4 mt-4">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-500" />
              <span className="text-sm text-gray-400">Normal</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
              <span className="text-sm text-gray-400">Anomaly</span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-3 gap-6">
        {/* Live Alerts Panel */}
        <div className="col-span-2 rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="text-red-400" size={20} />
              Live Alerts
            </h3>
            <span className="px-3 py-1 rounded-full bg-red-500/20 text-red-400 text-sm font-medium animate-pulse">
              {liveAlerts.length} Active
            </span>
          </div>
          <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
            {liveAlerts.map((alert) => (
              <div
                key={alert.id}
                className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-4 hover:border-cyan-500/30 transition-all duration-200"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold border ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    {getSourceBadge(alert.detection_source || 'ML')}
                    <span className="text-gray-400 text-sm font-mono">{alert.timestamp}</span>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${alert.action === 'Blocked' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                    }`}>
                    {alert.action}
                  </span>
                </div>
                <p className="text-white font-medium mb-2">{alert.signature}</p>
                <div className="flex items-center gap-4 text-sm text-gray-400 mb-3">
                  <span>Src: <span className="text-cyan-400">{alert.srcIp}:{alert.srcPort}</span></span>
                  <span>→</span>
                  <span>Dst: <span className="text-orange-400">{alert.dstIp}:{alert.dstPort}</span></span>
                  <span className="px-2 py-0.5 rounded bg-slate-700">{alert.protocol}</span>
                </div>
                <div className="flex items-center gap-3">
                  <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors text-sm">
                    <Eye size={14} />
                    Investigate
                  </button>
                  <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors text-sm">
                    <Ban size={14} />
                    Block IP
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Attackers */}
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Target className="text-red-400" size={20} />
            Top Attackers
          </h3>
          <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
            {topAttackers.slice(0, 6).map((attacker) => (
              <div
                key={attacker.ip}
                className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-3 hover:border-red-500/30 transition-all duration-200"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-mono text-sm">{attacker.ip}</span>
                  <span className="text-xs text-gray-500">{attacker.country}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-red-400">{attacker.type}</span>
                  <span className="text-xs text-gray-400">{attacker.attacks} attacks</span>
                </div>
                <div className="mt-2 h-1 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full"
                    style={{ width: `${(attacker.attacks / 1247) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Custom Scrollbar Styles */}
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1e293b;
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #334155;
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #475569;
        }
      `}</style>
    </div>
  );
}

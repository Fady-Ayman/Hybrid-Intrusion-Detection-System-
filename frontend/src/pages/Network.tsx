import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../data/api';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import {
  Network as NetworkIcon,
  Activity,
  Globe,
  Server,
  Wifi,
  Download,
  Upload,
  RefreshCw
} from 'lucide-react';




export default function Network() {
  const [data, setData] = useState({
    stats: { inboundMbps: 0, outboundMbps: 0, activeConnections: 0, blockedIps: 0 },
    connectionData: [],
    protocolData: [],
    activeConnections: []
  });

  const fetchData = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/network/dashboard`, { credentials: 'include' });
      if (!res.ok) throw new Error('Network response was not ok');
      const data = await res.json();
      setData(data);
    } catch (err) {
      console.error('Failed to fetch network dashboard data', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <NetworkIcon className="text-cyan-400" />
            Network Monitor
          </h1>
          <p className="text-gray-400 mt-1">Real-time network traffic analysis</p>
        </div>
        <button 
          onClick={fetchData}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors"
        >
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      {/* Network Stats */}
      <div className="grid grid-cols-4 gap-6 mb-8">
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 rounded-lg bg-green-500/20">
              <Download className="text-green-400" size={24} />
            </div>
            <span className="text-gray-400">Inbound</span>
          </div>
          <p className="text-3xl font-bold text-white">{data.stats.inboundMbps} <span className="text-lg text-gray-400">MB/s</span></p>
        </div>
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 rounded-lg bg-blue-500/20">
              <Upload className="text-blue-400" size={24} />
            </div>
            <span className="text-gray-400">Outbound</span>
          </div>
          <p className="text-3xl font-bold text-white">{data.stats.outboundMbps} <span className="text-lg text-gray-400">MB/s</span></p>
        </div>
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 rounded-lg bg-cyan-500/20">
              <Wifi className="text-cyan-400" size={24} />
            </div>
            <span className="text-gray-400">Active Connections</span>
          </div>
          <p className="text-3xl font-bold text-white">{data.stats.activeConnections}</p>
        </div>
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 rounded-lg bg-red-500/20">
              <Globe className="text-red-400" size={24} />
            </div>
            <span className="text-gray-400">Blocked IPs</span>
          </div>
          <p className="text-3xl font-bold text-white">{data.stats.blockedIps}</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-6 mb-8">
        {/* Connection Chart */}
        <div className="col-span-2 rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="text-cyan-400" size={20} />
            Connection Traffic (24h)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={data.connectionData}>
              <defs>
                <linearGradient id="inboundGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="outboundGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
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
              <Area type="monotone" dataKey="inbound" stroke="#06b6d4" fill="url(#inboundGradient)" name="Inbound" />
              <Area type="monotone" dataKey="outbound" stroke="#8b5cf6" fill="url(#outboundGradient)" name="Outbound" />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-center gap-6 mt-4">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-500" />
              <span className="text-sm text-gray-400">Inbound</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-purple-500" />
              <span className="text-sm text-gray-400">Outbound</span>
            </div>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Server className="text-cyan-400" size={20} />
            Protocol Distribution
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={data.protocolData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {data.protocolData.map((entry: any, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px'
                }}
                formatter={(value) => `${value}%`}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-2">
            {data.protocolData.map((protocol: any) => (
              <div key={protocol.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: protocol.color }} />
                  <span className="text-sm text-gray-400">{protocol.name}</span>
                </div>
                <span className="text-sm text-white font-medium">{protocol.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Active Connections Table */}
      <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Wifi className="text-cyan-400" size={20} />
          Active Connections
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Source IP</th>
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Destination IP</th>
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Protocol</th>
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Port</th>
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Status</th>
                <th className="text-left px-4 py-3 text-sm font-semibold text-gray-400">Duration</th>
              </tr>
            </thead>
            <tbody>
              {data.activeConnections.map((conn: any, index: number) => (
                <tr key={index} className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-cyan-400 font-mono text-sm">{conn.srcIp}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-orange-400 font-mono text-sm">{conn.dstIp}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 rounded bg-slate-700 text-gray-300 text-xs font-medium">
                      {conn.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-gray-300 text-sm">{conn.port}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2.5 py-1 rounded text-xs font-medium ${
                      conn.status === 'ESTABLISHED' 
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-cyan-500/20 text-cyan-400'
                    }`}>
                      {conn.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-gray-400 text-sm">{conn.duration}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

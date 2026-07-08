import React, { useState, useEffect, useRef } from 'react';
import {
  FileText,
  Search,
  Filter,
  Download,
  RefreshCw,
  ChevronDown,
  Terminal,
  Clock,
  ChevronRight,
  Wifi,
  WifiOff,
  Trash2
} from 'lucide-react';

interface SystemLog {
  id: number;
  timestamp: string;
  level: string;
  component: string;
  message: string;
  ip: string | null;
  stack_trace: string | null;
  raw_payload: string | null;
}

export default function Logs() {
  const [logs, setLogs] = useState<SystemLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [totalLogs, setTotalLogs] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [severity, setSeverity] = useState('ALL');
  const [componentFilter, setComponentFilter] = useState('ALL');
  const [isLiveTail, setIsLiveTail] = useState(true);
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const query = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
        level: severity,
        component: componentFilter
      });
      const res = await fetch(`http://localhost:8000/api/system/logs?${query}`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setLogs(data.logs);
        setTotalLogs(data.total);
      }
    } catch (err) {
      console.error("Failed to fetch logs", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, limit, severity, componentFilter]);

  // WebSocket Live Tail
  useEffect(() => {
    if (!isLiveTail) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      return;
    }

    const connectWS = () => {
      const ws = new WebSocket('ws://localhost:8000/ws/system/logs');
      ws.onmessage = (event) => {
        try {
          const newLog = JSON.parse(event.data);
          // Only prepend if filters match (Simplified check)
          if (severity === 'ALL' || newLog.level === severity) {
             setLogs(prev => [newLog, ...prev].slice(0, limit));
             setTotalLogs(prev => prev + 1);
          }
        } catch (e) {
          console.error("WS Parse error", e);
        }
      };
      ws.onclose = () => {
        if (isLiveTail) {
           setTimeout(connectWS, 3000); // Reconnect
        }
      };
      wsRef.current = ws;
    };

    connectWS();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [isLiveTail, severity, limit]);

  const toggleRow = (id: number) => {
    const next = new Set(expandedRows);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpandedRows(next);
  };

  const getSeverityColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10';
      case 'ERROR': return 'text-orange-500 bg-orange-500/10';
      case 'WARNING': return 'text-yellow-500 bg-yellow-500/10';
      case 'INFO': return 'text-cyan-500 bg-cyan-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  const exportCSV = () => {
    const headers = ['ID', 'Timestamp', 'Level', 'Component', 'Message', 'IP'];
    const rows = logs.map(l => [l.id, l.timestamp, l.level, l.component, `"${l.message}"`, l.ip || '']);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `system_logs_${new Date().toISOString()}.csv`;
    a.click();
  };

  const handleClearLogs = async () => {
    if (window.confirm('Are you sure you want to clear all system logs? This action cannot be undone.')) {
      try {
        const res = await fetch('http://localhost:8000/api/clear_databases?target=logs', { method: 'DELETE', credentials: 'include' });
        if (res.ok) {
          setLogs([]);
          setTotalLogs(0);
        }
      } catch (err) {
        console.error('Failed to clear logs:', err);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Terminal className="text-cyan-400" />
            System Event Logs
          </h1>
          <p className="text-gray-400 mt-1">Real-time system health and execution tracking</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={handleClearLogs}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 transition-colors"
          >
            <Trash2 size={18} />
            Clear Database
          </button>
          <button 
            onClick={() => setIsLiveTail(!isLiveTail)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              isLiveTail 
              ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
              : 'bg-slate-800/50 text-gray-400 border border-slate-700/50'
            }`}
          >
            {isLiveTail ? <Wifi size={18} /> : <WifiOff size={18} />}
            Live Tail
          </button>
          <button onClick={exportCSV} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-gray-300 hover:border-cyan-500/50 transition-colors">
            <Download size={18} />
            Export
          </button>
          <button onClick={fetchLogs} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors">
            <RefreshCw size={18} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <select 
          value={severity} 
          onChange={e => setSeverity(e.target.value)}
          className="bg-slate-800/80 border border-slate-700/50 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-500/50"
        >
          <option value="ALL">All Levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="ERROR">Error</option>
          <option value="WARNING">Warning</option>
          <option value="INFO">Info</option>
        </select>

        <select 
          value={componentFilter} 
          onChange={e => setComponentFilter(e.target.value)}
          className="bg-slate-800/80 border border-slate-700/50 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-500/50"
        >
          <option value="ALL">All Components</option>
          <option value="PCAP_Analyzer">PCAP Analyzer</option>
          <option value="FastAPI">FastAPI</option>
          <option value="Snort">Snort Engine</option>
        </select>
        
        <div className="flex items-center gap-2 text-gray-400 ml-auto">
           <span className="text-sm">Total Logs: {totalLogs}</span>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700/50 bg-slate-800/50">
                <th className="w-8"></th>
                <th className="text-left px-4 py-4 text-sm font-semibold text-gray-400">Timestamp</th>
                <th className="text-left px-4 py-4 text-sm font-semibold text-gray-400">Level</th>
                <th className="text-left px-4 py-4 text-sm font-semibold text-gray-400">Component</th>
                <th className="text-left px-4 py-4 text-sm font-semibold text-gray-400">Message</th>
                <th className="text-left px-4 py-4 text-sm font-semibold text-gray-400">IP</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <React.Fragment key={log.id}>
                  <tr 
                    onClick={() => toggleRow(log.id)}
                    className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 text-gray-500">
                      <ChevronRight size={16} className={`transition-transform ${expandedRows.has(log.id) ? 'rotate-90' : ''}`} />
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300 font-mono whitespace-nowrap">
                      {log.timestamp}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-1 rounded text-xs font-bold ${getSeverityColor(log.level)}`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-cyan-400 font-mono">
                      {log.component}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-200">
                      {log.message}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400 font-mono">
                      {log.ip || '-'}
                    </td>
                  </tr>
                  
                  {expandedRows.has(log.id) && (
                    <tr className="bg-slate-950/50 border-b border-slate-700/30">
                      <td colSpan={6} className="px-12 py-4">
                         {log.stack_trace && (
                           <div className="mb-4">
                             <h4 className="text-xs font-semibold text-gray-400 uppercase mb-2">Stack Trace</h4>
                             <pre className="p-4 bg-slate-900 rounded-lg border border-slate-700/50 text-red-400 text-xs font-mono overflow-x-auto">
                               {log.stack_trace}
                             </pre>
                           </div>
                         )}
                         {log.raw_payload && (
                           <div>
                             <h4 className="text-xs font-semibold text-gray-400 uppercase mb-2">Raw Payload</h4>
                             <pre className="p-4 bg-slate-900 rounded-lg border border-slate-700/50 text-green-400 text-xs font-mono overflow-x-auto">
                               {log.raw_payload}
                             </pre>
                           </div>
                         )}
                         {!log.stack_trace && !log.raw_payload && (
                           <div className="text-sm text-gray-500 italic">No additional context available.</div>
                         )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
              
              {logs.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-gray-500">
                    No system logs found matching the criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination */}
        <div className="border-t border-slate-700/50 bg-slate-800/30 px-6 py-4 flex items-center justify-between">
          <div className="text-sm text-gray-400">
            Showing <span className="text-white">{(page - 1) * limit + 1}</span> to <span className="text-white">{Math.min(page * limit, totalLogs)}</span> of <span className="text-white">{totalLogs}</span>
          </div>
          <div className="flex items-center gap-2">
             <button 
               disabled={page === 1}
               onClick={() => setPage(p => p - 1)}
               className="px-3 py-1 rounded bg-slate-700/50 text-white disabled:opacity-50 hover:bg-slate-700 transition-colors"
             >
               Prev
             </button>
             <button 
               disabled={page * limit >= totalLogs}
               onClick={() => setPage(p => p + 1)}
               className="px-3 py-1 rounded bg-slate-700/50 text-white disabled:opacity-50 hover:bg-slate-700 transition-colors"
             >
               Next
             </button>
          </div>
        </div>
      </div>
    </div>
  );
}

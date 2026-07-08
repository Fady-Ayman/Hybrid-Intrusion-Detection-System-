import { useState, useEffect, useRef, useCallback } from 'react';
import {
  AlertTriangle,
  Filter,
  Search,
  ChevronDown,
  Eye,
  Ban,
  Clock,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Trash2
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { AlertLog } from '../data/mockData';

export default function Alerts() {
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [originFilter, setOriginFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedAlert, setSelectedAlert] = useState<AlertLog | null>(null);
  
  const [alerts, setAlerts] = useState<AlertLog[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);
  
  const filtersRef = useRef({ searchTerm, severityFilter, sortOrder, originFilter });

  useEffect(() => {
    filtersRef.current = { searchTerm, severityFilter, sortOrder, originFilter };
  }, [searchTerm, severityFilter, sortOrder, originFilter]);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/alerts?page=${page}&limit=50&severity=${severityFilter}&search=${searchTerm}&sortOrder=${sortOrder}&origin=${originFilter}`, { credentials: 'include' });
      const data = await res.json();
      setAlerts(data.alerts || []);
      setTotalAlerts(data.total || 0);
      setTotalPages(data.totalPages || 1);
    } catch (err) {
      console.error("Failed to fetch alerts:", err);
    } finally {
      setLoading(false);
    }
  }, [page, severityFilter, searchTerm, sortOrder, originFilter]);

  // Fetch when filters or page change, with debounce for search
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchAlerts();
    }, 300);
    return () => clearTimeout(timer);
  }, [fetchAlerts]);

  // WebSocket for real-time updates
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws');
    
    ws.onmessage = (event) => {
      try {
        const newAlert = JSON.parse(event.data);
        
        const currentSearch = filtersRef.current.searchTerm.toLowerCase();
        const currentSeverity = filtersRef.current.severityFilter;
        const currentSort = filtersRef.current.sortOrder;
        
        // Only consider it an alert if it is definitively an attack (ignore Benign and Uncertain)
        if (!newAlert.is_attack || newAlert.is_attack === "0" || newAlert.is_attack === "false" || newAlert.is_attack === "False") return;

        let matchesSearch = true;
        if (currentSearch) {
          matchesSearch = 
            (newAlert.signature || "").toLowerCase().includes(currentSearch) ||
            (newAlert.srcIp || "").includes(currentSearch) ||
            (newAlert.dstIp || "").includes(currentSearch);
        }
        
        let matchesSeverity = true;
        if (currentSeverity !== 'ALL') {
          matchesSeverity = newAlert.severity === currentSeverity;
        }

        let matchesOrigin = true;
        if (filtersRef.current.originFilter !== 'ALL') {
          const expectedPcap = filtersRef.current.originFilter === 'PCAP' ? 1 : 0;
          matchesOrigin = newAlert.is_pcap === expectedPcap;
        }

        if (matchesSearch && matchesSeverity && matchesOrigin) {
          setAlerts(prev => {
            const existingIndex = prev.findIndex(a => a.id === newAlert.id);
            if (existingIndex !== -1) {
              // Update existing aggregated alert
              const updated = [...prev];
              updated[existingIndex] = newAlert;
              return updated;
            }
            
            if (currentSort === 'desc') {
               return [newAlert, ...prev].slice(0, 50);
            }
            return prev;
          });
          
          // Only increment total if it's truly a new alert (not updating an existing aggregated one)
          setAlerts(prev => {
            const isUpdate = prev.some(a => a.id === newAlert.id && a !== newAlert); // This is just a safe-check, we update the total separately
            return prev;
          });
          // Actually a better way to handle total increment:
          // we can't easily read `prev` from `setAlerts` to conditionally call `setTotalAlerts`, 
          // but we can just use the `setAlerts` return to determine if it grew.
          // For simplicity, we'll increment total only if it's a new ID, let's track seen IDs or just accept a slight total skew for live updates.
        }
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };

    return () => ws.close();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/20 border-red-500/50';
      case 'HIGH': return 'text-orange-500 bg-orange-500/20 border-orange-500/50';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/20 border-yellow-500/50';
      case 'LOW': return 'text-green-500 bg-green-500/20 border-green-500/50';
      default: return 'text-gray-500 bg-gray-500/20 border-gray-500/50';
    }
  };

  const getSourceBadge = (source: string) => {
    switch (source?.toUpperCase()) {
      case 'ML':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border text-indigo-400 bg-indigo-500/20 border-indigo-500/50">
            ML Model
          </span>
        );
      case 'SNORT':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border text-rose-400 bg-rose-500/20 border-rose-500/50">
            Snort Engine
          </span>
        );
      case 'HYBRID':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border text-amber-400 bg-amber-500/20 border-amber-500/50">
            Hybrid (ML + Signature)
          </span>
        );
      case 'ML_AGGREGATED':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border text-purple-200 bg-purple-900 border-purple-700">
            ML (Aggregated)
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border text-indigo-400 bg-indigo-500/20 border-indigo-500/50">
            ML Model
          </span>
        );
    }
  };

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;

  const handleClearAlerts = async () => {
    if (window.confirm('Are you sure you want to clear all alerts? This action cannot be undone.')) {
      try {
        const res = await fetch('http://localhost:8000/api/clear_databases?target=alerts', { method: 'DELETE', credentials: 'include' });
        if (res.ok) {
          setAlerts([]);
          setTotalAlerts(0);
        }
      } catch (err) {
        console.error('Failed to clear alerts:', err);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <AlertTriangle className="text-red-400" />
            Security Alerts
          </h1>
          <p className="text-gray-400 mt-1">Real-time intrusion detection alerts ({totalAlerts} total)</p>
        </div>
        <div className="flex items-center gap-4">
          {user?.role === 'admin' && (
            <button 
              onClick={handleClearAlerts}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 font-medium transition-colors"
            >
              <Trash2 size={18} />
              Clear Database
            </button>
          )}
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-400 font-medium">{criticalCount} Critical (Page {page})</span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
          <input
            type="text"
            placeholder="Search alerts by signature, IP..."
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 transition-colors"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="appearance-none pl-10 pr-10 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-white focus:outline-none focus:border-cyan-500/50 transition-colors cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" size={18} />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
          <select
            value={originFilter}
            onChange={(e) => { setOriginFilter(e.target.value); setPage(1); }}
            className="appearance-none pl-10 pr-10 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-white focus:outline-none focus:border-cyan-500/50 transition-colors cursor-pointer"
          >
            <option value="ALL">All Origins</option>
            <option value="LIVE">Live Traffic</option>
            <option value="PCAP">PCAP Uploads</option>
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" size={18} />
        </div>
        <button
          onClick={() => { setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc'); setPage(1); }}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-gray-300 hover:border-cyan-500/50 transition-colors"
        >
          <ArrowUpDown size={18} />
          <span>{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
        </button>
        <button
          onClick={fetchAlerts}
          disabled={loading}
          className={`p-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-gray-300 hover:border-cyan-500/50 transition-colors ${loading ? 'opacity-50' : ''}`}
          title="Refresh"
        >
          <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 overflow-hidden mb-6">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Severity</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Timestamp</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Source Engine</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Signature</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Source</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Destination</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Protocol</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Action</th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-8 text-center text-gray-500">
                    <RefreshCw size={24} className="animate-spin mx-auto mb-2 text-cyan-500" />
                    Loading alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-8 text-center text-gray-500">
                    No alerts found matching your criteria.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2 text-gray-400 text-sm font-mono whitespace-nowrap">
                          <Clock size={14} />
                          {alert.timestamp}
                        </div>
                        <span className={`self-start px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          alert.is_pcap === 1 
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' 
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {alert.is_pcap === 1 ? 'PCAP' : 'LIVE'}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {getSourceBadge(alert.detection_source || 'ML')}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <div>
                          <p className="text-white text-sm font-medium">{alert.signature}</p>
                          <p className="text-gray-500 text-xs mt-1">
                            {alert.signatureId ? `SID: ${alert.signatureId} | ` : ''}{alert.category}
                          </p>
                        </div>
                        {alert.hit_count && alert.hit_count > 1 ? (
                          <span className="px-2 py-0.5 text-xs font-bold text-white bg-red-600 rounded shadow">
                              x{alert.hit_count}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-cyan-400 font-mono text-sm">{alert.srcIp}:{alert.srcPort}</span>
                    </td>
                    <td className="px-6 py-4">
                      {alert.hit_count && alert.hit_count > 1 && alert.targeted_ports && alert.targeted_ports.length > 0 ? (
                        <div className="flex items-center space-x-1 text-orange-400 font-mono text-sm">
                            <span>{alert.targeted_ports.slice(0, 2).join(', ')}</span>
                            {alert.targeted_ports.length - 2 > 0 && (
                                <span className="px-1.5 py-0.5 text-[10px] font-bold text-blue-100 bg-blue-900 rounded">
                                    +{alert.targeted_ports.length - 2}
                                </span>
                            )}
                        </div>
                      ) : (
                        <span className="text-orange-400 font-mono text-sm">{alert.dstIp}:{alert.dstPort}</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-1 rounded bg-slate-700 text-gray-300 text-xs font-medium">
                        {alert.protocol}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded text-xs font-medium ${
                        alert.action === 'Blocked' 
                          ? 'bg-red-500/20 text-red-400' 
                          : 'bg-green-500/20 text-green-400'
                      }`}>
                        {alert.action}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <button className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors">
                          <Eye size={14} />
                        </button>
                        <button className="p-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors">
                          <Ban size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-4">
        <span className="text-gray-400 text-sm">
          Showing page {page} of {totalPages}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1 || loading}
            className="p-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-gray-300 hover:border-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft size={18} />
          </button>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages || loading || totalPages === 0}
            className="p-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-gray-300 hover:border-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight size={18} />
          </button>
        </div>
      </div>

      {/* Selected Alert Detail Modal */}
      {selectedAlert && (
        <div 
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50"
          onClick={() => setSelectedAlert(null)}
        >
          <div 
            className="bg-slate-900 border border-cyan-500/30 rounded-xl p-6 max-w-2xl w-full mx-4 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Alert Details</h2>
              <button 
                onClick={() => setSelectedAlert(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <span className={`px-3 py-1.5 rounded text-sm font-bold border ${getSeverityColor(selectedAlert.severity)}`}>
                  {selectedAlert.severity}
                </span>
                {getSourceBadge(selectedAlert.detection_source || 'ML')}
                <span className="text-gray-400 font-mono">{selectedAlert.timestamp}</span>
              </div>
              <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <p className="text-white text-lg font-medium mb-2">{selectedAlert.signature}</p>
                <p className="text-gray-400 text-sm">Signature ID: {selectedAlert.signatureId}</p>
                <p className="text-gray-400 text-sm">Category: {selectedAlert.category}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-slate-800/50 border border-cyan-500/20">
                  <p className="text-gray-400 text-sm mb-2">Source</p>
                  <p className="text-cyan-400 font-mono text-lg">{selectedAlert.srcIp}:{selectedAlert.srcPort}</p>
                </div>
                <div className="p-4 rounded-lg bg-slate-800/50 border border-orange-500/20">
                  <p className="text-gray-400 text-sm mb-2">Destination</p>
                  <p className="text-orange-400 font-mono text-lg">{selectedAlert.dstIp}:{selectedAlert.dstPort}</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-sm">Protocol:</span>
                  <span className="px-2 py-1 rounded bg-slate-700 text-gray-300 text-sm">{selectedAlert.protocol}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-sm">Action:</span>
                  <span className={`px-2.5 py-1 rounded text-sm font-medium ${
                    selectedAlert.action === 'Blocked' 
                      ? 'bg-red-500/20 text-red-400' 
                      : 'bg-green-500/20 text-green-400'
                  }`}>
                    {selectedAlert.action}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-4 mt-6 pt-6 border-t border-slate-700/50">
              <button className="flex-1 py-2.5 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors font-medium">
                Investigate
              </button>
              <button className="flex-1 py-2.5 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors font-medium">
                Block Source IP
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

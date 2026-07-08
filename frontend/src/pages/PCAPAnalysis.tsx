import { useState, useCallback } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import {
  Database, Upload, FileText, AlertTriangle, CheckCircle,
  Loader2, Clock, HardDrive, Wifi, Shield, XCircle
} from 'lucide-react';
import { API_BASE_URL } from '../data/api';

type Alert = any;
type PCAPAnalysisResult = any;

// Extend type locally to include new backend fields
interface FullPCAPResult extends PCAPAnalysisResult {
  snort_summary?: {
    ran: boolean;
    alerts_found: number;
    rules_matched: number[];
  };
  detection_breakdown?: {
    signature: number;
    ml: number;
  };
}


const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e'];

// ── Data aggregation helpers ──

interface IPCount { ip: string; count: number; }

function getTopIPs(alerts: Alert[], field: 'srcIp' | 'dstIp', limit = 5): IPCount[] {
  const counts: Record<string, number> = {};
  for (const a of alerts) {
    const ip = a[field];
    if (ip) counts[ip] = (counts[ip] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function getSeverityChartData(dist: any) {
  if (!dist) return [];
  return [
    { name: 'Critical', value: dist.critical || 0 },
    { name: 'High', value: dist.high || 0 },
    { name: 'Medium', value: dist.medium || 0 },
    { name: 'Low', value: dist.low || 0 },
  ].filter(d => d.value > 0);
}

function getAttackList(attackTypes: Record<string, number>) {
  if (!attackTypes) return [];
  return Object.entries(attackTypes)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

// ── Component ──

export default function PCAPAnalysis() {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: string; uploadTime: string } | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [result, setResult] = useState<FullPCAPResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ── Upload handler (real API call) ──
  const uploadAndAnalyze = useCallback(async (file: File) => {
    console.log('[PCAP] Starting upload:', file.name, file.size, file.type);
    setError(null);
    setResult(null);
    setAnalysisComplete(false);

    setUploadedFile({
      name: file.name,
      size: (file.size / (1024 * 1024)).toFixed(2) + ' MB',
      uploadTime: new Date().toLocaleString(),
    });

    setIsAnalyzing(true);

    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const res = await fetch(`${API_BASE_URL}/analyze/file`, {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });
      
      const response = await res.json();
      console.log('[PCAP] Response received:', response);

      setIsAnalyzing(false);

      if (res.ok && response.error == null) {
        setResult(response as FullPCAPResult);
        setAnalysisComplete(true);
      } else {
        setError(response.error || 'Analysis failed');
      }
    } catch (err) {
      console.error('[PCAP] Upload/Analysis error:', err);
      setIsAnalyzing(false);
      setError(err instanceof Error ? err.message : 'Upload failed — check console for details');
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng') || file.name.endsWith('.cap') || file.name.endsWith('.csv'))) {
      uploadAndAnalyze(file);
    } else {
      setError('Unsupported file type. Please use .pcap, .pcapng, .cap, or .csv files.');
    }
  }, [uploadAndAnalyze]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      uploadAndAnalyze(file);
    }
  }, [uploadAndAnalyze]);

  // Derived data from result
  const severityData = result ? getSeverityChartData(result.severity_distribution) : [];
  const topSourceIPs = result ? getTopIPs(result.alerts || [], 'srcIp') : [];
  const topDestIPs = result ? getTopIPs(result.alerts || [], 'dstIp') : [];
  const attackList = result ? getAttackList(result.attack_types) : [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Database className="text-cyan-400" />
            PCAP Analysis
          </h1>
          <p className="text-gray-400 mt-1">Upload and analyze packet capture files</p>
        </div>
      </div>

      {/* Upload Area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`rounded-xl border-2 border-dashed p-12 mb-8 text-center transition-all duration-300 ${
          isDragging
            ? 'border-cyan-400 bg-cyan-500/10'
            : 'border-slate-700 bg-slate-900/50 hover:border-slate-600'
        }`}
      >
        <div className="flex flex-col items-center">
          <div className={`p-4 rounded-full mb-4 ${isDragging ? 'bg-cyan-500/20' : 'bg-slate-800'}`}>
            <Upload className={`w-12 h-12 ${isDragging ? 'text-cyan-400' : 'text-gray-500'}`} />
          </div>
          <h3 className="text-xl font-semibold text-white mb-2">
            {isDragging ? 'Drop PCAP or CSV file here' : 'Drag & Drop PCAP or CSV File'}
          </h3>
          <p className="text-gray-400 mb-4">or click to browse</p>
          <label className="px-6 py-2.5 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors cursor-pointer">
            <span>Browse Files</span>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap,.csv"
              onChange={handleFileSelect}
              className="hidden"
            />
          </label>
          <p className="text-sm text-gray-500 mt-4">Supported formats: .pcap, .pcapng, .cap, .csv (Max 100MB)</p>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/30 p-4 mb-8 flex items-center gap-3">
          <XCircle className="text-red-400 flex-shrink-0" size={24} />
          <div>
            <p className="text-red-400 font-medium">Analysis Failed</p>
            <p className="text-red-400/70 text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* Uploaded File Info */}
      {uploadedFile && (
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6 mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-cyan-500/20">
                <FileText className="text-cyan-400" size={24} />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">{uploadedFile.name}</h3>
                <div className="flex items-center gap-4 text-sm text-gray-400 mt-1">
                  <span className="flex items-center gap-1">
                    <HardDrive size={14} />
                    {uploadedFile.size}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock size={14} />
                    {uploadedFile.uploadTime}
                  </span>
                </div>
              </div>
            </div>
            {isAnalyzing ? (
              <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                <Loader2 className="w-5 h-5 text-yellow-400 animate-spin" />
                <span className="text-yellow-400 font-medium">Analyzing...</span>
              </div>
            ) : analysisComplete ? (
              <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-green-500/10 border border-green-500/30">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="text-green-400 font-medium">Analysis Complete</span>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Analysis Loading Animation */}
      {isAnalyzing && (
        <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-12 mb-8">
          <div className="flex flex-col items-center">
            <div className="relative mb-8">
              <div className="w-24 h-24 rounded-full border-4 border-slate-700" />
              <div className="absolute inset-0 w-24 h-24 rounded-full border-4 border-cyan-500 border-t-transparent animate-spin" />
              <Loader2 className="absolute inset-0 m-auto w-10 h-10 text-cyan-400 animate-pulse" />
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Analyzing PCAP File</h3>
            <p className="text-gray-400 mb-6">Sending to ML pipeline for threat detection...</p>
            <div className="w-full max-w-md">
              <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full animate-loading-bar" />
              </div>
              <div className="flex items-center justify-between mt-2 text-sm text-gray-500">
                <span>Processing flows...</span>
                <span>Please wait</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Results */}
      {analysisComplete && result && !isAnalyzing && (
        <>
          {/* Stats Overview */}
          <div className="grid grid-cols-4 gap-6 mb-8">
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-3 rounded-lg bg-cyan-500/20">
                  <Wifi className="text-cyan-400" size={24} />
                </div>
                <span className="text-gray-400">Total Flows</span>
              </div>
              <p className="text-3xl font-bold text-white">{(result.total_flows || 0).toLocaleString()}</p>
            </div>
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-3 rounded-lg bg-green-500/20">
                  <Shield className="text-green-400" size={24} />
                </div>
                <span className="text-gray-400">Benign Flows</span>
              </div>
              <p className="text-3xl font-bold text-green-400">{(result.benign_flows || 0).toLocaleString()}</p>
            </div>
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-3 rounded-lg bg-yellow-500/20">
                  <AlertTriangle className="text-yellow-400" size={24} />
                </div>
                <span className="text-gray-400">Alerts Found</span>
              </div>
              <p className="text-3xl font-bold text-yellow-400">{(result.alerts_found || 0).toLocaleString()}</p>
            </div>
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-3 rounded-lg bg-red-500/20">
                  <AlertTriangle className="text-red-400" size={24} />
                </div>
                <span className="text-gray-400">Attack Types</span>
              </div>
              <p className="text-3xl font-bold text-red-400">{attackList.length}</p>
            </div>
          </div>

          {/* Detection Engines Status */}
          <div className="grid grid-cols-2 gap-6 mb-8">
            {/* Snort Engine */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  <Shield className="text-purple-400" size={20} />
                </div>
                <div>
                  <h3 className="text-white font-semibold">Snort Signature Engine</h3>
                  <p className="text-xs text-gray-500">Payload-based detection</p>
                </div>
                <span className={`ml-auto px-2.5 py-1 rounded-full text-xs font-medium ${
                  result.snort_summary?.ran
                    ? 'bg-green-500/20 text-green-400'
                    : 'bg-gray-500/20 text-gray-400'
                }`}>
                  {result.snort_summary?.ran ? '✓ Ran' : '✗ Skipped'}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-purple-400">{result.snort_summary?.alerts_found ?? 0}</p>
                  <p className="text-xs text-gray-500 mt-1">Alerts</p>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-purple-400">{result.snort_summary?.rules_matched?.length ?? 0}</p>
                  <p className="text-xs text-gray-500 mt-1">Rules Fired</p>
                </div>
              </div>
              {result.snort_summary && (result.snort_summary?.rules_matched?.length || 0) > 0 && (
                <div className="mt-3">
                  <p className="text-xs text-gray-500 mb-1">Matched SIDs:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(result.snort_summary?.rules_matched || []).slice(0, 8).map(sid => (
                      <span key={sid} className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 text-xs font-mono">{sid}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* ML Engine */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-cyan-500/20">
                  <Database className="text-cyan-400" size={20} />
                </div>
                <div>
                  <h3 className="text-white font-semibold">ML Pipeline (CyberHawk-V2)</h3>
                  <p className="text-xs text-gray-500">Flow-based statistical detection</p>
                </div>
                <span className="ml-auto px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400">
                  ✓ Ran
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-cyan-400">{result.detection_breakdown?.ml ?? result.alerts_found}</p>
                  <p className="text-xs text-gray-500 mt-1">Alerts</p>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-cyan-400">{result.total_flows}</p>
                  <p className="text-xs text-gray-500 mt-1">Flows Scanned</p>
                </div>
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-2 gap-6 mb-8">
            {/* Severity Distribution (Pie Chart) */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
              {severityData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={5}
                        dataKey="value"
                        nameKey="name"
                      >
                        {severityData.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '8px'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-2">
                    {severityData.map((item, index) => (
                      <div key={item.name} className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-sm text-gray-400">{item.name}</span>
                        <span className="text-sm text-white ml-auto">{item.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center h-[250px] text-gray-500">
                  <Shield size={40} className="mb-3 text-green-500/40" />
                  <p>No threats detected</p>
                </div>
              )}
            </div>

            {/* Top Source IPs (Bar Chart) */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Top Source IPs</h3>
              {topSourceIPs.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={topSourceIPs} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis type="number" stroke="#64748b" />
                    <YAxis dataKey="ip" type="category" stroke="#64748b" width={120} tick={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                    <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} name="Alerts" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex flex-col items-center justify-center h-[250px] text-gray-500">
                  <Shield size={40} className="mb-3 text-green-500/40" />
                  <p>No malicious source IPs found</p>
                </div>
              )}
            </div>
          </div>

          {/* Bottom Row */}
          <div className="grid grid-cols-2 gap-6">
            {/* Detected Threats (Attack Types) */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="text-red-400" size={20} />
                Detected Attack Types
              </h3>
              {attackList.length > 0 ? (
                <div className="space-y-3">
                  {attackList.map((attack, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700/50"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-2 h-2 rounded-full bg-red-500" />
                        <p className="text-white font-medium">{attack.name}</p>
                      </div>
                      <span className="px-3 py-1 rounded bg-red-500/20 text-red-400 text-sm font-medium">
                        {attack.count} detected
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield size={40} className="mx-auto mb-3 text-green-500/40" />
                  <p>No attacks detected — File is clean</p>
                </div>
              )}
            </div>

            {/* Top Destination IPs */}
            <div className="rounded-xl bg-slate-900/80 backdrop-blur-sm border border-slate-700/50 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Top Destination IPs</h3>
              {topDestIPs.length > 0 ? (
                <div className="space-y-3">
                  {topDestIPs.map((item, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700/50"
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm font-medium">
                          {index + 1}
                        </span>
                        <span className="text-orange-400 font-mono">{item.ip}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-white font-medium">{item.count}</span>
                        <span className="text-gray-400 text-sm ml-1">alerts</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield size={40} className="mx-auto mb-3 text-green-500/40" />
                  <p>No targeted destinations found</p>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* Loading Animation Style */}
      <style>{`
        @keyframes loading-bar {
          0% { width: 0%; }
          50% { width: 70%; }
          75% { width: 85%; }
          100% { width: 95%; }
        }
        .animate-loading-bar {
          animation: loading-bar 3s ease-in-out forwards;
        }
      `}</style>
    </div>
  );
}

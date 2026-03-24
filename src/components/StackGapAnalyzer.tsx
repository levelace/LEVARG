import React, { useState, useEffect } from 'react';
import { Layers, Play, AlertCircle, RefreshCw, Server, Activity, Terminal } from 'lucide-react';

export default function StackGapAnalyzer() {
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('GET');
  const [headers, setHeaders] = useState('{\n  "User-Agent": "LevarG-Analyzer/1.0"\n}');
  const [fingerprint, setFingerprint] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchFindings = async () => {
    try {
      const res = await fetch('/api/stack-gap/findings');
      const data = await res.json();
      setFindings(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchFindings();
    const interval = setInterval(fetchFindings, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalyze = async () => {
    if (!url) return;
    setLoading(true);
    setError('');
    setFingerprint(null);
    
    try {
      let parsedHeaders = {};
      try {
        parsedHeaders = JSON.parse(headers);
      } catch (e) {
        setError('Invalid JSON in headers');
        setLoading(false);
        return;
      }

      const res = await fetch('/api/stack-gap/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, method, headers: parsedHeaders })
      });
      
      const data = await res.json();
      if (res.ok) {
        setFingerprint(data.fingerprint);
      } else {
        setError(data.error);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full bg-black/40 backdrop-blur-md relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative z-10">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Layers className="w-8 h-8 text-emerald-400" />
          Stack Gap Analyzer
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Detect inconsistencies between infrastructure layers</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8 relative z-10">
        <div className="lg:col-span-2 bg-black/50 border border-emerald-900/30 p-6 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <div className="grid grid-cols-12 gap-4 items-end mb-4">
            <div className="col-span-2 relative group">
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
              <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Method</label>
              <select
                value={method}
                onChange={e => setMethod(e.target.value)}
                className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all relative z-10"
              >
                <option className="bg-emerald-950 text-emerald-100">GET</option>
                <option className="bg-emerald-950 text-emerald-100">POST</option>
              </select>
            </div>
            <div className="col-span-7 relative group">
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
              <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Target Endpoint</label>
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="https://api.example.com/v1/users"
                className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all placeholder:text-emerald-900/50 relative z-10"
              />
            </div>
            <div className="col-span-3">
              <button
                onClick={handleAnalyze}
                disabled={loading || !url}
                className="w-full bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-4 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all disabled:opacity-50 rounded-md relative overflow-hidden group"
              >
                <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
                {loading ? <RefreshCw className="w-4 h-4 animate-spin relative z-10" /> : <Play className="w-4 h-4 relative z-10" />} 
                <span className="relative z-10">Analyze Stack</span>
              </button>
            </div>
          </div>
          
          <div className="relative group">
            <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Headers (JSON)</label>
            <textarea
              value={headers}
              onChange={e => setHeaders(e.target.value)}
              className="w-full h-24 bg-black/50 border border-emerald-900/50 p-4 text-xs font-mono text-emerald-100/90 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md resize-none scrollbar-hide transition-all relative z-10 shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]"
            />
          </div>
          
          {error && (
            <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2 rounded-md shadow-[0_0_10px_rgba(239,68,68,0.1)]">
              <AlertCircle className="w-4 h-4" /> {error}
            </div>
          )}
        </div>

        <div className="lg:col-span-1 bg-black/40 backdrop-blur-md border border-emerald-900/30 p-6 rounded-lg flex flex-col shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <h3 className="text-xs font-mono text-emerald-100 uppercase tracking-wider mb-4 flex items-center gap-2 drop-shadow-[0_0_5px_rgba(16,185,129,0.3)]">
            <Server className="w-4 h-4 text-emerald-400" /> Stack Fingerprint
          </h3>
          
          {!fingerprint ? (
            <div className="flex-1 flex flex-col items-center justify-center opacity-30">
              <Activity className="w-8 h-8 mb-2 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
              <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/50 text-center">Run analysis to<br/>detect infrastructure</p>
            </div>
          ) : (
            <div className="space-y-4 flex-1">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">CDN / Edge</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.cdn}</div>
                </div>
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">WAF</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.waf}</div>
                </div>
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">Reverse Proxy</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.proxy}</div>
                </div>
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">Backend Server</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.backend}</div>
                </div>
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">Language</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.language}</div>
                </div>
                <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                  <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">Framework</div>
                  <div className="text-sm font-mono text-emerald-100">{fingerprint.framework}</div>
                </div>
              </div>
              <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                <div className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest mb-1">Detected Errors / Leaks</div>
                <div className="text-sm font-mono text-amber-400 drop-shadow-[0_0_5px_rgba(251,191,36,0.3)]">
                  {fingerprint.errors?.join(', ') || 'None detected'}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex-1 bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg flex flex-col overflow-hidden min-h-0 shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative z-10">
        <div className="p-4 bg-black/50 border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 flex justify-between items-center shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
          <span>Detected Gaps & Inconsistencies</span>
          <span className="bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded-sm border border-emerald-500/30 shadow-[0_0_5px_rgba(16,185,129,0.2)]">{findings.length} Findings</span>
        </div>
        
        <div className="flex-1 overflow-y-auto scrollbar-hide">
          {findings.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center opacity-30">
              <Terminal className="w-12 h-12 mb-4 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
              <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No stack gaps detected yet</p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 bg-black/50">
                  <th className="p-4 font-medium">Endpoint</th>
                  <th className="p-4 font-medium">Mutation Type</th>
                  <th className="p-4 font-medium">Baseline</th>
                  <th className="p-4 font-medium">Mutated</th>
                  <th className="p-4 font-medium">Evidence</th>
                  <th className="p-4 font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-emerald-900/20">
                {findings.map(finding => (
                  <tr key={finding.id} className="hover:bg-emerald-950/30 transition-colors group">
                    <td className="p-4 text-xs font-mono text-emerald-100/70 group-hover:text-emerald-100 transition-colors max-w-[200px] truncate" title={finding.endpoint}>{finding.endpoint}</td>
                    <td className="p-4 text-xs font-mono text-amber-400 drop-shadow-[0_0_5px_rgba(251,191,36,0.3)]">{finding.mutation_type}</td>
                    <td className="p-4 text-xs font-mono">
                      <span className="px-2 py-1 rounded-sm border bg-black/50 border-emerald-900/50 text-emerald-500/70">
                        {finding.baseline_status}
                      </span>
                    </td>
                    <td className="p-4 text-xs font-mono">
                      <span className={`px-2 py-1 rounded-sm border ${finding.mutated_status >= 500 ? 'bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_5px_rgba(239,68,68,0.2)]' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_5px_rgba(16,185,129,0.2)]'}`}>
                        {finding.mutated_status}
                      </span>
                    </td>
                    <td className="p-4 text-xs font-mono text-emerald-500/70">{finding.evidence}</td>
                    <td className="p-4">
                      <span className={`text-[10px] font-mono uppercase px-2 py-1 rounded-sm border ${finding.confidence === 'high' ? 'bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_5px_rgba(239,68,68,0.2)]' : 'bg-amber-500/10 border-amber-500/30 text-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.2)]'}`}>
                        {finding.confidence}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

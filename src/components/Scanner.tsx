import React, { useState, useEffect } from 'react';
import { Activity, Play, AlertCircle, CheckCircle2, Terminal, RefreshCw, Wand2, ChevronDown, ChevronUp } from 'lucide-react';

export default function Scanner({ initialUrl }: { initialUrl?: string }) {
  const [payloads, setPayloads] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [results, setResults] = useState<any[]>([]);
  
  const [targetUrl, setTargetUrl] = useState(initialUrl || 'https://example.com/?id=§FUZZ§');
  const [payloadSetId, setPayloadSetId] = useState('');
  const [method, setMethod] = useState('GET');
  const [loading, setLoading] = useState(false);
  const [fuzzableDiscoveries, setFuzzableDiscoveries] = useState<any[]>([]);
  const [showDiscoveries, setShowDiscoveries] = useState(false);

  const fetchFuzzable = async () => {
    try {
      const res = await fetch('/api/discoveries/fuzzable');
      const data = await res.json();
      setFuzzableDiscoveries(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchFuzzable();
  }, []);

  useEffect(() => {
    if (initialUrl) setTargetUrl(initialUrl.includes('§FUZZ§') ? initialUrl : `${initialUrl}?id=§FUZZ§`);
  }, [initialUrl]);

  const fetchData = async () => {
    const [pRes, sRes] = await Promise.all([
      fetch('/api/payloads').then(r => r.json()),
      fetch('/api/scans').then(r => r.json())
    ]);
    setPayloads(pRes);
    setScans(sRes);
    if (pRes.length > 0 && !payloadSetId) setPayloadSetId(pRes[0].id);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      fetchData();
      if (selectedScan) fetchResults(selectedScan);
    }, 5000);
    return () => clearInterval(interval);
  }, [selectedScan]);

  const fetchResults = async (scanId: string) => {
    const res = await fetch(`/api/scans/${scanId}/results`);
    const data = await res.json();
    setResults(data);
  };

  const startScan = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          payloadSetId,
          method,
          headers: { "User-Agent": "LevarG-Scanner/1.0" },
          body: ""
        })
      });
      const data = await res.json();
      setSelectedScan(data.id);
      fetchData();
    } catch (err) {
      console.error(err);
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
          <Activity className="w-8 h-8 text-emerald-400" />
          Fuzzing Scanner
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Automated parameter mutation and anomaly detection</p>
      </header>

      <div className="bg-black/50 border border-emerald-900/30 p-6 mb-8 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative z-10">
        <div className="grid grid-cols-12 gap-4 items-end">
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
          <div className="col-span-6 relative group">
            <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
            <div className="flex justify-between items-center mb-2">
              <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70">Target URL (Use §FUZZ§ for injection point)</label>
              {fuzzableDiscoveries.length > 0 && (
                <button 
                  onClick={() => setShowDiscoveries(!showDiscoveries)}
                  className="text-[10px] uppercase font-mono tracking-widest text-emerald-400 hover:text-emerald-300 flex items-center gap-1 transition-colors"
                >
                  <Wand2 className="w-3 h-3" /> 
                  {showDiscoveries ? 'Hide Discoveries' : 'Auto-Select'}
                  {showDiscoveries ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                </button>
              )}
            </div>
            <div className="relative">
              <input
                type="text"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all relative z-10"
              />
              
              {showDiscoveries && (
                <div className="absolute top-full left-0 right-0 mt-2 bg-black border border-emerald-500/30 rounded-md shadow-[0_10px_30px_rgba(0,0,0,0.8)] z-50 max-h-[250px] overflow-y-auto scrollbar-hide">
                  <div className="p-2 border-b border-emerald-900/30 bg-emerald-950/20 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70">
                    High-Value Fuzzable Discoveries
                  </div>
                  {fuzzableDiscoveries.map((disc, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        setTargetUrl(disc.url.includes('?') ? `${disc.url}&test=§FUZZ§` : `${disc.url}?id=§FUZZ§`);
                        setMethod(disc.method || 'GET');
                        setShowDiscoveries(false);
                      }}
                      className="w-full text-left p-3 hover:bg-emerald-500/10 border-b border-emerald-900/10 transition-colors flex justify-between items-center group"
                    >
                      <div className="flex flex-col">
                        <span className="text-xs font-mono text-emerald-100 truncate max-w-[300px]">{disc.url}</span>
                        <span className="text-[10px] font-mono text-emerald-500/50 uppercase">{disc.method}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                          Score: {disc.score}
                        </span>
                        <Play className="w-3 h-3 text-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="col-span-2 relative group">
            <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Payload Set</label>
            <select
              value={payloadSetId}
              onChange={e => setPayloadSetId(e.target.value)}
              className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all relative z-10"
            >
              {payloads.map(p => <option key={p.id} value={p.id} className="bg-emerald-950 text-emerald-100">{p.name}</option>)}
            </select>
          </div>
          <div className="col-span-2">
            <button
              onClick={startScan}
              disabled={loading || !payloadSetId}
              className="w-full bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-4 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all disabled:opacity-50 rounded-md relative overflow-hidden group"
            >
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <Play className="w-4 h-4 relative z-10" /> <span className="relative z-10">Start Scan</span>
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden min-h-0 relative z-10">
        {/* Scan History */}
        <div className="lg:col-span-1 bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg flex flex-col overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <div className="p-4 bg-black/50 border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 flex justify-between items-center shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <span>Scan History</span>
            <RefreshCw className="w-3 h-3 opacity-50 cursor-pointer hover:text-emerald-400 hover:opacity-100 transition-colors" onClick={fetchData} />
          </div>
          <div className="flex-1 overflow-y-auto divide-y divide-emerald-900/20 scrollbar-hide">
            {scans.map(scan => (
              <div 
                key={scan.id} 
                onClick={() => { setSelectedScan(scan.id); fetchResults(scan.id); }}
                className={`p-4 cursor-pointer transition-all relative overflow-hidden group ${selectedScan === scan.id ? 'bg-emerald-950/50 border-l-2 border-emerald-400' : 'hover:bg-emerald-950/30 border-l-2 border-transparent'}`}
              >
                {selectedScan !== scan.id && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
                <div className="flex justify-between items-center mb-2 relative z-10">
                  <span className="text-xs font-mono text-emerald-100/70 group-hover:text-emerald-100 transition-colors truncate max-w-[150px]">{scan.target_url}</span>
                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded-sm border ${scan.status === 'completed' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_5px_rgba(16,185,129,0.2)]' : 'bg-amber-500/10 border-amber-500/30 text-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.2)]'}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="text-[10px] text-emerald-500/50 font-mono relative z-10">
                  {new Date(scan.created_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Scan Results */}
        <div className="lg:col-span-2 bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg flex flex-col overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <div className="p-4 bg-black/50 border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            Results {selectedScan && `- ${results.length} requests processed`}
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-hide">
            {!selectedScan ? (
              <div className="h-full flex flex-col items-center justify-center opacity-30">
                <Terminal className="w-12 h-12 mb-4 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
                <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">Select a scan to view results</p>
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 bg-black/50">
                    <th className="p-4 font-medium">Payload</th>
                    <th className="p-4 font-medium">Status</th>
                    <th className="p-4 font-medium">Length</th>
                    <th className="p-4 font-medium">Anomaly</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-emerald-900/20">
                  {results.map(res => (
                    <tr key={res.id} className={`hover:bg-emerald-950/30 transition-colors group ${res.is_anomaly ? 'bg-red-500/5' : ''}`}>
                      <td className="p-4 text-xs font-mono text-emerald-100/70 group-hover:text-emerald-100 transition-colors max-w-[200px] truncate">{res.payload}</td>
                      <td className="p-4 text-xs font-mono">
                        <span className={`px-2 py-1 rounded-sm border ${res.status >= 200 && res.status < 300 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_5px_rgba(16,185,129,0.2)]' : 'bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_5px_rgba(239,68,68,0.2)]'}`}>
                          {res.status}
                        </span>
                      </td>
                      <td className="p-4 text-xs font-mono text-emerald-500/70">{res.length}</td>
                      <td className="p-4">
                        {res.is_anomaly ? (
                          <span className="flex items-center gap-2 text-[10px] font-mono uppercase text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]">
                            <AlertCircle className="w-3 h-3" /> Detected
                          </span>
                        ) : (
                          <span className="flex items-center gap-2 text-[10px] font-mono uppercase text-emerald-500/50 group-hover:text-emerald-400/70 transition-colors">
                            <CheckCircle2 className="w-3 h-3" /> Normal
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

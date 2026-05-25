import React, { useState } from 'react';
import { Search, Globe, Clock, Download, AlertTriangle, Camera, Grid, List, ExternalLink, Shield } from 'lucide-react';

interface SubdomainResult {
  subdomain: string;
  status: number | null;
  title: string | null;
  ip: string | null;
  contentLength: number | null;
  tech: string[];
  sources: string[];
  screenshotPath: string | null;
}

interface ToolStats {
  found: number;
  source: string;
}

interface EnumResponse {
  domain: string;
  total: number;
  live: number;
  screenshotsTaken: number;
  tools: { subfinder: ToolStats; bruteforce: ToolStats; osint: ToolStats };
  duplicatesRemoved: number;
  subdomains: SubdomainResult[];
}

export default function SubdomainPanel() {
  const [domain, setDomain] = useState('');
  const [wordlistSize, setWordlistSize] = useState(200);
  const [takeScreenshots, setTakeScreenshots] = useState(true);
  const [results, setResults] = useState<SubdomainResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [enumData, setEnumData] = useState<EnumResponse | null>(null);
  const [filter, setFilter] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [statusFilter, setStatusFilter] = useState<'all' | 'live' | 'dead'>('all');

  const handleEnumerate = async () => {
    if (!domain) return;
    setLoading(true);
    setError('');
    setResults([]);
    setEnumData(null);

    try {
      const res = await fetch('/api/subdomains/enumerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, wordlistSize, takeScreenshots }),
      });
      const data: EnumResponse = await res.json();
      if (!res.ok) throw new Error((data as unknown as { error: string }).error);
      setResults(data.subdomains || []);
      setEnumData(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    const header = 'Subdomain\tStatus\tTitle\tTech\tSources';
    const lines = results.map(r =>
      `${r.subdomain}\t${r.status ?? '-'}\t${r.title ?? '-'}\t${r.tech.join(', ') || '-'}\t${r.sources.join(', ')}`
    );
    const blob = new Blob([`${header}\n${lines.join('\n')}`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `subdomains-${domain}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const filtered = results.filter(r => {
    if (statusFilter === 'live' && r.status === null) return false;
    if (statusFilter === 'dead' && r.status !== null) return false;
    if (filter) {
      const q = filter.toLowerCase();
      return r.subdomain.includes(q) || (r.title && r.title.toLowerCase().includes(q)) || r.tech.some(t => t.toLowerCase().includes(q));
    }
    return true;
  });

  const statusColor = (s: number | null) => {
    if (!s) return 'text-gray-500';
    if (s >= 200 && s < 300) return 'text-emerald-400';
    if (s >= 300 && s < 400) return 'text-amber-400';
    return 'text-red-400';
  };

  const statusBg = (s: number | null) => {
    if (!s) return 'border-gray-700/50';
    if (s >= 200 && s < 300) return 'border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.1)]';
    if (s >= 300 && s < 400) return 'border-amber-500/30';
    return 'border-red-500/30';
  };

  return (
    <div className="p-8 max-w-7xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Globe className="w-8 h-8 text-emerald-400" />
          Subdomain Enumeration
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">
          3 Tools • Parallel Execution • Dedup • Screenshots • ROI Targeting
        </p>
      </header>

      {/* Input Controls */}
      <div className="cyber-card p-6 mb-6">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <div className="flex gap-4 items-end relative z-10">
          <div className="flex-1">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Target Domain</label>
            <input type="text" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" className="cyber-input w-full" />
          </div>
          <div className="w-32">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Wordlist Size</label>
            <select value={wordlistSize} onChange={e => setWordlistSize(Number(e.target.value))} className="cyber-input w-full">
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </div>
          <label className="flex items-center gap-2 cursor-pointer pb-2">
            <input type="checkbox" checked={takeScreenshots} onChange={e => setTakeScreenshots(e.target.checked)} className="accent-emerald-500" />
            <Camera className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-500/70">Screenshots</span>
          </label>
          <button onClick={handleEnumerate} disabled={loading || !domain} className="cyber-button px-8">
            {loading ? <Clock className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {loading ? 'Scanning...' : 'Enumerate'}
          </button>
        </div>
        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2 rounded-md">
            <AlertTriangle className="w-4 h-4" /> {error}
          </div>
        )}
      </div>

      {/* Tool Stats */}
      {enumData && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Subfinder', ...enumData.tools.subfinder, color: 'cyan' },
            { label: 'Brute-Force', ...enumData.tools.bruteforce, color: 'emerald' },
            { label: 'OSINT/Wayback', ...enumData.tools.osint, color: 'amber' },
          ].map(t => (
            <div key={t.label} className="cyber-card p-4">
              <div className={`text-xs font-mono uppercase tracking-widest mb-1 text-${t.color}-400/80`}>{t.label}</div>
              <div className={`text-2xl font-bold text-${t.color}-300`}>{t.found}</div>
              <div className="text-[9px] text-emerald-500/50 font-mono mt-1 truncate" title={t.source}>{t.source}</div>
            </div>
          ))}
          <div className="cyber-card p-4">
            <div className="text-xs font-mono uppercase tracking-widest mb-1 text-emerald-400/80">Final Container</div>
            <div className="text-2xl font-bold text-emerald-300">{enumData.total}</div>
            <div className="text-[9px] text-emerald-500/50 font-mono mt-1">
              {enumData.live} live • {enumData.duplicatesRemoved} dupes removed • {enumData.screenshotsTaken} screenshots
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <div className="cyber-card flex flex-col flex-1 min-h-0">
          <div className="p-4 bg-emerald-950/20 border-b border-emerald-900/30 flex justify-between items-center">
            <div className="flex items-center gap-4">
              <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-400/80 flex items-center gap-2">
                <Globe className="w-3 h-3" /> {filtered.length} subdomains
              </span>
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter..." className="cyber-input text-xs px-2 py-1 w-48" />
              <div className="flex gap-1">
                {(['all', 'live', 'dead'] as const).map(s => (
                  <button key={s} onClick={() => setStatusFilter(s)}
                    className={`text-[9px] uppercase font-mono px-2 py-0.5 rounded border transition-all ${statusFilter === s ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'border-emerald-900/30 text-emerald-500/50 hover:text-emerald-400'}`}
                  >{s}</button>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setViewMode('grid')} className={`p-1.5 rounded ${viewMode === 'grid' ? 'bg-emerald-500/20 text-emerald-300' : 'text-emerald-500/50'}`}>
                <Grid className="w-3.5 h-3.5" />
              </button>
              <button onClick={() => setViewMode('table')} className={`p-1.5 rounded ${viewMode === 'table' ? 'bg-emerald-500/20 text-emerald-300' : 'text-emerald-500/50'}`}>
                <List className="w-3.5 h-3.5" />
              </button>
              <button onClick={handleExport} className="p-1.5 bg-black/50 border border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-500/70 hover:text-emerald-300 rounded-md transition-colors" title="Export">
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto scrollbar-hide p-4">
            {viewMode === 'grid' ? (
              <div className="grid grid-cols-3 gap-4">
                {filtered.map((r, i) => (
                  <div key={i} className={`bg-black/40 border rounded-lg overflow-hidden hover:bg-emerald-950/20 transition-colors ${statusBg(r.status)}`}>
                    {r.screenshotPath ? (
                      <img src={r.screenshotPath} alt={r.subdomain} className="w-full h-36 object-cover object-top border-b border-emerald-900/20" loading="lazy" />
                    ) : (
                      <div className="w-full h-36 bg-black/60 flex items-center justify-center border-b border-emerald-900/20">
                        <Globe className="w-8 h-8 text-emerald-900/30" />
                      </div>
                    )}
                    <div className="p-3">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs font-mono text-emerald-100 truncate flex-1" title={r.subdomain}>{r.subdomain}</span>
                        <a href={`https://${r.subdomain}`} target="_blank" rel="noopener noreferrer" className="ml-2 text-emerald-500/50 hover:text-emerald-300">
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className={`text-[10px] font-mono font-bold ${statusColor(r.status)}`}>{r.status ?? 'DEAD'}</span>
                        {r.title && <span className="text-[9px] text-emerald-500/50 truncate flex-1" title={r.title}>{r.title}</span>}
                      </div>
                      {r.tech.length > 0 && (
                        <div className="flex gap-1 mt-2 flex-wrap">
                          {r.tech.map((t, j) => (
                            <span key={j} className="text-[8px] px-1.5 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400/70 rounded font-mono">{t}</span>
                          ))}
                        </div>
                      )}
                      <div className="flex gap-1 mt-2">
                        {r.sources.map((s, j) => (
                          <span key={j} className="text-[8px] px-1 py-0.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400/60 rounded font-mono">{s}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="text-[9px] font-mono uppercase text-emerald-500/60 tracking-widest border-b border-emerald-900/20">
                    <th className="text-left p-3">Subdomain</th>
                    <th className="text-center p-3 w-16">Status</th>
                    <th className="text-left p-3">Title</th>
                    <th className="text-left p-3">Tech</th>
                    <th className="text-left p-3 w-28">Sources</th>
                    <th className="text-center p-3 w-12">Screenshot</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <tr key={i} className="border-b border-emerald-900/10 hover:bg-emerald-900/10 transition-colors">
                      <td className="p-3 text-xs font-mono text-emerald-100">
                        <a href={`https://${r.subdomain}`} target="_blank" rel="noopener noreferrer" className="hover:text-emerald-300 flex items-center gap-1">
                          {r.subdomain} <ExternalLink className="w-2.5 h-2.5 text-emerald-500/40" />
                        </a>
                      </td>
                      <td className={`p-3 text-xs font-mono text-center font-bold ${statusColor(r.status)}`}>{r.status ?? '-'}</td>
                      <td className="p-3 text-xs font-mono text-emerald-100/70 truncate max-w-[200px]">{r.title ?? '-'}</td>
                      <td className="p-3 text-[10px] font-mono text-emerald-400/60">{r.tech.join(', ') || '-'}</td>
                      <td className="p-3">
                        <div className="flex gap-1 flex-wrap">
                          {r.sources.map((s, j) => (
                            <span key={j} className="text-[8px] px-1 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400/60 rounded">{s}</span>
                          ))}
                        </div>
                      </td>
                      <td className="p-3 text-center">
                        {r.screenshotPath ? (
                          <a href={r.screenshotPath} target="_blank" rel="noopener noreferrer">
                            <Camera className="w-3 h-3 text-emerald-400 mx-auto" />
                          </a>
                        ) : <span className="text-gray-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

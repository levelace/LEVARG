import React, { useState } from 'react';
import { Search, Globe, CheckCircle2, XCircle, Clock, Download, AlertTriangle } from 'lucide-react';

interface SubdomainResult {
  subdomain: string;
  status: number | null;
  title: string | null;
  ip: string | null;
}

export default function SubdomainPanel() {
  const [domain, setDomain] = useState('');
  const [wordlistSize, setWordlistSize] = useState(200);
  const [results, setResults] = useState<SubdomainResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState('');

  const handleEnumerate = async () => {
    if (!domain) return;
    setLoading(true);
    setError('');
    setResults([]);

    try {
      const res = await fetch('/api/subdomains/enumerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, wordlistSize }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setResults(data.subdomains || []);
      setTotal(data.total || 0);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    const lines = results.map(r => `${r.subdomain}\t${r.status ?? '-'}\t${r.title ?? '-'}`);
    const content = `Subdomain\tStatus\tTitle\n${lines.join('\n')}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `subdomains-${domain}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const filtered = filter
    ? results.filter(r => r.subdomain.includes(filter) || (r.title && r.title.toLowerCase().includes(filter.toLowerCase())))
    : results;

  const statusColor = (s: number | null) => {
    if (!s) return 'text-gray-500';
    if (s >= 200 && s < 300) return 'text-emerald-400';
    if (s >= 300 && s < 400) return 'text-amber-400';
    return 'text-red-400';
  };

  return (
    <div className="p-8 max-w-5xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Globe className="w-8 h-8 text-emerald-400" />
          Subdomain Enumeration
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Passive (crt.sh) + Active Brute-Force Discovery</p>
      </header>

      <div className="cyber-card p-6 mb-8">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <div className="flex gap-4 items-end relative z-10">
          <div className="flex-1">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Target Domain</label>
            <input
              type="text"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              placeholder="example.com"
              className="cyber-input w-full"
            />
          </div>
          <div className="w-32">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Wordlist Size</label>
            <select
              value={wordlistSize}
              onChange={e => setWordlistSize(Number(e.target.value))}
              className="cyber-input w-full"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </div>
          <button
            onClick={handleEnumerate}
            disabled={loading || !domain}
            className="cyber-button px-8"
          >
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

      {results.length > 0 && (
        <div className="cyber-card flex flex-col flex-1 min-h-0">
          <div className="p-4 bg-emerald-950/20 border-b border-emerald-900/30 flex justify-between items-center">
            <div className="flex items-center gap-4">
              <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-400/80 flex items-center gap-2">
                <Globe className="w-3 h-3" /> Results ({total})
              </span>
              <input
                type="text"
                value={filter}
                onChange={e => setFilter(e.target.value)}
                placeholder="Filter..."
                className="cyber-input text-xs px-2 py-1 w-48"
              />
            </div>
            <button onClick={handleExport} className="p-1.5 bg-black/50 border border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-500/70 hover:text-emerald-300 rounded-md transition-colors" title="Export">
              <Download className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-hide">
            <table className="w-full">
              <thead>
                <tr className="text-[9px] font-mono uppercase text-emerald-500/60 tracking-widest border-b border-emerald-900/20">
                  <th className="text-left p-3">Subdomain</th>
                  <th className="text-center p-3 w-20">Status</th>
                  <th className="text-left p-3">Title</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, i) => (
                  <tr key={i} className="border-b border-emerald-900/10 hover:bg-emerald-900/10 transition-colors">
                    <td className="p-3 text-xs font-mono text-emerald-100">{r.subdomain}</td>
                    <td className={`p-3 text-xs font-mono text-center font-bold ${statusColor(r.status)}`}>{r.status ?? '-'}</td>
                    <td className="p-3 text-xs font-mono text-emerald-100/70 truncate max-w-[300px]">{r.title ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

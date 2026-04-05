import React, { useState, useEffect } from 'react';
import { Search, Import, Plus, Terminal, Filter, Globe, MoreVertical, Send, Activity, Binary } from 'lucide-react';

export default function ReconEngine({ onSendToRepeater, onSendToFuzzer, onSendToEncoder }: any) {
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [importText, setImportText] = useState('');
  const [showImport, setShowImport] = useState(false);

  const fetchEndpoints = async () => {
    const res = await fetch('/api/endpoints');
    const data = await res.json();
    setEndpoints(data);
  };

  useEffect(() => {
    fetchEndpoints();
    const interval = setInterval(fetchEndpoints, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (file.name.endsWith('.json')) {
        try {
          const parsed = JSON.parse(text);
          if (Array.isArray(parsed)) {
            const lines = parsed.map(p => `${p.url || p.endpoint || p} ${p.method || 'GET'} ${p.source || 'import'}`).join('\n');
            setImportText(prev => prev ? prev + '\n' + lines : lines);
            return;
          }
        } catch(e) {}
      }
      setImportText(prev => prev ? prev + '\n' + text : text);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleImport = async () => {
    const lines = importText.split('\n').filter(l => l.trim());
    const newEndpoints = lines.map(line => {
      const parts = line.split(' ');
      return {
        url: parts[0],
        method: parts[1] || 'GET',
        source: parts[2] || 'import'
      };
    });

    await fetch('/api/endpoints/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoints: newEndpoints })
    });

    setImportText('');
    setShowImport(false);
    fetchEndpoints();
  };

  return (
    <div className="p-8 max-w-6xl mx-auto w-full h-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-12 flex justify-between items-end relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
            <Search className="w-8 h-8 text-emerald-400" />
            Recon Engine
          </h2>
          <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Endpoint discovery and asset inventory</p>
        </div>
        <button
          onClick={() => setShowImport(!showImport)}
          className="cyber-button"
        >
          <Import className="w-4 h-4" />
          Import Data
        </button>
      </header>

      {showImport && (
        <div className="cyber-card p-8 mb-8 animate-in fade-in slide-in-from-top-4">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
          <div className="flex justify-between items-center mb-4 relative z-10">
            <h3 className="text-xs font-mono text-emerald-300 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-3 h-3" /> Bulk Import (URL [METHOD] [SOURCE])
            </h3>
            <label className="cursor-pointer bg-black/50 border border-emerald-900/50 text-emerald-400/80 px-3 py-1.5 text-[10px] font-mono uppercase tracking-widest rounded-md hover:bg-emerald-900/30 hover:text-emerald-300 transition-colors">
              Upload File
              <input type="file" accept=".txt,.json,.csv,.md" className="hidden" onChange={handleFileUpload} />
            </label>
          </div>
          <textarea
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="https://api.example.com/v1/user GET katana"
            className="cyber-input w-full h-48 p-4 resize-none"
          />
          <div className="mt-4 flex justify-end gap-4 relative z-10">
            <button onClick={() => setShowImport(false)} className="text-xs font-mono uppercase tracking-widest text-emerald-500/50 hover:text-emerald-400 transition-colors">Cancel</button>
            <button onClick={handleImport} className="bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-4 py-2 text-xs font-mono uppercase tracking-widest rounded-md hover:bg-emerald-500/20 hover:shadow-[0_0_10px_rgba(16,185,129,0.3)] transition-all">Process Import</button>
          </div>
        </div>
      )}

      <div className="cyber-card">
        <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-emerald-500/5 blur-[100px] rounded-full pointer-events-none" />
        
        <div className="grid grid-cols-12 gap-4 p-4 border-b border-emerald-900/30 bg-emerald-950/20 rounded-t-lg text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 relative z-10">
          <div className="col-span-1">Method</div>
          <div className="col-span-6">Endpoint URL</div>
          <div className="col-span-2">Source</div>
          <div className="col-span-2">Discovered</div>
          <div className="col-span-1 text-right">Actions</div>
        </div>
        <div className="divide-y divide-emerald-900/20 relative z-10">
          {endpoints.length === 0 ? (
            <div className="p-20 text-center opacity-50">
              <Globe className="w-12 h-12 mx-auto mb-4 text-emerald-500/30 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
              <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No endpoints discovered yet</p>
            </div>
          ) : (
            endpoints.map((ep) => (
              <div key={ep.id} className="grid grid-cols-12 gap-4 p-4 items-center hover:bg-emerald-900/10 transition-colors group">
                <div className="col-span-1">
                  <span className={cn(
                    "text-[10px] font-mono px-2 py-1 rounded-sm border shadow-[0_0_5px_rgba(0,0,0,0.2)]",
                    ep.method === 'GET' ? "bg-blue-500/10 border-blue-500/30 text-blue-400" :
                    ep.method === 'POST' ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" :
                    "bg-amber-500/10 border-amber-500/30 text-amber-400"
                  )}>
                    {ep.method}
                  </span>
                </div>
                <div className="col-span-6 font-mono text-xs text-emerald-100 truncate group-hover:text-emerald-50 transition-colors">{ep.url}</div>
                <div className="col-span-2 text-[10px] font-mono uppercase text-emerald-500/60">{ep.source}</div>
                <div className="col-span-2 text-[10px] text-emerald-500/50 font-mono">
                  {new Date(ep.created_at).toLocaleDateString()}
                </div>
                <div className="col-span-1 text-right relative group/menu">
                  <button className="p-1 text-emerald-500/50 hover:text-emerald-400 transition-colors">
                    <MoreVertical className="w-4 h-4" />
                  </button>
                  <div className="absolute right-0 top-full mt-1 w-48 bg-black/90 backdrop-blur-xl border border-emerald-900/50 rounded-md shadow-[0_10px_30px_rgba(0,0,0,0.8)] opacity-0 invisible group-hover/menu:opacity-100 group-hover/menu:visible transition-all z-50 flex flex-col py-1">
                    <button onClick={() => onSendToRepeater({ url: ep.url, method: ep.method })} className="px-4 py-2.5 text-xs font-mono text-left text-emerald-400/80 hover:bg-emerald-900/30 hover:text-emerald-300 flex items-center gap-3 transition-colors">
                      <Send className="w-3 h-3"/> Send to Repeater
                    </button>
                    <button onClick={() => onSendToFuzzer(ep.url)} className="px-4 py-2.5 text-xs font-mono text-left text-emerald-400/80 hover:bg-emerald-900/30 hover:text-emerald-300 flex items-center gap-3 transition-colors">
                      <Activity className="w-3 h-3"/> Send to Fuzzer
                    </button>
                    <button onClick={() => onSendToEncoder(ep.url)} className="px-4 py-2.5 text-xs font-mono text-left text-emerald-400/80 hover:bg-emerald-900/30 hover:text-emerald-300 flex items-center gap-3 transition-colors">
                      <Binary className="w-3 h-3"/> Send to Encoder
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(' ');
}

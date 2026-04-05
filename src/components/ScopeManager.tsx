import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Shield, AlertCircle } from 'lucide-react';

export default function ScopeManager() {
  const [scopes, setScopes] = useState<{ id: string, domain: string }[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [error, setError] = useState('');

  const fetchScopes = async () => {
    const res = await fetch('/api/scopes');
    const data = await res.json();
    setScopes(data);
  };

  useEffect(() => {
    fetchScopes();
    const interval = setInterval(fetchScopes, 5000);
    return () => clearInterval(interval);
  }, []);

  const addScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain) return;
    
    const res = await fetch('/api/scopes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: newDomain })
    });

    if (res.ok) {
      setNewDomain('');
      setError('');
      fetchScopes();
    } else {
      setError('Failed to add domain. It might already exist.');
    }
  };

  const deleteScope = async (id: string) => {
    await fetch(`/api/scopes/${id}`, { method: 'DELETE' });
    fetchScopes();
  };

  return (
    <div className="p-8 max-w-4xl mx-auto w-full h-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-12 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Shield className="w-8 h-8 text-emerald-400" />
          Scope Control
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Define and manage approved research boundaries</p>
      </header>

      <div className="cyber-card p-8 mb-8">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <form onSubmit={addScope} className="flex gap-4 relative z-10">
          <div className="flex-1 relative">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="e.g. example.com"
              className="cyber-input w-full"
            />
          </div>
          <button
            type="submit"
            className="cyber-button"
          >
            <Plus className="w-4 h-4" />
            Add Domain
          </button>
        </form>
        {error && (
          <div className="mt-4 flex items-center gap-2 text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/30 p-3 rounded-md shadow-[0_0_10px_rgba(239,68,68,0.2)] relative z-10">
            <AlertCircle className="w-4 h-4" />
            {error}
          </div>
        )}
      </div>

      <div className="space-y-4">
        <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-emerald-500/70 mb-4 flex items-center gap-2">
          <Shield className="w-3 h-3" /> Approved Domains
        </h3>
        {scopes.length === 0 ? (
          <div className="p-12 border border-dashed border-emerald-900/30 bg-black/30 rounded-lg flex flex-col items-center justify-center opacity-50">
            <Shield className="w-8 h-8 mb-2 text-emerald-500/30 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
            <span className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No domains in scope</span>
          </div>
        ) : (
          scopes.map((scope) => (
            <div key={scope.id} className="cyber-card p-4 flex items-center justify-between group hover:border-emerald-500/50 hover:bg-emerald-950/20 transition-all duration-300">
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-4 relative z-10">
                <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/30 rounded-md flex items-center justify-center group-hover:bg-emerald-500/20 group-hover:shadow-[0_0_10px_rgba(16,185,129,0.3)] transition-all">
                  <Shield className="w-5 h-5 text-emerald-400 drop-shadow-[0_0_5px_currentColor]" />
                </div>
                <div>
                  <div className="text-sm font-bold font-mono text-emerald-100 group-hover:text-emerald-50 transition-colors">{scope.domain}</div>
                  <div className="text-[10px] text-emerald-500/50 font-mono uppercase tracking-tighter mt-1">ID: {scope.id.split('-')[0]}</div>
                </div>
              </div>
              <button
                onClick={() => deleteScope(scope.id)}
                className="p-2 opacity-0 group-hover:opacity-100 text-emerald-500/50 hover:text-red-400 hover:bg-red-500/10 hover:shadow-[0_0_10px_rgba(239,68,68,0.2)] rounded-md transition-all relative z-10"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

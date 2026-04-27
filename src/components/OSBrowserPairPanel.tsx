import React, { useEffect, useState } from 'react';
import { Smartphone, Trash2, Plus, RefreshCw, Copy } from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}
interface Token {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  token: string;
  label: string | null;
  last_used_at: string | null;
  use_count: number;
  created_at: string;
}

export default function OSBrowserPairPanel() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [tokens, setTokens] = useState<Token[]>([]);
  const [scopeId, setScopeId] = useState('');
  const [label, setLabel] = useState('');
  const [error, setError] = useState('');

  const load = async () => {
    try {
      const [sc, tk] = await Promise.all([
        fetch('/api/scopes').then((r) => r.json()),
        fetch('/api/extension/tokens').then((r) => r.json()),
      ]);
      setScopes(sc);
      setTokens(tk);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    const i = setInterval(load, 8000);
    return () => clearInterval(i);
  }, []);

  const create = async () => {
    setError('');
    try {
      const res = await fetch('/api/extension/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scopeId, label: label || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Create failed');
      setScopeId('');
      setLabel('');
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Revoke this pairing token? Any extension still using it will fail to ingest.'))
      return;
    await fetch(`/api/extension/tokens/${id}`, { method: 'DELETE' });
    load();
  };

  const ingestUrl = `${window.location.origin}/api/extension/cookies`;

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
          <Smartphone className="w-5 h-5" /> OS-Browser Bridge
        </h2>
        <button
          onClick={load}
          className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300"
        >
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      <p className="text-xs text-zinc-500 mb-4 max-w-3xl">
        Pair your real desktop or mobile browser to LEVARG. After login, captured cookies flow back
        into a new Session bound to the same scope. Three transports: extension (HttpOnly cookies
        included), bookmarklet (mobile-friendly, non-HttpOnly only), or manual paste from DevTools.
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs">
          {error}
        </div>
      )}

      <div className="mb-6 border border-emerald-700/50 rounded p-4 bg-black/60">
        <div className="text-emerald-300 font-bold mb-3 flex items-center gap-2">
          <Plus className="w-4 h-4" /> Generate pairing token
        </div>
        <div className="grid grid-cols-3 gap-3">
          <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
            Scope
            <select
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
              className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
            >
              <option value="">— pick a scope —</option>
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.domain}
                </option>
              ))}
            </select>
          </label>
          <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider col-span-2">
            Label (optional)
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. my laptop / Pixel 8"
              className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
            />
          </label>
        </div>
        <button
          onClick={create}
          disabled={!scopeId}
          className="mt-3 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold disabled:opacity-50"
        >
          Generate
        </button>
        <div className="mt-3 text-[11px] text-zinc-500">
          Ingest URL (paste in extension options): <code className="text-emerald-400">{ingestUrl}</code>
        </div>
      </div>

      {tokens.length === 0 ? (
        <div className="text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded">
          No paired devices yet. Generate a token, then open <code>/pair/&lt;token&gt;</code> on the
          device where you'll log in.
        </div>
      ) : (
        <div className="space-y-2">
          {tokens.map((t) => {
            const pairUrl = `${window.location.origin}/pair/${t.token}`;
            return (
              <div key={t.id} className="border border-emerald-900/40 rounded p-3 bg-black/40">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className="text-emerald-200 font-bold">
                      {t.label ?? '(unlabeled)'} · {t.scope_domain ?? '(scope deleted)'}
                    </div>
                    <div className="text-[11px] text-zinc-500">
                      uses: {t.use_count}
                      {t.last_used_at && ` · last ${new Date(t.last_used_at).toLocaleString()}`}
                    </div>
                  </div>
                  <button
                    onClick={() => remove(t.id)}
                    className="text-xs px-2 py-1 bg-red-900/30 border border-red-800/50 rounded text-red-300 hover:bg-red-900/50 flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" /> Revoke
                  </button>
                </div>
                <div className="grid grid-cols-1 gap-1 text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 w-24">Pair URL:</span>
                    <code className="text-emerald-400 flex-1 break-all">{pairUrl}</code>
                    <button
                      onClick={() => navigator.clipboard.writeText(pairUrl)}
                      className="text-zinc-400 hover:text-emerald-400"
                      title="Copy"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 w-24">Token:</span>
                    <code className="text-emerald-300 flex-1 break-all">{t.token}</code>
                    <button
                      onClick={() => navigator.clipboard.writeText(t.token)}
                      className="text-zinc-400 hover:text-emerald-400"
                      title="Copy"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

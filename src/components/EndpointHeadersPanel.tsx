import React, { useEffect, useState } from 'react';
import { FileCode2, Plus, Trash2, RefreshCw, Save, X, ToggleLeft, ToggleRight, Search } from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}

interface HeaderRule {
  id: string;
  pattern: string;
  name: string;
  value: string;
  scope_id: string | null;
  scope_domain?: string | null;
  description: string | null;
  priority: number;
  enabled: boolean;
  created_at: string;
}

interface FormState {
  pattern: string;
  name: string;
  value: string;
  scopeId: string;
  description: string;
  priority: number;
}

const emptyForm: FormState = { pattern: '', name: '', value: '', scopeId: '', description: '', priority: 0 };

export default function EndpointHeadersPanel() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [rules, setRules] = useState<HeaderRule[]>([]);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [matchUrl, setMatchUrl] = useState('');
  const [matchResults, setMatchResults] = useState<any[] | null>(null);

  const load = async () => {
    try {
      const [sc, hr] = await Promise.all([
        fetch('/api/scopes').then(r => r.json()),
        fetch('/api/endpoint-headers').then(r => r.json()),
      ]);
      setScopes(sc);
      setRules(hr);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    const i = setInterval(load, 10000);
    return () => clearInterval(i);
  }, []);

  const submit = async () => {
    setError('');
    try {
      const url = editingId ? `/api/endpoint-headers/${editingId}` : '/api/endpoint-headers';
      const method = editingId ? 'PATCH' : 'POST';
      const body = editingId
        ? { pattern: form.pattern, name: form.name, value: form.value, description: form.description || null, priority: form.priority }
        : { ...form, scopeId: form.scopeId || undefined, description: form.description || null };
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setForm(emptyForm);
      setEditingId(null);
      setAdding(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Delete this header rule?')) return;
    await fetch(`/api/endpoint-headers/${id}`, { method: 'DELETE' });
    load();
  };

  const toggle = async (id: string) => {
    await fetch(`/api/endpoint-headers/${id}/toggle`, { method: 'POST' });
    load();
  };

  const testMatch = async () => {
    if (!matchUrl) return;
    try {
      const res = await fetch('/api/endpoint-headers/match', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: matchUrl }),
      });
      const data = await res.json();
      setMatchResults(Array.isArray(data) ? data : []);
    } catch (e) {
      setMatchResults([]);
    }
  };

  const startEdit = (r: HeaderRule) => {
    setEditingId(r.id);
    setAdding(true);
    setForm({
      pattern: r.pattern,
      name: r.name,
      value: r.value,
      scopeId: r.scope_id || '',
      description: r.description || '',
      priority: r.priority,
    });
  };

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
            <FileCode2 className="w-5 h-5" /> Per-Endpoint Headers
          </h2>
          <p className="text-[11px] text-zinc-500 mt-1">
            Define custom headers injected into every request matching a URL pattern. Useful for Bearer tokens, CSRF headers, or API keys that vary by endpoint.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          <button
            onClick={() => { setForm(emptyForm); setEditingId(null); setAdding(true); }}
            className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold"
          >
            <Plus className="w-3 h-3" /> Add Rule
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-3 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs">{error}</div>
      )}

      {adding && (
        <div className="mt-4 mb-6 border border-emerald-700/50 rounded p-4 bg-black/60">
          <div className="flex justify-between items-center mb-3">
            <span className="text-emerald-300 font-bold">{editingId ? 'Edit Rule' : 'New Header Rule'}</span>
            <button onClick={() => { setAdding(false); setEditingId(null); }} className="text-zinc-500 hover:text-zinc-300"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              URL Pattern (regex or glob)
              <input
                value={form.pattern}
                onChange={e => setForm({ ...form, pattern: e.target.value })}
                placeholder="https://api.example.com/v2/*"
                className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Header Name
              <input
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Authorization"
                className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider col-span-2">
              Header Value
              <input
                value={form.value}
                onChange={e => setForm({ ...form, value: e.target.value })}
                placeholder="Bearer eyJhbGc..."
                className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
              />
            </label>
            {!editingId && (
              <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
                Scope (optional)
                <select
                  value={form.scopeId}
                  onChange={e => setForm({ ...form, scopeId: e.target.value })}
                  className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none"
                >
                  <option value="">Global (all scopes)</option>
                  {scopes.map(s => <option key={s.id} value={s.id}>{s.domain}</option>)}
                </select>
              </label>
            )}
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Priority
              <input
                type="number"
                value={form.priority}
                onChange={e => setForm({ ...form, priority: parseInt(e.target.value) || 0 })}
                className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider col-span-2">
              Description (optional)
              <input
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="API v2 bearer token"
                className="mt-1 w-full bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
              />
            </label>
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <button onClick={() => { setAdding(false); setEditingId(null); }} className="text-xs text-zinc-500 hover:text-zinc-300 px-3 py-1.5">Cancel</button>
            <button onClick={submit} disabled={!form.pattern || !form.name} className="flex items-center gap-1 text-xs px-4 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold disabled:opacity-40">
              <Save className="w-3 h-3" /> {editingId ? 'Update' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="mt-4 text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded text-center">
          No header rules defined. Click "Add Rule" to inject custom headers into requests matching a URL pattern.
        </div>
      ) : (
        <div className="mt-4 space-y-2">
          {rules.map(r => (
            <div key={r.id} className={`p-3 rounded border bg-black/40 ${r.enabled ? 'border-emerald-700/40' : 'border-zinc-700/30 opacity-50'}`}>
              <div className="flex items-center gap-3">
                <button onClick={() => toggle(r.id)} className="shrink-0">
                  {r.enabled ? <ToggleRight className="w-5 h-5 text-emerald-400" /> : <ToggleLeft className="w-5 h-5 text-zinc-500" />}
                </button>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-emerald-300 font-bold">{r.name}:</span>
                    <span className="text-zinc-300 truncate">{r.value.length > 40 ? r.value.slice(0, 40) + '…' : r.value}</span>
                  </div>
                  <div className="text-[10px] text-zinc-500 mt-0.5">
                    Pattern: <span className="text-amber-400/70">{r.pattern}</span>
                    {r.scope_domain && <span className="ml-2">Scope: {r.scope_domain}</span>}
                    {r.description && <span className="ml-2">— {r.description}</span>}
                    <span className="ml-2">Priority: {r.priority}</span>
                  </div>
                </div>
                <button onClick={() => startEdit(r)} className="text-xs text-zinc-400 hover:text-emerald-300 px-2 py-1">Edit</button>
                <button onClick={() => remove(r.id)} className="text-xs text-red-400/60 hover:text-red-300 px-2 py-1"><Trash2 className="w-3 h-3" /></button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 border-t border-emerald-900/30 pt-4">
        <h3 className="text-xs text-emerald-400/70 uppercase tracking-wider mb-2 flex items-center gap-1">
          <Search className="w-3 h-3" /> URL Match Tester
        </h3>
        <div className="flex gap-2">
          <input
            value={matchUrl}
            onChange={e => setMatchUrl(e.target.value)}
            placeholder="https://api.example.com/v2/users"
            className="flex-1 bg-black/60 border border-emerald-900/50 rounded px-3 py-1.5 text-emerald-100 text-xs outline-none focus:border-emerald-500/70"
          />
          <button onClick={testMatch} disabled={!matchUrl} className="text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300 disabled:opacity-40">
            Test
          </button>
        </div>
        {matchResults !== null && (
          <div className="mt-2 p-3 bg-black/40 border border-emerald-900/30 rounded text-xs">
            {matchResults.length === 0 ? (
              <span className="text-zinc-500">No rules match this URL.</span>
            ) : (
              matchResults.map((r: any, i: number) => (
                <div key={i} className="py-1 border-b border-emerald-900/20 last:border-0">
                  <span className="text-emerald-300">{r.name}</span>: <span className="text-zinc-300">{r.value}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

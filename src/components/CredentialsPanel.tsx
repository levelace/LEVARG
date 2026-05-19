import React, { useEffect, useState } from 'react';
import { Lock, Trash2, Plus, RefreshCw, Save, X } from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}

interface Credential {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  label: string;
  username: string;
  password?: string;
  has_password: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface FormState {
  scopeId: string;
  label: string;
  username: string;
  password: string;
  notes: string;
}

const empty: FormState = { scopeId: '', label: '', username: '', password: '', notes: '' };

export default function CredentialsPanel() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [form, setForm] = useState<FormState>(empty);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [adding, setAdding] = useState(false);

  const load = async () => {
    try {
      const [sc, cr] = await Promise.all([
        fetch('/api/scopes').then((r) => r.json()),
        fetch('/api/credentials').then((r) => r.json()),
      ]);
      setScopes(sc);
      setCreds(cr);
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

  const submit = async () => {
    setError('');
    try {
      const url = editingId ? `/api/credentials/${editingId}` : '/api/credentials';
      const method = editingId ? 'PATCH' : 'POST';
      const body = editingId
        ? {
            label: form.label,
            username: form.username,
            password: form.password || undefined,
            notes: form.notes || null,
          }
        : { ...form, notes: form.notes || null };
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Request failed');
      setForm(empty);
      setEditingId(null);
      setAdding(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Delete this credential? Any auth-flows linked to it will be unlinked.')) return;
    await fetch(`/api/credentials/${id}`, { method: 'DELETE' });
    load();
  };

  const startEdit = (c: Credential) => {
    setEditingId(c.id);
    setAdding(true);
    setForm({
      scopeId: c.scope_id,
      label: c.label,
      username: c.username,
      password: '',
      notes: c.notes ?? '',
    });
  };

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
          <Lock className="w-5 h-5" /> Stored Credentials
        </h2>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300"
          >
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          <button
            onClick={() => {
              setForm({ ...empty, scopeId: scopes[0]?.id ?? '' });
              setEditingId(null);
              setAdding(true);
            }}
            className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold"
          >
            <Plus className="w-3 h-3" /> Add
          </button>
        </div>
      </div>

      <p className="text-xs text-zinc-500 mb-4 max-w-3xl">
        Username + password pairs bound 1:1 to a Scope. Used by auth-flows to fill in-scope login
        forms. Stored plaintext at rest (matches Burp/ZAP project files); the password is redacted in
        list views and never returned to the UI. Credentials for scope A can never be replayed against
        scope B.
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs">
          {error}
        </div>
      )}

      {adding && (
        <div className="mb-6 border border-emerald-700/50 rounded p-4 bg-black/60">
          <div className="text-emerald-300 font-bold mb-3">
            {editingId ? 'Edit credential' : 'Add credential'}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Scope
              <select
                disabled={!!editingId}
                value={form.scopeId}
                onChange={(e) => setForm({ ...form, scopeId: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100 disabled:opacity-50"
              >
                <option value="">— pick a scope —</option>
                {scopes.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.domain}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Label
              <input
                value={form.label}
                onChange={(e) => setForm({ ...form, label: e.target.value })}
                placeholder="e.g. tester-A"
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Username / email
              <input
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Password {editingId && <span className="text-zinc-500">(leave blank to keep current)</span>}
              <input
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider col-span-2">
              Notes
              <input
                value={form.notes}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
            </label>
          </div>
          <div className="mt-3 flex gap-2">
            <button
              onClick={submit}
              className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold"
            >
              <Save className="w-3 h-3" /> Save
            </button>
            <button
              onClick={() => {
                setAdding(false);
                setEditingId(null);
                setForm(empty);
              }}
              className="flex items-center gap-1 text-xs px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded text-zinc-300"
            >
              <X className="w-3 h-3" /> Cancel
            </button>
          </div>
        </div>
      )}

      {creds.length === 0 ? (
        <div className="text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded">
          No credentials yet. Add one to bind a username + password to a scope.
        </div>
      ) : (
        <div className="space-y-2">
          {creds.map((c) => (
            <div
              key={c.id}
              className="border border-emerald-900/40 rounded p-3 bg-black/40 flex items-center justify-between"
            >
              <div>
                <div className="text-emerald-200 font-bold">{c.label}</div>
                <div className="text-[11px] text-zinc-500">
                  Scope: <span className="text-emerald-400">{c.scope_domain ?? '(deleted)'}</span> ·
                  user: <span className="text-emerald-300">{c.username}</span> · password{' '}
                  {c.has_password ? (
                    <span className="text-emerald-500">stored</span>
                  ) : (
                    <span className="text-amber-400">missing</span>
                  )}
                  {c.notes && <span> · {c.notes}</span>}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => startEdit(c)}
                  className="text-xs px-2 py-1 bg-zinc-900 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800"
                >
                  Edit
                </button>
                <button
                  onClick={() => remove(c.id)}
                  className="text-xs px-2 py-1 bg-red-900/30 border border-red-800/50 rounded text-red-300 hover:bg-red-900/50 flex items-center gap-1"
                >
                  <Trash2 className="w-3 h-3" /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { KeyRound, Trash2, RefreshCw, Eye, EyeOff } from 'lucide-react';

interface Session {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  name: string;
  cookies: { name: string; domain?: string }[];
  headers: Record<string, string>;
  storage: { localStorage?: Record<string, string>; sessionStorage?: Record<string, string> };
  user_agent: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export default function SessionsPanel() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [error, setError] = useState('');
  const [reveal, setReveal] = useState<Record<string, boolean>>({});

  const load = async () => {
    try {
      const res = await fetch('/api/sessions');
      if (!res.ok) throw new Error('Failed to load sessions');
      const data: Session[] = await res.json();
      setSessions(data);
      setError('');
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    load();
    const i = setInterval(load, 5000);
    return () => clearInterval(i);
  }, []);

  const remove = async (id: string) => {
    if (!confirm('Delete this session? Authenticated tests will lose access to its cookies.')) return;
    await fetch(`/api/sessions/${id}`, { method: 'DELETE' });
    load();
  };

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
          <KeyRound className="w-5 h-5" /> Authenticated Sessions
        </h2>
        <button
          onClick={load}
          className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300"
        >
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      <p className="text-xs text-zinc-500 mb-4 max-w-3xl">
        Each Session is bound to exactly one Scope. Captured via the built-in browser after a successful login;
        the resulting cookies, storage, and User-Agent permeate every test surface (Request Lab, Scanner,
        Stack Gap, Auto-Hunter, Flow Runner) when selected — and refuse to fire against any host outside the
        bound scope.
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs">
          {error}
        </div>
      )}

      {sessions.length === 0 ? (
        <div className="text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded">
          No sessions yet. Open the Built-in Browser, log in to a scoped target, then click "Save as
          Session".
        </div>
      ) : (
        <div className="space-y-3">
          {sessions.map(s => (
            <div key={s.id} className="border border-emerald-900/40 rounded p-3 bg-black/40">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-emerald-200 font-bold">{s.name}</div>
                  <div className="text-[11px] text-zinc-500">
                    Scope: <span className="text-emerald-400">{s.scope_domain ?? '(deleted)'}</span> ·{' '}
                    cookies: {s.cookies.length} · localStorage:{' '}
                    {Object.keys(s.storage.localStorage ?? {}).length} · sessionStorage:{' '}
                    {Object.keys(s.storage.sessionStorage ?? {}).length} · updated {new Date(s.updated_at).toLocaleString()}
                  </div>
                  {s.notes && <div className="text-[11px] text-zinc-400 mt-1">{s.notes}</div>}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setReveal(r => ({ ...r, [s.id]: !r[s.id] }))}
                    className="text-xs px-2 py-1 bg-zinc-900 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800 flex items-center gap-1"
                  >
                    {reveal[s.id] ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {reveal[s.id] ? 'Hide' : 'Inspect'}
                  </button>
                  <button
                    onClick={() => remove(s.id)}
                    className="text-xs px-2 py-1 bg-red-900/30 border border-red-800/50 rounded text-red-300 hover:bg-red-900/50 flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" /> Delete
                  </button>
                </div>
              </div>
              {reveal[s.id] && (
                <pre className="mt-3 p-2 bg-black/60 border border-emerald-900/30 rounded text-[10px] text-emerald-200 overflow-auto max-h-64">
{JSON.stringify(
  {
    cookies: s.cookies.map(c => ({ name: c.name, domain: c.domain })),
    headers: s.headers,
    user_agent: s.user_agent,
    storage_keys: {
      localStorage: Object.keys(s.storage.localStorage ?? {}),
      sessionStorage: Object.keys(s.storage.sessionStorage ?? {}),
    },
  },
  null,
  2,
)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

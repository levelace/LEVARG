import React, { useEffect, useState } from 'react';
import {
  Globe,
  KeyRound,
  Lock,
  LogIn,
  Smartphone,
  Shield,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}
interface Session {
  id: string;
  scope_id: string;
  name: string;
}
interface Credential {
  id: string;
  scope_id: string;
  label: string;
  username: string;
}
interface AuthFlow {
  id: string;
  scope_id: string;
  name: string;
  is_default: boolean;
  trigger_mode: string;
  last_status: 'ok' | 'error' | null;
  success_count: number;
  fail_count: number;
}
interface ExtToken {
  id: string;
  scope_id: string;
  label: string | null;
  use_count: number;
}

type Nav =
  | 'browser'
  | 'sessions'
  | 'credentials'
  | 'authflows'
  | 'osbridge'
  | 'scope';

interface Props {
  onNavigate: (view: Nav) => void;
}

const fetchJson = <T,>(url: string): Promise<T> =>
  fetch(url).then((r) => (r.ok ? (r.json() as Promise<T>) : ([] as unknown as T)));

export default function IdentityDashboard({ onNavigate }: Props) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [flows, setFlows] = useState<AuthFlow[]>([]);
  const [tokens, setTokens] = useState<ExtToken[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [sc, ss, cr, fl, tk] = await Promise.all([
        fetchJson<Scope[]>('/api/scopes'),
        fetchJson<Session[]>('/api/sessions'),
        fetchJson<Credential[]>('/api/credentials'),
        fetchJson<AuthFlow[]>('/api/auth-flows'),
        fetchJson<ExtToken[]>('/api/extension/tokens'),
      ]);
      setScopes(sc);
      setSessions(ss);
      setCreds(cr);
      setFlows(fl);
      setTokens(tk);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const i = setInterval(load, 10000);
    return () => clearInterval(i);
  }, []);

  const byScope = (scopeId: string) => ({
    sessions: sessions.filter((s) => s.scope_id === scopeId).length,
    creds: creds.filter((c) => c.scope_id === scopeId).length,
    flows: flows.filter((f) => f.scope_id === scopeId).length,
    tokens: tokens.filter((t) => t.scope_id === scopeId).length,
    defaultFlow: flows.find((f) => f.scope_id === scopeId && f.is_default) ?? null,
  });

  const cards: Array<{
    id: Nav;
    label: string;
    icon: typeof Globe;
    count: number;
    sub: string;
    color: string;
  }> = [
    {
      id: 'browser',
      label: 'Built-in Browser',
      icon: Globe,
      count: 0,
      sub: 'Headed Chromium · per-scope profile',
      color: 'cyan',
    },
    {
      id: 'sessions',
      label: 'Auth Sessions',
      icon: KeyRound,
      count: sessions.length,
      sub: 'Cookie + header bundles',
      color: 'amber',
    },
    {
      id: 'credentials',
      label: 'Credentials',
      icon: Lock,
      count: creds.length,
      sub: 'Username + password (plaintext)',
      color: 'emerald',
    },
    {
      id: 'authflows',
      label: 'Auth Flows',
      icon: LogIn,
      count: flows.length,
      sub: 'Replayable login macros',
      color: 'fuchsia',
    },
    {
      id: 'osbridge',
      label: 'OS Browser Bridge',
      icon: Smartphone,
      count: tokens.length,
      sub: 'Pair external desktop / mobile browser',
      color: 'sky',
    },
  ];

  const colorClass = (c: string) => {
    switch (c) {
      case 'cyan':
        return 'border-cyan-700/40 hover:border-cyan-500/70 text-cyan-300';
      case 'amber':
        return 'border-amber-700/40 hover:border-amber-500/70 text-amber-300';
      case 'fuchsia':
        return 'border-fuchsia-700/40 hover:border-fuchsia-500/70 text-fuchsia-300';
      case 'sky':
        return 'border-sky-700/40 hover:border-sky-500/70 text-sky-300';
      default:
        return 'border-emerald-700/40 hover:border-emerald-500/70 text-emerald-300';
    }
  };

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
            <Shield className="w-5 h-5" /> Auth &amp; Identity
          </h2>
          <p className="text-[11px] text-zinc-500 mt-1">
            One-stop view of every authentication surface bound to your scopes. Click any card to
            jump into its panel.
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300 disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mt-5">
        {cards.map((c) => {
          const Icon = c.icon;
          return (
            <button
              key={c.id}
              onClick={() => onNavigate(c.id)}
              className={`text-left border rounded-lg p-4 bg-black/50 backdrop-blur transition-all ${colorClass(
                c.color,
              )}`}
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-4 h-4" />
                <span className="text-[11px] uppercase tracking-wider opacity-80">{c.label}</span>
              </div>
              <div className="text-2xl font-bold tabular-nums">{c.count || (c.id === 'browser' ? '—' : 0)}</div>
              <div className="text-[10px] text-zinc-500 mt-1 leading-tight">{c.sub}</div>
              <div className="text-[10px] mt-3 flex items-center gap-1 opacity-70">
                Open <ChevronRight className="w-3 h-3" />
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-8">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-emerald-300 font-bold flex items-center gap-2">
            <Shield className="w-4 h-4" /> Per-scope rollup
          </h3>
          <button
            onClick={() => onNavigate('scope')}
            className="text-[11px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
          >
            Manage scopes <ChevronRight className="w-3 h-3" />
          </button>
        </div>
        {scopes.length === 0 ? (
          <div className="text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded">
            No scopes registered. Add one in Scope Control to begin authenticated testing.
          </div>
        ) : (
          <div className="border border-emerald-900/30 rounded-lg overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-emerald-950/40 text-emerald-400/80">
                <tr>
                  <th className="text-left px-3 py-2 font-mono uppercase tracking-wider">Scope</th>
                  <th className="text-right px-3 py-2 font-mono uppercase tracking-wider">Sessions</th>
                  <th className="text-right px-3 py-2 font-mono uppercase tracking-wider">Creds</th>
                  <th className="text-right px-3 py-2 font-mono uppercase tracking-wider">Flows</th>
                  <th className="text-left px-3 py-2 font-mono uppercase tracking-wider">Default flow</th>
                  <th className="text-right px-3 py-2 font-mono uppercase tracking-wider">Devices</th>
                </tr>
              </thead>
              <tbody>
                {scopes.map((s) => {
                  const r = byScope(s.id);
                  return (
                    <tr
                      key={s.id}
                      className="border-t border-emerald-900/20 hover:bg-emerald-950/20"
                    >
                      <td className="px-3 py-2 text-emerald-200">{s.domain}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{r.sessions}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{r.creds}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{r.flows}</td>
                      <td className="px-3 py-2 text-zinc-400">
                        {r.defaultFlow ? (
                          <span className="text-emerald-300">{r.defaultFlow.name}</span>
                        ) : (
                          <span className="text-zinc-600 italic">none</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums">{r.tokens}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-6 p-4 border border-emerald-900/30 rounded-lg bg-black/30">
        <h3 className="text-emerald-300 font-bold mb-2 text-sm">Authentication pipeline</h3>
        <ol className="text-[11px] text-zinc-400 space-y-1.5 list-decimal list-inside">
          <li>
            Register a target in <span className="text-emerald-300">Scope Control</span> — every
            credential and flow is bound 1:1 to a scope.
          </li>
          <li>
            Stash a username/password pair in <span className="text-emerald-300">Credentials</span>{' '}
            and reference it from an <span className="text-emerald-300">Auth Flow</span> via{' '}
            <code>${'${USERNAME}'}</code> / <code>${'${PASSWORD}'}</code>.
          </li>
          <li>
            Mark the flow <span className="text-emerald-300">default</span> so it preflights on
            hunt start. Set trigger to <code>on_401</code> to auto-refresh mid-hunt when a request
            hits a login redirect.
          </li>
          <li>
            For SSO / MFA targets, pair your real device via{' '}
            <span className="text-emerald-300">OS Browser Bridge</span>; cookies flow back into a
            fresh Session bound to the same scope.
          </li>
          <li>
            Pick the resulting Session in any test phase — Auto-Hunter, Scanner, Request Lab, Stack
            Gap, Flows — and authentication permeates every outbound in-scope request.
          </li>
        </ol>
      </div>
    </div>
  );
}

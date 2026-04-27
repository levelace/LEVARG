import React, { useState, useEffect } from 'react';
import {
  Globe, Play, Square, Save, Pause, AlertCircle, Activity, Eye, EyeOff,
} from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}

interface BrowserStatus {
  running: boolean;
  scopeId: string | null;
  scopeDomain: string | null;
  headless: boolean;
  capturing: boolean;
  capturedRequests: number;
  outOfScopeDropped: number;
  pages: { url: string; title: string }[];
}

const EMPTY_STATUS: BrowserStatus = {
  running: false,
  scopeId: null,
  scopeDomain: null,
  headless: false,
  capturing: true,
  capturedRequests: 0,
  outOfScopeDropped: 0,
  pages: [],
};

export default function BrowserPanel() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [status, setStatus] = useState<BrowserStatus>(EMPTY_STATUS);
  const [selectedScopeId, setSelectedScopeId] = useState<string>('');
  const [headless, setHeadless] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [sessionName, setSessionName] = useState('');
  const [sessionNotes, setSessionNotes] = useState('');
  const [savedMessage, setSavedMessage] = useState('');

  const fetchAll = async () => {
    try {
      const [scopesRes, statusRes] = await Promise.all([
        fetch('/api/scopes'),
        fetch('/api/browser/status'),
      ]);
      const scopesData: Scope[] = await scopesRes.json();
      const statusData: BrowserStatus = await statusRes.json();
      setScopes(scopesData);
      setStatus(statusData);
      if (!selectedScopeId && scopesData.length > 0) {
        setSelectedScopeId(scopesData[0].id);
      }
    } catch (err) {
      // network errors are expected during navigation; ignore
    }
  };

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 2500);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const launch = async () => {
    if (!selectedScopeId) {
      setError('Pick a scope to bind the browser to before launching.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/browser/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scopeId: selectedScopeId, headless }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Launch failed');
      setStatus(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const close = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/browser/close', { method: 'POST' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Close failed');
      }
      await fetchAll();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleCapture = async () => {
    try {
      await fetch('/api/browser/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !status.capturing }),
      });
      fetchAll();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const saveAsSession = async () => {
    if (!sessionName.trim()) {
      setError('Session name is required.');
      return;
    }
    setBusy(true);
    setError('');
    setSavedMessage('');
    try {
      const res = await fetch('/api/browser/save-as-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sessionName.trim(), notes: sessionNotes || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setSavedMessage(`Saved as session "${sessionName.trim()}" (id: ${data.sessionId.slice(0, 8)}\u2026)`);
      setSessionName('');
      setSessionNotes('');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="p-8 max-w-5xl mx-auto w-full h-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-12 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Globe className="w-8 h-8 text-emerald-400" />
          Authenticated Browser
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">
          Drive a real Chromium under stealth. Capture in-scope traffic. Save state as a Session.
        </p>
      </header>

      {error && (
        <div className="mb-6 flex items-center gap-2 text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/30 p-3 rounded-md">
          <AlertCircle className="w-4 h-4" />
          {error}
        </div>
      )}
      {savedMessage && (
        <div className="mb-6 flex items-center gap-2 text-emerald-300 text-xs font-mono bg-emerald-500/10 border border-emerald-500/30 p-3 rounded-md">
          <Save className="w-4 h-4" />
          {savedMessage}
        </div>
      )}

      {/* Launch panel */}
      <div className="cyber-card p-6 mb-6 relative">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-emerald-500/70 mb-4">
          Launch Configuration
        </h3>
        <div className="grid grid-cols-12 gap-4 items-end">
          <div className="col-span-6">
            <label className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-1 block">
              Bound Scope
            </label>
            <select
              value={selectedScopeId}
              onChange={(e) => setSelectedScopeId(e.target.value)}
              disabled={status.running}
              className="cyber-input w-full"
            >
              {scopes.length === 0 && <option value="">No scopes — add one in Scope Control</option>}
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>{s.domain}</option>
              ))}
            </select>
          </div>
          <div className="col-span-3">
            <label className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-1 block">
              Mode
            </label>
            <button
              type="button"
              onClick={() => setHeadless((h) => !h)}
              disabled={status.running}
              className="cyber-input w-full flex items-center justify-center gap-2"
            >
              {headless ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              {headless ? 'Headless' : 'Headed'}
            </button>
          </div>
          <div className="col-span-3">
            {status.running ? (
              <button
                type="button"
                onClick={close}
                disabled={busy}
                className="cyber-button w-full bg-red-500/10 hover:bg-red-500/20 border-red-500/30"
              >
                <Square className="w-4 h-4" />
                Close
              </button>
            ) : (
              <button
                type="button"
                onClick={launch}
                disabled={busy || scopes.length === 0}
                className="cyber-button w-full"
              >
                <Play className="w-4 h-4" />
                Launch
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Status panel */}
      <div className="cyber-card p-6 mb-6 relative">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-emerald-500/70">
            Live Status
          </h3>
          <button
            type="button"
            onClick={toggleCapture}
            disabled={!status.running}
            className="text-[10px] font-mono uppercase tracking-widest px-3 py-1 rounded border border-emerald-500/30 hover:bg-emerald-500/10 disabled:opacity-30 flex items-center gap-2"
          >
            {status.capturing ? <Pause className="w-3 h-3" /> : <Activity className="w-3 h-3" />}
            {status.capturing ? 'Pause Capture' : 'Resume Capture'}
          </button>
        </div>
        <div className="grid grid-cols-4 gap-4">
          <StatBlock label="Running" value={status.running ? 'YES' : 'NO'} accent={status.running ? 'green' : 'gray'} />
          <StatBlock label="Bound Scope" value={status.scopeDomain || '—'} accent="green" />
          <StatBlock label="Captured" value={String(status.capturedRequests)} accent="green" />
          <StatBlock
            label="Out of Scope (Dropped)"
            value={String(status.outOfScopeDropped)}
            accent={status.outOfScopeDropped > 0 ? 'amber' : 'gray'}
          />
        </div>
        {status.pages.length > 0 && (
          <div className="mt-4">
            <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Open Pages</div>
            <div className="space-y-1 max-h-48 overflow-y-auto scrollbar-hide">
              {status.pages.map((p, i) => (
                <div key={i} className="text-xs font-mono text-emerald-200/80 truncate border-l-2 border-emerald-500/30 pl-2">
                  {p.title || '(untitled)'} <span className="text-emerald-500/50">— {p.url}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Save as Session */}
      <div className="cyber-card p-6 relative">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-emerald-500/70 mb-4">
          Snapshot Browser State as Session
        </h3>
        <p className="text-xs text-emerald-200/60 mb-4 font-mono leading-relaxed">
          Captures cookies + localStorage / sessionStorage for in-scope hosts only. Cookies bound to identity-provider domains
          (e.g., google.com, okta.com) are excluded — only material for {status.scopeDomain || 'the active scope'} is saved.
        </p>
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-4">
            <label className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-1 block">
              Session Name
            </label>
            <input
              type="text"
              value={sessionName}
              onChange={(e) => setSessionName(e.target.value)}
              placeholder="e.g. admin, user-A"
              className="cyber-input w-full"
            />
          </div>
          <div className="col-span-6">
            <label className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-1 block">
              Notes (optional)
            </label>
            <input
              type="text"
              value={sessionNotes}
              onChange={(e) => setSessionNotes(e.target.value)}
              placeholder="role / permissions / what this account can do"
              className="cyber-input w-full"
            />
          </div>
          <div className="col-span-2 flex items-end">
            <button
              type="button"
              onClick={saveAsSession}
              disabled={busy || !status.running}
              className="cyber-button w-full"
            >
              <Save className="w-4 h-4" />
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatBlock({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: 'green' | 'amber' | 'gray';
}) {
  const colorMap = {
    green: 'text-emerald-300 border-emerald-500/30',
    amber: 'text-amber-300 border-amber-500/30',
    gray: 'text-zinc-400 border-zinc-500/30',
  } as const;
  return (
    <div className={`border ${colorMap[accent]} bg-black/30 rounded-md p-3`}>
      <div className="text-[9px] font-mono uppercase tracking-widest text-emerald-500/60 mb-1">{label}</div>
      <div className={`text-lg font-mono font-bold ${colorMap[accent]} truncate`}>{value}</div>
    </div>
  );
}

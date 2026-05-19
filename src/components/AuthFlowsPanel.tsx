import React, { useEffect, useState } from 'react';
import { LogIn, Trash2, Plus, RefreshCw, Save, X, Play, Wand2 } from 'lucide-react';

interface Scope {
  id: string;
  domain: string;
}
interface Credential {
  id: string;
  scope_id: string;
  label: string;
  username: string;
}

type StepType =
  | 'goto'
  | 'fill'
  | 'click'
  | 'press'
  | 'waitForSelector'
  | 'waitForUrl'
  | 'sleep';

interface FlowStep {
  type: StepType;
  url?: string;
  selector?: string;
  value?: string;
  secret?: boolean;
  key?: 'Enter' | 'Tab' | 'Escape';
  urlContains?: string;
  timeout?: number;
  ms?: number;
  waitFor?: 'load' | 'domcontentloaded' | 'networkidle0' | 'networkidle2';
}

interface AuthFlow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  credential_id: string | null;
  name: string;
  steps: FlowStep[];
  trigger_mode: string;
  is_default: boolean;
  last_run_at: string | null;
  last_status: 'ok' | 'error' | null;
  last_error: string | null;
  success_count: number;
  fail_count: number;
}

interface FormState {
  scopeId: string;
  name: string;
  credentialId: string;
  triggerMode: string;
  isDefault: boolean;
  steps: FlowStep[];
  detectUrl: string;
}

const empty: FormState = {
  scopeId: '',
  name: '',
  credentialId: '',
  triggerMode: 'preflight',
  isDefault: false,
  steps: [],
  detectUrl: '',
};

export default function AuthFlowsPanel() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [flows, setFlows] = useState<AuthFlow[]>([]);
  const [form, setForm] = useState<FormState>(empty);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [running, setRunning] = useState<string | null>(null);

  const load = async () => {
    try {
      const [sc, cr, fl] = await Promise.all([
        fetch('/api/scopes').then((r) => r.json()),
        fetch('/api/credentials').then((r) => r.json()),
        fetch('/api/auth-flows').then((r) => r.json()),
      ]);
      setScopes(sc);
      setCreds(cr);
      setFlows(fl);
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
      const url = editingId ? `/api/auth-flows/${editingId}` : '/api/auth-flows';
      const method = editingId ? 'PATCH' : 'POST';
      const body = editingId
        ? {
            name: form.name,
            steps: form.steps,
            credentialId: form.credentialId || null,
            triggerMode: form.triggerMode,
            isDefault: form.isDefault,
          }
        : {
            scopeId: form.scopeId,
            name: form.name,
            steps: form.steps,
            credentialId: form.credentialId || null,
            triggerMode: form.triggerMode,
            isDefault: form.isDefault,
          };
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setForm(empty);
      setEditingId(null);
      setAdding(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const detect = async () => {
    setError('');
    setInfo('');
    if (!form.detectUrl) {
      setError('Enter a URL to auto-detect a login form');
      return;
    }
    try {
      const res = await fetch('/api/auth-flows/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: form.detectUrl }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Detect failed');
      if (!data.detected) {
        setInfo('No login form detected on that URL.');
        return;
      }
      setForm({ ...form, steps: data.suggestedSteps as FlowStep[] });
      setInfo(
        `Detected ${data.detected.passwordSelector ? 'password field' : 'form'} ` +
          `(form: ${data.detected.formSelector}). Steps populated.`,
      );
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Delete this auth-flow?')) return;
    await fetch(`/api/auth-flows/${id}`, { method: 'DELETE' });
    load();
  };

  const run = async (id: string) => {
    setRunning(id);
    setError('');
    setInfo('');
    try {
      const res = await fetch(`/api/auth-flows/${id}/run`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Run failed');
      if (!data.ok) {
        setError(`Replay failed: ${data.error}`);
      } else {
        setInfo(`Replay ok. New session: ${data.sessionId}`);
      }
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(null);
    }
  };

  const updateStep = (i: number, patch: Partial<FlowStep>) => {
    const next = form.steps.slice();
    next[i] = { ...next[i], ...patch };
    setForm({ ...form, steps: next });
  };
  const removeStep = (i: number) => {
    setForm({ ...form, steps: form.steps.filter((_, j) => j !== i) });
  };
  const addStep = (type: StepType) => {
    const seed: FlowStep = { type };
    if (type === 'goto') seed.url = '';
    if (type === 'fill') {
      seed.selector = '';
      seed.value = '';
    }
    if (type === 'click') seed.selector = '';
    if (type === 'press') seed.key = 'Enter';
    if (type === 'waitForSelector') seed.selector = '';
    if (type === 'waitForUrl') seed.urlContains = '';
    if (type === 'sleep') seed.ms = 1000;
    setForm({ ...form, steps: [...form.steps, seed] });
  };

  const startEdit = (f: AuthFlow) => {
    setEditingId(f.id);
    setAdding(true);
    setForm({
      scopeId: f.scope_id,
      name: f.name,
      credentialId: f.credential_id ?? '',
      triggerMode: f.trigger_mode,
      isDefault: f.is_default,
      steps: f.steps,
      detectUrl: '',
    });
  };

  const credsForScope = creds.filter((c) => !form.scopeId || c.scope_id === form.scopeId);

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
          <LogIn className="w-5 h-5" /> Auth Flows
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
            <Plus className="w-3 h-3" /> New flow
          </button>
        </div>
      </div>

      <p className="text-xs text-zinc-500 mb-4 max-w-3xl">
        Replayable login macros bound to a scope. Steps fire only against in-scope hosts — provider
        OAuth pages (accounts.google.com etc.) are refused at runtime, so credentials are never
        typed onto a third-party domain. On each successful replay, the resulting cookie jar is
        captured into a new Session.
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs">
          {error}
        </div>
      )}
      {info && (
        <div className="mb-4 p-3 bg-emerald-900/20 border border-emerald-800/50 rounded text-emerald-300 text-xs">
          {info}
        </div>
      )}

      {adding && (
        <div className="mb-6 border border-emerald-700/50 rounded p-4 bg-black/60 space-y-3">
          <div className="text-emerald-300 font-bold">{editingId ? 'Edit flow' : 'New flow'}</div>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Scope
              <select
                disabled={!!editingId}
                value={form.scopeId}
                onChange={(e) => setForm({ ...form, scopeId: e.target.value, credentialId: '' })}
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
              Name
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Linked credential
              <select
                value={form.credentialId}
                onChange={(e) => setForm({ ...form, credentialId: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              >
                <option value="">— none —</option>
                {credsForScope.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label} ({c.username})
                  </option>
                ))}
              </select>
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Trigger
              <select
                value={form.triggerMode}
                onChange={(e) => setForm({ ...form, triggerMode: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              >
                <option value="preflight">preflight (run on hunt start)</option>
                <option value="on_401">on_401 (auto-refresh on 401 / login redirect)</option>
                <option value="discovery">discovery (run when login form is detected)</option>
                <option value="all">all triggers</option>
                <option value="manual">manual (only via Run button)</option>
              </select>
            </label>
          </div>
          <label className="flex items-center gap-2 text-[11px] text-emerald-400/70 uppercase tracking-wider">
            <input
              type="checkbox"
              checked={form.isDefault}
              onChange={(e) => setForm({ ...form, isDefault: e.target.checked })}
            />
            Default flow for this scope (auto-selected when starting an auth-flow-less hunt)
          </label>

          <div className="border border-emerald-900/40 rounded p-3 bg-black/40">
            <div className="text-[11px] text-emerald-400/80 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Wand2 className="w-3 h-3" /> Auto-detect from URL
            </div>
            <div className="flex gap-2">
              <input
                value={form.detectUrl}
                onChange={(e) => setForm({ ...form, detectUrl: e.target.value })}
                placeholder="https://target.example.com/login"
                className="flex-1 bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100"
              />
              <button
                onClick={detect}
                className="text-xs px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold"
              >
                Detect
              </button>
            </div>
            <div className="text-[10px] text-zinc-500 mt-1">
              Fetches the URL through LEVARG (in-scope only) and pre-populates fill/click steps from
              the form's selectors. Templates: <code>${'${USERNAME}'}</code>{' '}
              <code>${'${PASSWORD}'}</code> are replaced from the linked credential at run time.
            </div>
          </div>

          <div className="border border-emerald-900/40 rounded p-3 bg-black/40">
            <div className="text-[11px] text-emerald-400/80 uppercase tracking-wider mb-2">
              Steps ({form.steps.length})
            </div>
            <div className="space-y-2">
              {form.steps.map((s, i) => (
                <div key={i} className="border border-emerald-900/30 rounded p-2 bg-black/60">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-emerald-300 text-xs font-bold uppercase">{s.type}</span>
                    <button
                      onClick={() => removeStep(i)}
                      className="ml-auto text-[10px] text-red-400 hover:text-red-300"
                    >
                      remove
                    </button>
                  </div>
                  {s.type === 'goto' && (
                    <input
                      value={s.url ?? ''}
                      onChange={(e) => updateStep(i, { url: e.target.value })}
                      placeholder="https://target/login"
                      className="w-full bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    />
                  )}
                  {s.type === 'fill' && (
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        value={s.selector ?? ''}
                        onChange={(e) => updateStep(i, { selector: e.target.value })}
                        placeholder="CSS selector"
                        className="bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                      />
                      <input
                        value={s.value ?? ''}
                        onChange={(e) => updateStep(i, { value: e.target.value })}
                        placeholder="value or ${USERNAME} / ${PASSWORD}"
                        className="bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                      />
                    </div>
                  )}
                  {s.type === 'click' && (
                    <input
                      value={s.selector ?? ''}
                      onChange={(e) => updateStep(i, { selector: e.target.value })}
                      placeholder="CSS selector"
                      className="w-full bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    />
                  )}
                  {s.type === 'press' && (
                    <select
                      value={s.key ?? 'Enter'}
                      onChange={(e) =>
                        updateStep(i, { key: e.target.value as 'Enter' | 'Tab' | 'Escape' })
                      }
                      className="bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    >
                      <option value="Enter">Enter</option>
                      <option value="Tab">Tab</option>
                      <option value="Escape">Escape</option>
                    </select>
                  )}
                  {s.type === 'waitForSelector' && (
                    <input
                      value={s.selector ?? ''}
                      onChange={(e) => updateStep(i, { selector: e.target.value })}
                      placeholder="CSS selector"
                      className="w-full bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    />
                  )}
                  {s.type === 'waitForUrl' && (
                    <input
                      value={s.urlContains ?? ''}
                      onChange={(e) => updateStep(i, { urlContains: e.target.value })}
                      placeholder="URL substring (e.g. /home)"
                      className="w-full bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    />
                  )}
                  {s.type === 'sleep' && (
                    <input
                      type="number"
                      value={s.ms ?? 1000}
                      onChange={(e) => updateStep(i, { ms: Number(e.target.value) })}
                      className="w-full bg-black border border-emerald-900/40 px-2 py-1 rounded text-emerald-100 text-xs"
                    />
                  )}
                </div>
              ))}
            </div>
            <div className="flex gap-2 mt-2 flex-wrap">
              {(
                ['goto', 'fill', 'click', 'press', 'waitForSelector', 'waitForUrl', 'sleep'] as StepType[]
              ).map((t) => (
                <button
                  key={t}
                  onClick={() => addStep(t)}
                  className="text-[11px] px-2 py-1 bg-zinc-900 hover:bg-zinc-800 border border-emerald-900/40 rounded text-emerald-300"
                >
                  + {t}
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
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

      {flows.length === 0 ? (
        <div className="text-zinc-500 text-xs italic p-6 border border-dashed border-emerald-900/40 rounded">
          No auth-flows yet. Create one and bind it to a scope to auto-fill the in-scope login form.
        </div>
      ) : (
        <div className="space-y-2">
          {flows.map((f) => (
            <div key={f.id} className="border border-emerald-900/40 rounded p-3 bg-black/40">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-emerald-200 font-bold flex items-center gap-2">
                    {f.name}
                    {f.is_default && (
                      <span className="text-[9px] px-1.5 py-0.5 bg-emerald-700/40 border border-emerald-600/50 rounded text-emerald-200 uppercase tracking-wider">
                        default
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-zinc-500">
                    Scope: <span className="text-emerald-400">{f.scope_domain ?? '(deleted)'}</span> ·
                    trigger: <span className="text-emerald-300">{f.trigger_mode}</span> · steps:{' '}
                    {f.steps.length} · ok: {f.success_count} / fail: {f.fail_count}
                    {f.last_status && (
                      <>
                        {' '}
                        · last:{' '}
                        <span
                          className={
                            f.last_status === 'ok' ? 'text-emerald-400' : 'text-red-400'
                          }
                        >
                          {f.last_status}
                        </span>
                        {f.last_run_at && ` @ ${new Date(f.last_run_at).toLocaleString()}`}
                      </>
                    )}
                  </div>
                  {f.last_error && (
                    <div className="text-[10px] text-red-300 mt-1">last error: {f.last_error}</div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => run(f.id)}
                    disabled={running === f.id}
                    className="text-xs px-2 py-1 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold flex items-center gap-1 disabled:opacity-60"
                  >
                    <Play className="w-3 h-3" /> {running === f.id ? 'Running…' : 'Run'}
                  </button>
                  <button
                    onClick={() => startEdit(f)}
                    className="text-xs px-2 py-1 bg-zinc-900 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => remove(f.id)}
                    className="text-xs px-2 py-1 bg-red-900/30 border border-red-800/50 rounded text-red-300 hover:bg-red-900/50 flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" /> Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

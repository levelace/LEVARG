import React, { useState, useEffect } from 'react';
import {
  Replace, Plus, Trash2, RefreshCw, ToggleLeft, ToggleRight, Edit2, X, Save,
  AlertCircle, ArrowUpDown,
} from 'lucide-react';

interface MatchReplaceRule {
  id: string;
  name: string;
  enabled: number;
  target: string;
  match_type: string;
  match_pattern: string;
  replace_value: string;
  priority: number;
  created_at: string;
  updated_at: string;
}

interface FormState {
  name: string;
  target: string;
  matchType: string;
  matchPattern: string;
  replaceValue: string;
  priority: number;
}

const emptyForm: FormState = {
  name: '',
  target: 'header',
  matchType: 'literal',
  matchPattern: '',
  replaceValue: '',
  priority: 0,
};

const TARGETS = [
  { value: 'url', label: 'URL' },
  { value: 'header', label: 'Header' },
  { value: 'body', label: 'Body' },
  { value: 'method', label: 'Method' },
];

export default function MatchReplacePanel() {
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [testInput, setTestInput] = useState('');
  const [testOutput, setTestOutput] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await fetch('/api/match-replace');
      setRules(await res.json());
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => { load(); }, []);

  const submit = async () => {
    setError('');
    try {
      const url = editingId ? `/api/match-replace/${editingId}` : '/api/match-replace';
      const method = editingId ? 'PATCH' : 'POST';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setForm(emptyForm);
      setEditingId(null);
      setAdding(false);
      setInfo(editingId ? 'Rule updated.' : 'Rule created.');
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const toggle = async (id: string) => {
    await fetch(`/api/match-replace/${id}/toggle`, { method: 'POST' });
    load();
  };

  const remove = async (id: string) => {
    if (!confirm('Delete this rule?')) return;
    await fetch(`/api/match-replace/${id}`, { method: 'DELETE' });
    load();
  };

  const clearAll = async () => {
    if (!confirm('Delete ALL match-replace rules?')) return;
    await fetch('/api/match-replace', { method: 'DELETE' });
    load();
  };

  const startEdit = (r: MatchReplaceRule) => {
    setEditingId(r.id);
    setAdding(true);
    setForm({
      name: r.name,
      target: r.target,
      matchType: r.match_type,
      matchPattern: r.match_pattern,
      replaceValue: r.replace_value,
      priority: r.priority,
    });
  };

  const testRule = () => {
    if (!testInput || !form.matchPattern) return;
    try {
      if (form.matchType === 'regex') {
        const re = new RegExp(form.matchPattern, 'g');
        setTestOutput(testInput.replace(re, form.replaceValue));
      } else {
        setTestOutput(testInput.split(form.matchPattern).join(form.replaceValue));
      }
    } catch (e) {
      setTestOutput(`Error: ${(e as Error).message}`);
    }
  };

  return (
    <div className="h-full overflow-auto p-6 text-zinc-300 font-mono text-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-emerald-300 flex items-center gap-2">
          <Replace className="w-5 h-5" /> Match & Replace
        </h2>
        <div className="flex gap-2">
          <button onClick={load}
            className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-800/50 rounded text-emerald-300">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          {rules.length > 0 && (
            <button onClick={clearAll}
              className="flex items-center gap-1 text-xs px-3 py-1.5 bg-red-900/30 hover:bg-red-900/50 border border-red-800/50 rounded text-red-300">
              <Trash2 className="w-3 h-3" /> Clear All
            </button>
          )}
          <button
            onClick={() => { setForm(emptyForm); setEditingId(null); setAdding(true); }}
            className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold">
            <Plus className="w-3 h-3" /> New Rule
          </button>
        </div>
      </div>

      <p className="text-xs text-zinc-500 mb-4 max-w-3xl">
        Rules modify outgoing proxy requests in-flight. Each rule matches a pattern in the URL, headers,
        body, or method and replaces it. Rules fire in priority order on every Request Lab and Replay call.
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4" /> {error}
        </div>
      )}
      {info && (
        <div className="mb-4 p-3 bg-emerald-900/20 border border-emerald-800/50 rounded text-emerald-300 text-xs">
          {info}
        </div>
      )}

      {/* Add/Edit form */}
      {adding && (
        <div className="mb-6 border border-emerald-700/50 rounded p-4 bg-black/60 space-y-3">
          <div className="flex justify-between items-center">
            <div className="text-emerald-300 font-bold">{editingId ? 'Edit Rule' : 'New Rule'}</div>
            <button onClick={() => { setAdding(false); setEditingId(null); setForm(emptyForm); }}
              className="text-zinc-500 hover:text-zinc-300"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Name
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Add auth token"
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100" />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Target
              <select value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100">
                {TARGETS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Match Type
              <select value={form.matchType} onChange={(e) => setForm({ ...form, matchType: e.target.value })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100">
                <option value="literal">Literal</option>
                <option value="regex">Regex</option>
              </select>
            </label>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Match Pattern
              <input value={form.matchPattern} onChange={(e) => setForm({ ...form, matchPattern: e.target.value })}
                placeholder={form.matchType === 'regex' ? 'Bearer\\s+\\w+' : 'old-value'}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100 font-mono text-xs" />
            </label>
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Replace With
              <input value={form.replaceValue} onChange={(e) => setForm({ ...form, replaceValue: e.target.value })}
                placeholder="new-value"
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100 font-mono text-xs" />
            </label>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 items-end">
            <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider">
              Priority (lower = first)
              <input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value) || 0 })}
                className="mt-1 w-full bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100" />
            </label>
            <div className="col-span-2">
              <label className="text-[11px] text-emerald-400/70 uppercase tracking-wider block">Test Input</label>
              <div className="flex gap-2 mt-1">
                <input value={testInput} onChange={(e) => setTestInput(e.target.value)}
                  placeholder="Paste text to test"
                  className="flex-1 bg-black border border-emerald-900/50 px-2 py-1 rounded text-emerald-100 font-mono text-xs" />
                <button onClick={testRule}
                  className="px-3 py-1 bg-emerald-900/40 border border-emerald-800/50 rounded text-emerald-300 text-xs hover:bg-emerald-900/60">
                  Test
                </button>
              </div>
              {testOutput !== null && (
                <div className="mt-1 text-xs font-mono text-amber-300 bg-amber-900/10 border border-amber-800/30 rounded px-2 py-1 break-all">
                  {testOutput}
                </div>
              )}
            </div>
            <button onClick={submit} disabled={!form.name || !form.matchPattern}
              className="flex items-center justify-center gap-1 text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-black rounded font-bold disabled:opacity-40">
              <Save className="w-3 h-3" /> {editingId ? 'Update' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {/* Rules table */}
      {rules.length === 0 ? (
        <div className="text-center text-zinc-500 py-12">
          <Replace className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No match-replace rules yet.</p>
          <p className="text-xs mt-1">Rules modify proxy requests in-flight (URL, headers, body, method).</p>
        </div>
      ) : (
        <div className="border border-emerald-900/30 rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-emerald-900/20 text-emerald-400/70 uppercase tracking-wider text-[10px]">
                <th className="p-2 text-left">On</th>
                <th className="p-2 text-left">Name</th>
                <th className="p-2 text-left">Target</th>
                <th className="p-2 text-left">Type</th>
                <th className="p-2 text-left">Match</th>
                <th className="p-2 text-left">Replace</th>
                <th className="p-2 text-center"><ArrowUpDown className="w-3 h-3 inline" /></th>
                <th className="p-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className={`border-t border-emerald-900/20 ${r.enabled ? '' : 'opacity-40'} hover:bg-emerald-950/20`}>
                  <td className="p-2">
                    <button onClick={() => toggle(r.id)} className="text-emerald-400 hover:text-emerald-300">
                      {r.enabled ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5 text-zinc-500" />}
                    </button>
                  </td>
                  <td className="p-2 text-emerald-200">{r.name}</td>
                  <td className="p-2">
                    <span className="px-1.5 py-0.5 bg-emerald-900/30 border border-emerald-800/30 rounded text-emerald-300 text-[10px] uppercase">
                      {r.target}
                    </span>
                  </td>
                  <td className="p-2 text-zinc-400">{r.match_type}</td>
                  <td className="p-2 font-mono text-amber-300 max-w-[200px] truncate" title={r.match_pattern}>{r.match_pattern}</td>
                  <td className="p-2 font-mono text-cyan-300 max-w-[200px] truncate" title={r.replace_value}>{r.replace_value}</td>
                  <td className="p-2 text-center text-zinc-400">{r.priority}</td>
                  <td className="p-2 text-right">
                    <div className="flex gap-1 justify-end">
                      <button onClick={() => startEdit(r)}
                        className="p-1 hover:bg-emerald-900/30 rounded text-emerald-400/60 hover:text-emerald-300">
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => remove(r.id)}
                        className="p-1 hover:bg-red-900/30 rounded text-red-400/60 hover:text-red-300">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

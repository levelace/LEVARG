import React, { useState, useEffect, useCallback } from 'react';
import {
  Shuffle, Plus, Trash2, Power, Copy, RotateCcw, ChevronDown,
  ChevronRight, Zap, Shield, Code, Lock, Hash, AlertTriangle,
  Loader2, GripVertical, Eye, EyeOff,
} from 'lucide-react';

interface Condition {
  target: string;
  operator: string;
  value: string;
  headerName?: string;
}

interface Action {
  type: string;
  target: string;
  pattern?: string;
  replacement?: string;
  headerName?: string;
  headerValue?: string;
  jwtClaims?: Record<string, unknown>;
  rotateValues?: string[];
}

interface Rule {
  id: string;
  name: string;
  phase: 'request' | 'response';
  enabled: boolean;
  priority: number;
  conditions: Condition[];
  conditionLogic: 'and' | 'or';
  actions: Action[];
  hitCount: number;
  scopeId?: string;
  comment?: string;
  createdAt: string;
  updatedAt: string;
}

interface CatalogCondition {
  target: string;
  operator: string;
  label: string;
}

interface CatalogAction {
  type: string;
  label: string;
}

interface CatalogCategory<T> {
  category: string;
  conditions?: T[];
  actions?: T[];
}

interface Catalog {
  conditions: CatalogCategory<CatalogCondition>[];
  actions: CatalogCategory<CatalogAction>[];
}

function cn(...inputs: (string | boolean | undefined | null)[]): string {
  return inputs.filter(Boolean).join(' ');
}

const CATEGORY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  'Scope': Shield,
  'Request': Zap,
  'Response': Eye,
  'Universal': Hash,
  'Transform': Code,
  'Encoding': Lock,
  'Headers': GripVertical,
  'Security Testing': AlertTriangle,
  'Auth / Token': Lock,
};

const EMPTY_CONDITION: Condition = { target: 'url', operator: 'always', value: '' };
const EMPTY_ACTION: Action = { type: 'literal_replace', target: 'req_body', pattern: '', replacement: '' };

function ConditionEditor({
  condition,
  catalog,
  onChange,
  onRemove,
}: {
  condition: Condition;
  catalog: Catalog;
  onChange: (c: Condition) => void;
  onRemove: () => void;
}) {
  const needsHeaderName = ['req_header_value', 'res_header_value'].includes(condition.target);
  const needsValue = !['exists', 'not_exists', 'always'].includes(condition.operator);

  return (
    <div className="flex items-start gap-2 p-3 rounded-lg bg-black/30 border border-emerald-900/20 group">
      <select
        value={`${condition.target}::${condition.operator}`}
        onChange={(e) => {
          const [target, operator] = e.target.value.split('::');
          onChange({ ...condition, target, operator });
        }}
        className="flex-1 min-w-[200px] bg-black/50 border border-emerald-900/50 text-emerald-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-emerald-500/50"
      >
        {catalog.conditions.map((cat) => (
          <optgroup key={cat.category} label={`━━ ${cat.category} ━━`}>
            {cat.conditions!.map((c) => (
              <option key={`${c.target}::${c.operator}`} value={`${c.target}::${c.operator}`}>
                {c.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>

      {needsHeaderName && (
        <input
          type="text"
          value={condition.headerName || ''}
          onChange={(e) => onChange({ ...condition, headerName: e.target.value })}
          placeholder="Header name"
          className="w-32 bg-black/50 border border-emerald-900/50 text-emerald-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-emerald-500/50"
        />
      )}

      {needsValue && (
        <input
          type="text"
          value={condition.value}
          onChange={(e) => onChange({ ...condition, value: e.target.value })}
          placeholder={condition.operator === 'regex' ? 'Pattern...' : condition.operator === 'json_path' ? '$.path.to.key' : 'Value...'}
          className="flex-1 bg-black/50 border border-emerald-900/50 text-emerald-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-emerald-500/50"
        />
      )}

      <button
        onClick={onRemove}
        className="p-1.5 text-red-500/50 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
      >
        <Trash2 className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

function ActionEditor({
  action,
  catalog,
  onChange,
  onRemove,
}: {
  action: Action;
  catalog: Catalog;
  onChange: (a: Action) => void;
  onRemove: () => void;
}) {
  const isHeaderAction = ['add_header', 'set_header', 'remove_header'].includes(action.type);
  const isJwt = action.type === 'jwt_decode_tamper';
  const isRotate = action.type === 'rotate_value';
  const needsPattern = ![
    'add_header', 'set_header', 'remove_header',
    'chunk_body',
  ].includes(action.type);
  const needsReplacement = [
    'regex_replace', 'literal_replace', 'prepend', 'append',
    'crlf_inject', 'rotate_value', 'param_pollute',
  ].includes(action.type);

  return (
    <div className="p-3 rounded-lg bg-black/30 border border-cyan-900/20 space-y-2 group">
      <div className="flex items-center gap-2">
        <select
          value={action.type}
          onChange={(e) => onChange({ ...action, type: e.target.value })}
          className="flex-1 bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
        >
          {catalog.actions.map((cat) => (
            <optgroup key={cat.category} label={`━━ ${cat.category} ━━`}>
              {cat.actions!.map((a) => (
                <option key={a.type} value={a.type}>{a.label}</option>
              ))}
            </optgroup>
          ))}
        </select>

        <select
          value={action.target}
          onChange={(e) => onChange({ ...action, target: e.target.value })}
          className="w-28 bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
        >
          <option value="url">URL</option>
          <option value="req_header">Req Headers</option>
          <option value="req_body">Req Body</option>
          <option value="res_header">Res Headers</option>
          <option value="res_body">Res Body</option>
        </select>

        <button
          onClick={onRemove}
          className="p-1.5 text-red-500/50 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      {isHeaderAction && (
        <div className="flex gap-2">
          <input
            type="text"
            value={action.headerName || ''}
            onChange={(e) => onChange({ ...action, headerName: e.target.value })}
            placeholder="Header name"
            className="flex-1 bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
          />
          {action.type !== 'remove_header' && (
            <input
              type="text"
              value={action.headerValue || ''}
              onChange={(e) => onChange({ ...action, headerValue: e.target.value })}
              placeholder="Header value"
              className="flex-1 bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
            />
          )}
        </div>
      )}

      {!isHeaderAction && needsPattern && (
        <input
          type="text"
          value={action.pattern || ''}
          onChange={(e) => onChange({ ...action, pattern: e.target.value })}
          placeholder={isJwt ? 'JWT auto-detected' : isRotate ? 'Pattern to replace' : 'Match pattern (regex or literal)'}
          className="w-full bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
        />
      )}

      {needsReplacement && !isHeaderAction && (
        <input
          type="text"
          value={action.replacement || ''}
          onChange={(e) => onChange({ ...action, replacement: e.target.value })}
          placeholder={isRotate ? 'val1|||val2|||val3 (pipe-separated)' : isJwt ? '{"alg":"none","admin":true}' : 'Replacement text ($1, $2 for groups)'}
          className="w-full bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
        />
      )}

      {isJwt && (
        <input
          type="text"
          value={action.replacement || ''}
          onChange={(e) => onChange({ ...action, replacement: e.target.value })}
          placeholder='JWT claims override JSON: {"role":"admin","exp":9999999999}'
          className="w-full bg-black/50 border border-cyan-900/50 text-cyan-100 px-2 py-1.5 text-xs font-mono rounded focus:outline-none focus:border-cyan-500/50"
        />
      )}
    </div>
  );
}

function RuleEditor({
  rule,
  catalog,
  onSave,
  onCancel,
}: {
  rule: Partial<Rule>;
  catalog: Catalog;
  onSave: (data: Partial<Rule>) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<Partial<Rule>>({
    name: '',
    phase: 'request',
    conditionLogic: 'and',
    conditions: [{ ...EMPTY_CONDITION }],
    actions: [{ ...EMPTY_ACTION }],
    priority: 0,
    comment: '',
    ...rule,
  });

  const updateCondition = (idx: number, c: Condition) => {
    const next = [...(form.conditions || [])];
    next[idx] = c;
    setForm({ ...form, conditions: next });
  };

  const updateAction = (idx: number, a: Action) => {
    const next = [...(form.actions || [])];
    next[idx] = a;
    setForm({ ...form, actions: next });
  };

  return (
    <div className="space-y-5 p-4 bg-black/50 rounded-xl border border-emerald-900/30">
      {/* Name + Phase */}
      <div className="flex gap-3">
        <input
          type="text"
          value={form.name || ''}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="Rule name"
          className="flex-1 bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-sm font-mono rounded-lg focus:outline-none focus:border-emerald-500/50"
        />
        <select
          value={form.phase}
          onChange={(e) => setForm({ ...form, phase: e.target.value as 'request' | 'response' })}
          className="bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-xs font-mono rounded-lg focus:outline-none focus:border-emerald-500/50"
        >
          <option value="request">Request Phase</option>
          <option value="response">Response Phase</option>
        </select>
        <input
          type="number"
          value={form.priority ?? 0}
          onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value) || 0 })}
          className="w-20 bg-black/50 border border-emerald-900/50 text-emerald-100 px-2 py-2 text-xs font-mono rounded-lg focus:outline-none focus:border-emerald-500/50 text-center"
          title="Priority (higher = runs first)"
        />
      </div>

      {/* Conditions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-widest font-mono text-emerald-400">Conditions</span>
            <select
              value={form.conditionLogic}
              onChange={(e) => setForm({ ...form, conditionLogic: e.target.value as 'and' | 'or' })}
              className="bg-black/50 border border-emerald-900/50 text-emerald-300 px-1.5 py-0.5 text-[10px] font-mono rounded focus:outline-none focus:border-emerald-500/50"
            >
              <option value="and">ALL match (AND)</option>
              <option value="or">ANY match (OR)</option>
            </select>
          </div>
          <button
            onClick={() => setForm({ ...form, conditions: [...(form.conditions || []), { ...EMPTY_CONDITION }] })}
            className="text-[10px] font-mono text-emerald-500 hover:text-emerald-300 flex items-center gap-1 transition-colors"
          >
            <Plus className="w-3 h-3" /> Add
          </button>
        </div>
        <div className="space-y-2">
          {(form.conditions || []).map((c, i) => (
            <ConditionEditor
              key={i}
              condition={c}
              catalog={catalog}
              onChange={(updated) => updateCondition(i, updated)}
              onRemove={() => setForm({
                ...form,
                conditions: (form.conditions || []).filter((_, j) => j !== i),
              })}
            />
          ))}
        </div>
      </div>

      {/* Actions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] uppercase tracking-widest font-mono text-cyan-400">Actions</span>
          <button
            onClick={() => setForm({ ...form, actions: [...(form.actions || []), { ...EMPTY_ACTION }] })}
            className="text-[10px] font-mono text-cyan-500 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <Plus className="w-3 h-3" /> Add
          </button>
        </div>
        <div className="space-y-2">
          {(form.actions || []).map((a, i) => (
            <ActionEditor
              key={i}
              action={a}
              catalog={catalog}
              onChange={(updated) => updateAction(i, updated)}
              onRemove={() => setForm({
                ...form,
                actions: (form.actions || []).filter((_, j) => j !== i),
              })}
            />
          ))}
        </div>
      </div>

      {/* Comment */}
      <input
        type="text"
        value={form.comment || ''}
        onChange={(e) => setForm({ ...form, comment: e.target.value })}
        placeholder="Comment (optional)"
        className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100/70 px-3 py-1.5 text-xs font-mono rounded-lg focus:outline-none focus:border-emerald-500/50"
      />

      {/* Save / Cancel */}
      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-4 py-1.5 text-xs font-mono text-emerald-500/70 hover:text-emerald-300 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onSave(form)}
          disabled={!form.name?.trim()}
          className="px-5 py-1.5 text-xs font-mono rounded-lg bg-emerald-600/30 border border-emerald-500/40 text-emerald-200 hover:bg-emerald-600/40 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
        >
          Save Rule
        </button>
      </div>
    </div>
  );
}

export default function MatchReplacePanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingRule, setEditingRule] = useState<Partial<Rule> | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const fetchRules = useCallback(async () => {
    try {
      const res = await fetch('/api/match-replace');
      if (res.ok) setRules(await res.json());
    } catch { /* ignore */ }
    setLoading(false);
  }, []);

  const fetchCatalog = useCallback(async () => {
    try {
      const res = await fetch('/api/match-replace/catalog');
      if (res.ok) setCatalog(await res.json());
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchRules();
    fetchCatalog();
  }, [fetchRules, fetchCatalog]);

  const saveRule = async (data: Partial<Rule>) => {
    if (data.id) {
      await fetch(`/api/match-replace/${data.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
    } else {
      await fetch('/api/match-replace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
    }
    setEditingRule(null);
    fetchRules();
  };

  const toggleRule = async (id: string) => {
    await fetch(`/api/match-replace/${id}/toggle`, { method: 'POST' });
    fetchRules();
  };

  const deleteRule = async (id: string) => {
    await fetch(`/api/match-replace/${id}`, { method: 'DELETE' });
    fetchRules();
  };

  const duplicateRule = async (id: string) => {
    await fetch(`/api/match-replace/${id}/duplicate`, { method: 'POST' });
    fetchRules();
  };

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  if (loading || !catalog) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="w-5 h-5 text-emerald-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shuffle className="w-4 h-4 text-emerald-400" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400">Match & Replace</span>
          <span className="text-[9px] font-mono text-emerald-500/50 ml-1">
            {rules.filter((r) => r.enabled).length}/{rules.length} active
          </span>
        </div>
        <button
          onClick={() => setEditingRule({})}
          className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 hover:text-emerald-200 px-2 py-1 rounded border border-emerald-900/40 hover:border-emerald-500/40 transition-all"
        >
          <Plus className="w-3 h-3" /> New Rule
        </button>
      </div>

      {/* Editor */}
      {editingRule !== null && (
        <div className="p-3 border-b border-emerald-900/30 overflow-y-auto max-h-[60%]">
          <RuleEditor
            rule={editingRule}
            catalog={catalog}
            onSave={saveRule}
            onCancel={() => setEditingRule(null)}
          />
        </div>
      )}

      {/* Rule List */}
      <div className="flex-1 overflow-y-auto scrollbar-hide">
        {rules.length === 0 && editingRule === null && (
          <div className="flex flex-col items-center justify-center h-full opacity-40">
            <Shuffle className="w-10 h-10 text-emerald-500/50 mb-3" />
            <p className="text-xs font-mono text-emerald-500/70">No rules configured</p>
            <p className="text-[10px] font-mono text-emerald-500/40 mt-1">Click "New Rule" to intercept & mutate traffic</p>
          </div>
        )}

        {rules.map((rule) => {
          const isExpanded = expandedIds.has(rule.id);
          return (
            <div
              key={rule.id}
              className={cn(
                'border-b border-emerald-900/20 transition-colors',
                rule.enabled ? 'bg-transparent' : 'bg-black/20 opacity-60',
              )}
            >
              {/* Rule Row */}
              <div className="flex items-center gap-2 px-3 py-2.5 group">
                <button onClick={() => toggleExpand(rule.id)} className="text-emerald-500/50 hover:text-emerald-300 transition-colors">
                  {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </button>

                <button
                  onClick={() => toggleRule(rule.id)}
                  className={cn(
                    'p-1 rounded transition-colors',
                    rule.enabled ? 'text-emerald-400 hover:text-emerald-300' : 'text-zinc-600 hover:text-zinc-400',
                  )}
                >
                  <Power className="w-3.5 h-3.5" />
                </button>

                <span className={cn(
                  'text-[9px] font-mono px-1.5 py-0.5 rounded border',
                  rule.phase === 'request'
                    ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                    : 'bg-amber-500/10 border-amber-500/30 text-amber-400',
                )}>{rule.phase === 'request' ? 'REQ' : 'RES'}</span>

                <span className="flex-1 text-xs font-mono text-emerald-100 truncate">{rule.name}</span>

                <span className="text-[9px] font-mono text-emerald-500/40" title="Hit count">
                  {rule.hitCount > 0 ? `${rule.hitCount} hits` : ''}
                </span>

                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button onClick={() => setEditingRule(rule)} className="p-1 text-emerald-500/50 hover:text-emerald-300 transition-colors" title="Edit">
                    <Code className="w-3 h-3" />
                  </button>
                  <button onClick={() => duplicateRule(rule.id)} className="p-1 text-emerald-500/50 hover:text-emerald-300 transition-colors" title="Duplicate">
                    <Copy className="w-3 h-3" />
                  </button>
                  <button onClick={() => deleteRule(rule.id)} className="p-1 text-red-500/50 hover:text-red-400 transition-colors" title="Delete">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="px-8 pb-3 space-y-2">
                  {rule.comment && (
                    <p className="text-[10px] font-mono text-emerald-500/50 italic">{rule.comment}</p>
                  )}
                  <div className="text-[10px] font-mono text-emerald-500/60">
                    <span className="text-emerald-400">Conditions</span> ({rule.conditionLogic.toUpperCase()}):
                    {rule.conditions.length === 0 && <span className="ml-1 text-emerald-500/40">always</span>}
                  </div>
                  {rule.conditions.map((c, i) => (
                    <div key={i} className="text-[10px] font-mono text-emerald-200/60 pl-3 border-l border-emerald-900/30">
                      {c.target} <span className="text-emerald-400">{c.operator}</span>{' '}
                      {c.value && <span className="text-amber-300/70">{c.value}</span>}
                      {c.headerName && <span className="text-cyan-300/70 ml-1">[{c.headerName}]</span>}
                    </div>
                  ))}
                  <div className="text-[10px] font-mono text-cyan-400 mt-1">Actions:</div>
                  {rule.actions.map((a, i) => (
                    <div key={i} className="text-[10px] font-mono text-cyan-200/60 pl-3 border-l border-cyan-900/30">
                      <span className="text-cyan-400">{a.type}</span> → {a.target}
                      {a.pattern && <span className="text-amber-300/70 ml-1">/{a.pattern}/</span>}
                      {a.replacement && <span className="text-emerald-300/70 ml-1">→ {a.replacement}</span>}
                      {a.headerName && <span className="text-cyan-300/70 ml-1">{a.headerName}: {a.headerValue}</span>}
                    </div>
                  ))}
                  <div className="text-[9px] font-mono text-emerald-500/30 mt-1">
                    Priority: {rule.priority} | Created: {new Date(rule.createdAt).toLocaleString()}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

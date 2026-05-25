import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, Plus, Trash2, RefreshCw, Play, ChevronDown,
  AlertTriangle, Eye, EyeOff, Filter, X, Edit3, Save, Target,
  Download, FileText,
} from 'lucide-react';

interface StrideThreat {
  id: string;
  scope_id: string | null;
  category: string;
  title: string;
  description: string | null;
  affected_asset: string | null;
  attack_vector: string | null;
  severity: string;
  status: string;
  mitigation: string | null;
  cvss_score: number | null;
  evidence: string | null;
  created_at: string;
  updated_at: string;
}

interface Scope {
  id: string;
  domain: string;
}

interface SummaryData {
  total: number;
  byCategory: Record<string, { total: number; bySeverity: Record<string, number> }>;
}

const CATEGORIES = [
  { key: 'spoofing', label: 'Spoofing', color: 'text-red-400', bg: 'bg-red-500/20', desc: 'Pretending to be something or someone else' },
  { key: 'tampering', label: 'Tampering', color: 'text-orange-400', bg: 'bg-orange-500/20', desc: 'Modifying data or code' },
  { key: 'repudiation', label: 'Repudiation', color: 'text-yellow-400', bg: 'bg-yellow-500/20', desc: 'Denying performed actions' },
  { key: 'info_disclosure', label: 'Info Disclosure', color: 'text-cyan-400', bg: 'bg-cyan-500/20', desc: 'Exposing information to unauthorized actors' },
  { key: 'dos', label: 'Denial of Service', color: 'text-purple-400', bg: 'bg-purple-500/20', desc: 'Making resources unavailable' },
  { key: 'elevation', label: 'Elevation of Privilege', color: 'text-pink-400', bg: 'bg-pink-500/20', desc: 'Gaining unauthorized capabilities' },
] as const;

const SEVERITIES = [
  { key: 'critical', color: 'bg-red-600 text-white' },
  { key: 'high', color: 'bg-orange-600 text-white' },
  { key: 'medium', color: 'bg-yellow-600 text-black' },
  { key: 'low', color: 'bg-blue-600 text-white' },
  { key: 'info', color: 'bg-gray-600 text-white' },
] as const;

const STATUSES = ['identified', 'investigating', 'mitigated', 'accepted', 'resolved'] as const;

const severityBadge = (sev: string) => {
  const s = SEVERITIES.find(x => x.key === sev) ?? SEVERITIES[2];
  return <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${s.color}`}>{sev}</span>;
};

const statusBadge = (st: string) => {
  const colors: Record<string, string> = {
    identified: 'bg-red-500/30 text-red-300',
    investigating: 'bg-yellow-500/30 text-yellow-300',
    mitigated: 'bg-blue-500/30 text-blue-300',
    accepted: 'bg-gray-500/30 text-gray-300',
    resolved: 'bg-emerald-500/30 text-emerald-300',
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[st] ?? colors.identified}`}>{st}</span>;
};

export default function StridePanel() {
  const [threats, setThreats] = useState<StrideThreat[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');

  // Filters
  const [filterCategory, setFilterCategory] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterScope, setFilterScope] = useState('');

  // Create form
  const [showForm, setShowForm] = useState(false);
  const [formScopeId, setFormScopeId] = useState('');
  const [formCategory, setFormCategory] = useState('spoofing');
  const [formTitle, setFormTitle] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formAsset, setFormAsset] = useState('');
  const [formVector, setFormVector] = useState('');
  const [formSeverity, setFormSeverity] = useState('medium');
  const [formMitigation, setFormMitigation] = useState('');
  const [formCvss, setFormCvss] = useState('');

  // Detail/Edit
  const [selectedThreat, setSelectedThreat] = useState<StrideThreat | null>(null);
  const [editing, setEditing] = useState(false);
  const [editStatus, setEditStatus] = useState('');
  const [editMitigation, setEditMitigation] = useState('');
  const [editSeverity, setEditSeverity] = useState('');

  const fetchThreats = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterScope) params.set('scopeId', filterScope);
      if (filterCategory) params.set('category', filterCategory);
      if (filterStatus) params.set('status', filterStatus);
      if (filterSeverity) params.set('severity', filterSeverity);
      const res = await fetch(`/api/stride?${params}`);
      setThreats(await res.json());
    } catch { /* ignore */ }
  }, [filterScope, filterCategory, filterStatus, filterSeverity]);

  const fetchSummary = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterScope) params.set('scopeId', filterScope);
      const res = await fetch(`/api/stride/summary?${params}`);
      setSummary(await res.json());
    } catch { /* ignore */ }
  }, [filterScope]);

  useEffect(() => {
    fetch('/api/scopes').then(r => r.json()).then(setScopes).catch(() => {});
  }, []);

  useEffect(() => { fetchThreats(); fetchSummary(); }, [fetchThreats, fetchSummary]);

  const handleCreate = async () => {
    if (!formTitle.trim()) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/stride', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeId: formScopeId || undefined,
          category: formCategory,
          title: formTitle,
          description: formDescription || undefined,
          affectedAsset: formAsset || undefined,
          attackVector: formVector || undefined,
          severity: formSeverity,
          mitigation: formMitigation || undefined,
          cvssScore: formCvss ? parseFloat(formCvss) : undefined,
        }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error); }
      setFormTitle(''); setFormDescription(''); setFormAsset('');
      setFormVector(''); setFormMitigation(''); setFormCvss('');
      setShowForm(false);
      fetchThreats(); fetchSummary();
    } catch (err: any) {
      setError(err.message);
    } finally { setLoading(false); }
  };

  const handleAutoAnalyze = async () => {
    setAnalyzing(true);
    setError('');
    try {
      const res = await fetch('/api/stride/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scopeId: filterScope || undefined }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error); }
      const data = await res.json();
      const dupMsg = data.newlyInserted < data.generated ? ` (${data.generated - data.newlyInserted} duplicates skipped)` : '';
      setError(`Generated ${data.generated} threat(s), ${data.newlyInserted ?? data.generated} new${dupMsg}`);
      fetchThreats(); fetchSummary();
    } catch (err: any) {
      setError(err.message);
    } finally { setAnalyzing(false); }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/stride/${id}`, { method: 'DELETE' });
      if (selectedThreat?.id === id) setSelectedThreat(null);
      fetchThreats(); fetchSummary();
    } catch { /* ignore */ }
  };

  const handleClearAll = async () => {
    try {
      await fetch('/api/stride', { method: 'DELETE' });
      setSelectedThreat(null);
      fetchThreats(); fetchSummary();
    } catch { /* ignore */ }
  };

  const handleUpdate = async () => {
    if (!selectedThreat) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/stride/${selectedThreat.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: editStatus,
          severity: editSeverity,
          mitigation: editMitigation,
        }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error); }
      const updated = await res.json();
      setSelectedThreat(updated);
      setEditing(false);
      fetchThreats(); fetchSummary();
    } catch (err: any) {
      setError(err.message);
    } finally { setLoading(false); }
  };

  const openDetail = (t: StrideThreat) => {
    setSelectedThreat(t);
    setEditStatus(t.status);
    setEditSeverity(t.severity);
    setEditMitigation(t.mitigation ?? '');
    setEditing(false);
  };

  const getCategoryMeta = (key: string) => CATEGORIES.find(c => c.key === key) ?? CATEGORIES[0];

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-emerald-900/30 shrink-0">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-emerald-400" />
          <h2 className="text-lg font-bold text-emerald-300">STRIDE Threat Model</h2>
          <span className="text-xs text-gray-500 ml-2">
            {threats.length} threat{threats.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleAutoAnalyze}
            disabled={analyzing}
            className="flex items-center gap-1 px-3 py-1.5 text-xs bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 rounded border border-amber-600/40 transition disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${analyzing ? 'animate-spin' : ''}`} />
            {analyzing ? 'Analyzing…' : 'Auto-Analyze'}
          </button>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-1 px-3 py-1.5 text-xs bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 rounded border border-emerald-600/40 transition"
          >
            <Plus className="w-3.5 h-3.5" /> Add Threat
          </button>
          <button
            onClick={() => { fetchThreats(); fetchSummary(); }}
            className="p-1.5 text-gray-400 hover:text-emerald-400 transition"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          {threats.length > 0 && (
            <>
              <button
                onClick={() => {
                  const params = new URLSearchParams();
                  if (filterScope) params.set('scopeId', filterScope);
                  params.set('format', 'markdown');
                  window.open(`/api/stride/export?${params}`, '_blank');
                }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/20 rounded transition"
                title="Export report"
              >
                <Download className="w-3.5 h-3.5" /> Export
              </button>
              <button
                onClick={handleClearAll}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded transition"
              >
                <Trash2 className="w-3.5 h-3.5" /> Clear
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className={`mx-4 mt-2 px-3 py-2 text-xs rounded border ${error.startsWith('Generated') ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'}`}>
          {error}
          <button onClick={() => setError('')} className="ml-2 text-gray-500 hover:text-gray-300"><X className="w-3 h-3 inline" /></button>
        </div>
      )}

      {/* STRIDE Category Summary Cards */}
      {summary && summary.total > 0 && (
        <div className="grid grid-cols-3 md:grid-cols-6 gap-2 px-4 py-3 border-b border-emerald-900/20 shrink-0">
          {CATEGORIES.map(cat => {
            const data = summary.byCategory[cat.key];
            const count = data?.total ?? 0;
            return (
              <button
                key={cat.key}
                onClick={() => setFilterCategory(filterCategory === cat.key ? '' : cat.key)}
                className={`flex flex-col items-center p-2 rounded border transition text-center ${
                  filterCategory === cat.key
                    ? `${cat.bg} border-current ${cat.color}`
                    : 'border-gray-700/50 hover:border-gray-600 text-gray-400 hover:text-gray-300'
                }`}
              >
                <span className="text-xl font-bold">{count}</span>
                <span className="text-[10px] font-medium leading-tight">{cat.label}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-emerald-900/20 flex-wrap shrink-0">
        <Filter className="w-3.5 h-3.5 text-gray-500" />
        <select value={filterScope} onChange={e => setFilterScope(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
          <option value="">All Scopes</option>
          {scopes.map(s => <option key={s.id} value={s.id}>{s.domain}</option>)}
        </select>
        <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
          <option value="">All Categories</option>
          {CATEGORIES.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}
        </select>
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s.key} value={s.key}>{s.key}</option>)}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
          <option value="">All Statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(filterCategory || filterSeverity || filterStatus || filterScope) && (
          <button onClick={() => { setFilterCategory(''); setFilterSeverity(''); setFilterStatus(''); setFilterScope(''); }}
            className="text-xs text-gray-500 hover:text-gray-300 underline">
            Reset
          </button>
        )}
      </div>

      {/* Create Form */}
      {showForm && (
        <div className="mx-4 mt-2 p-3 bg-gray-900/80 border border-emerald-900/40 rounded-lg shrink-0">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">Category *</label>
              <select value={formCategory} onChange={e => setFormCategory(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300">
                {CATEGORIES.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">Severity</label>
              <select value={formSeverity} onChange={e => setFormSeverity(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300">
                {SEVERITIES.map(s => <option key={s.key} value={s.key}>{s.key}</option>)}
              </select>
            </div>
          </div>
          <div className="mb-2">
            <label className="block text-[10px] text-gray-500 mb-1">Title *</label>
            <input value={formTitle} onChange={e => setFormTitle(e.target.value)}
              placeholder="e.g., Missing CSRF protection on /api/transfer"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300" />
          </div>
          <div className="mb-2">
            <label className="block text-[10px] text-gray-500 mb-1">Description</label>
            <textarea value={formDescription} onChange={e => setFormDescription(e.target.value)} rows={2}
              placeholder="Detailed threat description…"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 resize-none" />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">Affected Asset</label>
              <input value={formAsset} onChange={e => setFormAsset(e.target.value)}
                placeholder="URL or component name"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300" />
            </div>
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">Attack Vector</label>
              <input value={formVector} onChange={e => setFormVector(e.target.value)}
                placeholder="How the threat is exploited"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300" />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">Scope</label>
              <select value={formScopeId} onChange={e => setFormScopeId(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300">
                <option value="">No scope</option>
                {scopes.map(s => <option key={s.id} value={s.id}>{s.domain}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-gray-500 mb-1">CVSS Score</label>
              <input value={formCvss} onChange={e => setFormCvss(e.target.value)}
                type="number" min="0" max="10" step="0.1" placeholder="0.0 – 10.0"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300" />
            </div>
          </div>
          <div className="mb-3">
            <label className="block text-[10px] text-gray-500 mb-1">Mitigation Notes</label>
            <textarea value={formMitigation} onChange={e => setFormMitigation(e.target.value)} rows={2}
              placeholder="Recommended countermeasures…"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 resize-none" />
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} disabled={loading || !formTitle.trim()}
              className="flex items-center gap-1 px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded transition disabled:opacity-50">
              <Plus className="w-3.5 h-3.5" /> Create Threat
            </button>
            <button onClick={() => setShowForm(false)}
              className="px-3 py-1.5 text-xs text-gray-400 hover:text-gray-300 transition">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Threat List */}
        <div className={`${selectedThreat ? 'w-1/2' : 'w-full'} overflow-y-auto`}>
          {threats.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-500 gap-3">
              <ShieldAlert className="w-12 h-12 text-gray-700" />
              <p className="text-sm">No threats found</p>
              <p className="text-xs text-gray-600">Click "Auto-Analyze" to generate threats from recon data, scan anomalies, sessions, and auth flows — or add manually.</p>
              <p className="text-xs text-gray-700 mt-1">Threats are also auto-generated from Request Lab responses and completed scans.</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-800/50">
              {threats.map(t => {
                const cat = getCategoryMeta(t.category);
                return (
                  <button
                    key={t.id}
                    onClick={() => openDetail(t)}
                    className={`w-full text-left px-4 py-3 hover:bg-gray-800/40 transition ${
                      selectedThreat?.id === t.id ? 'bg-emerald-900/20 border-l-2 border-emerald-400' : ''
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <span className={`mt-0.5 text-[10px] font-bold px-1.5 py-0.5 rounded ${cat.bg} ${cat.color}`}>
                        {cat.label.charAt(0)}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm text-gray-200 font-medium truncate">{t.title}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[10px]">
                          {severityBadge(t.severity)}
                          {statusBadge(t.status)}
                          {t.cvss_score != null && (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              t.cvss_score >= 9 ? 'bg-red-700/40 text-red-300' :
                              t.cvss_score >= 7 ? 'bg-orange-700/40 text-orange-300' :
                              t.cvss_score >= 4 ? 'bg-yellow-700/40 text-yellow-300' :
                              'bg-gray-700/40 text-gray-400'
                            }`}>{t.cvss_score}</span>
                          )}
                          {t.affected_asset && (
                            <span className="text-gray-500 truncate max-w-[200px]">
                              <Target className="w-3 h-3 inline mr-0.5" />{t.affected_asset}
                            </span>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={e => { e.stopPropagation(); handleDelete(t.id); }}
                        className="p-1 text-gray-600 hover:text-red-400 transition shrink-0"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Detail Panel */}
        {selectedThreat && (
          <div className="w-1/2 border-l border-emerald-900/30 overflow-y-auto bg-gray-900/40">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-emerald-300">Threat Detail</h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => { setEditing(!editing); }}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-emerald-300 transition"
                >
                  {editing ? <><EyeOff className="w-3.5 h-3.5" /> Cancel</> : <><Edit3 className="w-3.5 h-3.5" /> Edit</>}
                </button>
                <button onClick={() => setSelectedThreat(null)}
                  className="p-1 text-gray-500 hover:text-gray-300 transition">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${getCategoryMeta(selectedThreat.category).bg} ${getCategoryMeta(selectedThreat.category).color}`}>
                  {getCategoryMeta(selectedThreat.category).label}
                </span>
              </div>
              <h4 className="text-base font-semibold text-gray-200">{selectedThreat.title}</h4>

              <div className="flex items-center gap-3">
                {editing ? (
                  <>
                    <select value={editSeverity} onChange={e => setEditSeverity(e.target.value)}
                      className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
                      {SEVERITIES.map(s => <option key={s.key} value={s.key}>{s.key}</option>)}
                    </select>
                    <select value={editStatus} onChange={e => setEditStatus(e.target.value)}
                      className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </>
                ) : (
                  <>
                    {severityBadge(selectedThreat.severity)}
                    {statusBadge(selectedThreat.status)}
                    {selectedThreat.cvss_score != null && (
                      <span className="text-xs text-gray-400">CVSS: {selectedThreat.cvss_score}</span>
                    )}
                  </>
                )}
              </div>

              {selectedThreat.description && (
                <div>
                  <label className="text-[10px] text-gray-500 font-medium">Description</label>
                  <p className="text-xs text-gray-300 mt-1 whitespace-pre-wrap">{selectedThreat.description}</p>
                </div>
              )}

              {selectedThreat.affected_asset && (
                <div>
                  <label className="text-[10px] text-gray-500 font-medium">Affected Asset</label>
                  <p className="text-xs text-cyan-300 mt-1 font-mono">{selectedThreat.affected_asset}</p>
                </div>
              )}

              {selectedThreat.attack_vector && (
                <div>
                  <label className="text-[10px] text-gray-500 font-medium">Attack Vector</label>
                  <p className="text-xs text-orange-300 mt-1">{selectedThreat.attack_vector}</p>
                </div>
              )}

              <div>
                <label className="text-[10px] text-gray-500 font-medium">Mitigation</label>
                {editing ? (
                  <textarea value={editMitigation} onChange={e => setEditMitigation(e.target.value)} rows={3}
                    placeholder="Add mitigation notes…"
                    className="w-full mt-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 resize-none" />
                ) : (
                  <p className="text-xs text-gray-300 mt-1 whitespace-pre-wrap">
                    {selectedThreat.mitigation || <span className="text-gray-600 italic">No mitigation notes</span>}
                  </p>
                )}
              </div>

              {editing && (
                <button onClick={handleUpdate} disabled={loading}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded transition disabled:opacity-50">
                  <Save className="w-3.5 h-3.5" /> Save Changes
                </button>
              )}

              <div className="text-[10px] text-gray-600 pt-2 border-t border-gray-800">
                Created: {new Date(selectedThreat.created_at).toLocaleString()} · Updated: {new Date(selectedThreat.updated_at).toLocaleString()}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

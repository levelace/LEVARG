import React, { useState, useEffect } from 'react';
import { GitBranch, Plus, Play, Trash2, ChevronRight, Database, X, CheckCircle2, AlertCircle } from 'lucide-react';

export default function FlowCapture() {
  const [flows, setFlows] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newFlow, setNewFlow] = useState({ name: '', steps: [{ method: 'GET', url: '', headers: '{}', body: '' }] });
  const [runResults, setRunResults] = useState<any>(null);

  const fetchFlows = async () => {
    const res = await fetch('/api/flows');
    const data = await res.json();
    setFlows(data);
  };

  useEffect(() => {
    fetchFlows();
    const interval = setInterval(fetchFlows, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleCreate = async () => {
    if (!newFlow.name || newFlow.steps.some(s => !s.url)) return;
    
    const parsedSteps = newFlow.steps.map(s => {
      let parsedHeaders = {};
      try { parsedHeaders = JSON.parse(s.headers); } catch (e) {}
      return { ...s, headers: parsedHeaders };
    });

    await fetch('/api/flows', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newFlow.name, steps: parsedSteps })
    });
    
    setShowCreate(false);
    setNewFlow({ name: '', steps: [{ method: 'GET', url: '', headers: '{}', body: '' }] });
    fetchFlows();
  };

  const handleDelete = async (id: string) => {
    await fetch(`/api/flows/${id}`, { method: 'DELETE' });
    fetchFlows();
  };

  const handleRun = async (id: string) => {
    setRunResults(null);
    const res = await fetch(`/api/flows/${id}/run`, { method: 'POST' });
    const data = await res.json();
    setRunResults({ id, ...data });
  };

  const addStep = () => {
    setNewFlow({ ...newFlow, steps: [...newFlow.steps, { method: 'GET', url: '', headers: '{}', body: '' }] });
  };

  const updateStep = (index: number, field: string, value: string) => {
    const updatedSteps = [...newFlow.steps];
    updatedSteps[index] = { ...updatedSteps[index], [field]: value };
    setNewFlow({ ...newFlow, steps: updatedSteps });
  };

  const removeStep = (index: number) => {
    const updatedSteps = newFlow.steps.filter((_, i) => i !== index);
    setNewFlow({ ...newFlow, steps: updatedSteps });
  };

  return (
    <div className="p-8 max-w-6xl mx-auto w-full bg-black/40 backdrop-blur-md relative overflow-hidden min-h-full">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-12 flex justify-between items-end relative z-10">
        <div className="relative">
          <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
          <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
            <GitBranch className="w-8 h-8 text-emerald-400" />
            State Engine
          </h2>
          <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Multi-step request orchestration & flow analysis</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-6 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center gap-2 hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all rounded-md relative overflow-hidden group"
        >
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
          <Plus className="w-4 h-4 relative z-10" />
          <span className="relative z-10">New Flow</span>
        </button>
      </header>

      {showCreate && (
        <div className="bg-black/60 backdrop-blur-md border border-emerald-900/50 p-6 rounded-lg mb-8 shadow-[0_4px_20px_rgba(0,0,0,0.5)] relative z-20">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-sm font-mono text-emerald-300 uppercase tracking-wider">Create New Flow</h3>
            <button onClick={() => setShowCreate(false)} className="text-emerald-500/50 hover:text-emerald-400 transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="mb-6">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Flow Name</label>
            <input
              type="text"
              value={newFlow.name}
              onChange={(e) => setNewFlow({ ...newFlow, name: e.target.value })}
              placeholder="e.g., Auth Bypass Sequence"
              className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all"
            />
          </div>

          <div className="space-y-4 mb-6">
            {newFlow.steps.map((step, index) => (
              <div key={index} className="p-4 bg-emerald-950/10 border border-emerald-900/30 rounded-lg relative group">
                <div className="absolute -left-2 -top-2 w-6 h-6 bg-emerald-900/80 rounded-full flex items-center justify-center text-[10px] font-mono text-emerald-400 border border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                  {index + 1}
                </div>
                {newFlow.steps.length > 1 && (
                  <button onClick={() => removeStep(index)} className="absolute right-2 top-2 text-emerald-500/30 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
                <div className="grid grid-cols-12 gap-4 mt-2">
                  <div className="col-span-3">
                    <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Method</label>
                    <select
                      value={step.method}
                      onChange={(e) => updateStep(index, 'method', e.target.value)}
                      className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 rounded-md"
                    >
                      {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m}>{m}</option>)}
                    </select>
                  </div>
                  <div className="col-span-9">
                    <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">URL</label>
                    <input
                      type="text"
                      value={step.url}
                      onChange={(e) => updateStep(index, 'url', e.target.value)}
                      placeholder="https://api.example.com/v1/auth"
                      className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 rounded-md"
                    />
                  </div>
                  <div className="col-span-6">
                    <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Headers (JSON)</label>
                    <textarea
                      value={step.headers}
                      onChange={(e) => updateStep(index, 'headers', e.target.value)}
                      className="w-full h-20 bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 rounded-md resize-none scrollbar-hide"
                    />
                  </div>
                  <div className="col-span-6">
                    <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Body</label>
                    <textarea
                      value={step.body}
                      onChange={(e) => updateStep(index, 'body', e.target.value)}
                      className="w-full h-20 bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 rounded-md resize-none scrollbar-hide"
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-between items-center">
            <button onClick={addStep} className="text-xs font-mono uppercase tracking-widest text-emerald-400 hover:text-emerald-300 flex items-center gap-2 transition-colors">
              <Plus className="w-3 h-3" /> Add Step
            </button>
            <button onClick={handleCreate} disabled={!newFlow.name} className="bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 px-6 py-2 text-xs font-mono uppercase tracking-widest rounded-md hover:bg-emerald-500/30 transition-all disabled:opacity-50">
              Save Flow
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
        {flows.length === 0 ? (
          <div className="col-span-full p-20 border border-dashed border-emerald-900/50 bg-black/50 rounded-lg flex flex-col items-center justify-center opacity-60 shadow-[inset_0_2px_20px_rgba(0,0,0,0.3)]">
            <GitBranch className="w-12 h-12 mb-4 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
            <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No state flows defined</p>
          </div>
        ) : (
          flows.map((flow) => (
            <div key={flow.id} className="bg-black/50 border border-emerald-900/30 p-6 rounded-lg group hover:border-emerald-500/50 hover:bg-emerald-950/20 transition-all duration-300 shadow-[0_4px_20px_rgba(0,0,0,0.2)] relative overflow-hidden flex flex-col">
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex justify-between items-start mb-6 relative z-10">
                <div>
                  <h3 className="text-lg font-bold font-mono text-emerald-100 group-hover:text-emerald-50 transition-colors">{flow.name}</h3>
                  <p className="text-[10px] text-emerald-500/70 font-mono uppercase tracking-widest mt-1">{flow.steps.length} Steps in sequence</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => handleRun(flow.id)} className="p-2 border border-emerald-900/50 rounded-md text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-500/50 hover:shadow-[0_0_10px_rgba(16,185,129,0.3)] transition-all bg-black/50">
                    <Play className="w-3 h-3" />
                  </button>
                  <button onClick={() => handleDelete(flow.id)} className="p-2 border border-emerald-900/50 rounded-md text-red-400 hover:bg-red-500/20 hover:border-red-500/50 hover:shadow-[0_0_10px_rgba(239,68,68,0.3)] transition-all bg-black/50">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-hide relative z-10">
                {flow.steps.map((step: any, i: number) => (
                  <React.Fragment key={i}>
                    <div className="flex-shrink-0 w-10 h-10 bg-black/50 border border-emerald-900/50 rounded-md flex items-center justify-center text-[10px] font-mono text-emerald-500/70 group-hover:border-emerald-500/50 group-hover:text-emerald-400 group-hover:shadow-[0_0_10px_rgba(16,185,129,0.2)] transition-all">
                      S{i + 1}
                    </div>
                    {i < flow.steps.length - 1 && <ChevronRight className="w-3 h-3 text-emerald-900/50 group-hover:text-emerald-500/50 flex-shrink-0 transition-colors" />}
                  </React.Fragment>
                ))}
              </div>
              
              {runResults && runResults.id === flow.id && (
                <div className="mt-4 pt-4 border-t border-emerald-900/30 relative z-10">
                  <h4 className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Execution Results</h4>
                  <div className="space-y-2">
                    {runResults.results.map((res: any, i: number) => (
                      <div key={i} className="flex items-center justify-between text-xs font-mono bg-black/40 p-2 rounded border border-emerald-900/20">
                        <div className="flex items-center gap-2 truncate max-w-[200px]">
                          {res.success ? <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" /> : <AlertCircle className="w-3 h-3 text-red-400 flex-shrink-0" />}
                          <span className="text-emerald-100/70 truncate" title={res.step}>S{i+1}: {res.step}</span>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0">
                          <span className={res.status >= 400 ? 'text-red-400' : 'text-emerald-400'}>{res.status || 'ERR'}</span>
                          <span className="text-emerald-500/50">{res.duration}ms</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

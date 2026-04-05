import React, { useState, useEffect } from 'react';
import { Database, Plus, Trash2, Code, Terminal, Search, Sparkles, Clock, Copy, Flame, Shield, Zap, Skull } from 'lucide-react';
import { GoogleGenAI } from '@google/genai';
import { motion, AnimatePresence } from 'motion/react';

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function PayloadManager() {
  const [payloads, setPayloads] = useState<any[]>([]);
  const [oven, setOven] = useState<Record<string, any>>({});
  const [loadingOven, setLoadingOven] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'custom' | 'oven'>('custom');
  const [showAdd, setShowAdd] = useState(false);
  const [newPayload, setNewPayload] = useState({ name: '', content: '', type: 'fuzzing' });
  const [generating, setGenerating] = useState(false);

  const fetchPayloads = async () => {
    const res = await fetch('/api/payloads');
    const data = await res.json();
    setPayloads(data);
  };

  const fetchOven = async () => {
    setLoadingOven(true);
    try {
      const res = await fetch('/api/oven');
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();
      console.log('[PayloadManager] Oven data received:', data);
      setOven(data);
    } catch (err: any) {
      console.error('[PayloadManager] Error fetching oven:', err);
      setError(`Failed to load Payload Oven: ${err.message}`);
    } finally {
      setLoadingOven(false);
    }
  };

  useEffect(() => {
    fetchPayloads();
    fetchOven();
    const interval = setInterval(() => {
      fetchPayloads();
      fetchOven();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetch('/api/payloads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newPayload)
    });
    setNewPayload({ name: '', content: '', type: 'fuzzing' });
    setShowAdd(false);
    fetchPayloads();
  };

  const handleGenerate = async () => {
    if (!newPayload.name) {
      alert("Please provide a name/description for the payload set first.");
      return;
    }
    const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
    if (!apiKey) {
      alert('Gemini API Key not found. Please set GEMINI_API_KEY or API_KEY in your environment.');
      return;
    }
    
    setGenerating(true);
    try {
      const ai = new GoogleGenAI({ apiKey });
      const prompt = `Generate a list of 20 highly effective security testing payloads for the following scenario: ${newPayload.name}.
      The payload type is: ${newPayload.type}.
      Return ONLY the payloads, one per line. Do not include markdown formatting, numbers, or explanations.`;
      
      const result = await ai.models.generateContent({
        model: 'gemini-1.5-flash',
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
      });
      
      // Use the proper property access for the SDK
      const responseText = (result as any).response.text();
      if (responseText) {
        setNewPayload({ ...newPayload, content: responseText.trim() });
      }
    } catch (err: any) {
      console.error('AI Generation failed:', err);
      alert(`AI Generation failed: ${err.message || 'Unknown error'}`);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto w-full h-full overflow-y-auto scrollbar-hide">
      <header className="mb-12 flex justify-between items-end relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
            <Database className="w-8 h-8 text-emerald-400" />
            Payload Engine
          </h2>
          <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Mutation sets and parameter injection vectors</p>
        </div>
        <div className="flex gap-4">
          <div className="bg-black/50 border border-emerald-900/30 rounded-lg p-1 flex">
            <button
              onClick={() => setView('custom')}
              className={cn(
                "px-4 py-1.5 text-[10px] font-mono uppercase tracking-widest rounded-md transition-all",
                view === 'custom' ? "bg-emerald-500/20 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]" : "text-emerald-500/40 hover:text-emerald-500/70"
              )}
            >
              Custom Sets
            </button>
            <button
              onClick={() => setView('oven')}
              className={cn(
                "px-4 py-1.5 text-[10px] font-mono uppercase tracking-widest rounded-md transition-all flex items-center gap-2",
                view === 'oven' ? "bg-orange-500/20 text-orange-400 shadow-[0_0_10px_rgba(249,115,22,0.2)]" : "text-orange-500/40 hover:text-orange-500/70"
              )}
            >
              <Flame className="w-3 h-3" />
              Payload Oven
            </button>
          </div>
          {view === 'custom' && (
            <button
              onClick={() => setShowAdd(true)}
              className="bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-6 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center gap-2 hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.4)] transition-all rounded-md relative overflow-hidden group"
            >
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <Plus className="w-4 h-4 relative z-10" />
              <span className="relative z-10">Add Payload Set</span>
            </button>
          )}
        </div>
      </header>

      <AnimatePresence mode="wait">
        {view === 'custom' ? (
          <motion.div
            key="custom"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-8"
          >
            {showAdd && (
              <div className="bg-black/40 backdrop-blur-md border border-emerald-900/30 p-8 mb-8 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative overflow-hidden animate-in fade-in slide-in-from-top-4">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
                <form onSubmit={handleAdd} className="space-y-4 relative z-10">
                  <div className="grid grid-cols-2 gap-4">
                    <input
                      type="text"
                      placeholder="Set Name (e.g. XSS Vectors)"
                      value={newPayload.name}
                      onChange={e => setNewPayload({ ...newPayload, name: e.target.value })}
                      className="bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all placeholder:text-emerald-900/50"
                    />
                    <select
                      value={newPayload.type}
                      onChange={e => setNewPayload({ ...newPayload, type: e.target.value })}
                      className="bg-black/50 border border-emerald-900/50 text-emerald-100 px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all"
                    >
                      <option value="fuzzing" className="bg-emerald-950 text-emerald-100">Fuzzing</option>
                      <option value="injection" className="bg-emerald-950 text-emerald-100">Injection</option>
                      <option value="auth" className="bg-emerald-950 text-emerald-100">Auth Bypass</option>
                      <option value="custom" className="bg-emerald-950 text-emerald-100">Custom</option>
                    </select>
                  </div>
                  <textarea
                    placeholder="Payloads (one per line)"
                    value={newPayload.content}
                    onChange={e => setNewPayload({ ...newPayload, content: e.target.value })}
                    className="w-full h-48 bg-black/50 border border-emerald-900/50 p-4 text-xs font-mono text-emerald-100 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md resize-none transition-all placeholder:text-emerald-900/50 scrollbar-hide"
                  />
                  <div className="flex justify-between items-center">
                    <button 
                      type="button" 
                      onClick={handleGenerate} 
                      disabled={generating}
                      className="bg-purple-500/10 border border-purple-500/50 text-purple-400 px-4 py-2 text-xs font-mono uppercase tracking-widest rounded-md hover:bg-purple-500/20 hover:shadow-[0_0_15px_rgba(168,85,247,0.4)] transition-all flex items-center gap-2 disabled:opacity-50 disabled:hover:shadow-none relative overflow-hidden group"
                    >
                      {!generating && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(168,85,247,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
                      {generating ? <Clock className="w-3 h-3 animate-spin relative z-10" /> : <Sparkles className="w-3 h-3 relative z-10" />}
                      <span className="relative z-10">Generate with AI</span>
                    </button>
                    <div className="flex gap-4">
                      <button type="button" onClick={() => setShowAdd(false)} className="text-xs font-mono uppercase tracking-widest text-emerald-500/50 hover:text-emerald-300 transition-colors">Cancel</button>
                      <button type="submit" className="bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-6 py-2.5 text-xs font-mono uppercase tracking-widest rounded-md hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.4)] transition-all">Save Set</button>
                    </div>
                  </div>
                </form>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {payloads.length === 0 ? (
                <div className="col-span-full p-20 border border-dashed border-emerald-900/30 bg-black/30 rounded-lg flex flex-col items-center justify-center opacity-50">
                  <Database className="w-12 h-12 mb-4 text-emerald-500/30 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
                  <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No payload sets available</p>
                </div>
              ) : (
                payloads.map((payload) => (
                  <div key={payload.id} className="bg-black/40 backdrop-blur-md border border-emerald-900/30 p-6 rounded-lg group hover:border-emerald-500/50 hover:bg-emerald-950/20 transition-all duration-300 flex flex-col shadow-[0_4px_20px_rgba(0,0,0,0.2)] relative overflow-hidden">
                    <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
                    <div className="flex justify-between items-start mb-4 relative z-10">
                      <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-md text-emerald-400 group-hover:bg-emerald-500/20 group-hover:shadow-[0_0_10px_rgba(16,185,129,0.3)] transition-all">
                        <Code className="w-4 h-4 drop-shadow-[0_0_5px_currentColor]" />
                      </div>
                      <span className="text-[10px] font-mono uppercase text-emerald-500/70 border border-emerald-900/50 px-2 py-0.5 rounded-sm bg-black/50">{payload.type}</span>
                    </div>
                    <h3 className="text-lg font-bold font-mono text-emerald-100 mb-1 group-hover:text-emerald-50 transition-colors relative z-10">{payload.name}</h3>
                    <p className="text-[10px] text-emerald-500/50 font-mono uppercase tracking-widest mb-6 flex-1 relative z-10">
                      {payload.content.split('\n').length} Vectors defined
                    </p>
                    <div className="flex justify-between items-center pt-4 border-t border-emerald-900/30 relative z-10">
                      <button 
                        onClick={() => navigator.clipboard.writeText(payload.content)}
                        className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest hover:text-emerald-300 hover:drop-shadow-[0_0_5px_rgba(16,185,129,0.5)] transition-all flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" /> Copy Raw
                      </button>
                      <button 
                        onClick={async () => {
                          await fetch(`/api/payloads/${payload.id}`, { method: 'DELETE' });
                          fetchPayloads();
                        }}
                        className="p-1.5 text-emerald-500/50 hover:text-red-400 hover:bg-red-500/10 hover:shadow-[0_0_10px_rgba(239,68,68,0.2)] rounded-md transition-all"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="oven"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-8"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {loadingOven ? (
                <div className="col-span-full flex flex-col items-center justify-center py-12 text-emerald-500/50">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500 mb-4"></div>
                  <p className="font-mono text-sm">Heating the oven...</p>
                </div>
              ) : Object.keys(oven).length === 0 ? (
                <div className="col-span-full flex flex-col items-center justify-center py-12 text-emerald-500/50 border border-emerald-500/20 rounded-lg bg-black/40">
                  <Flame className="w-8 h-8 mb-4 opacity-20" />
                  <p className="font-mono text-sm">Oven is empty. No payloads available.</p>
                </div>
              ) : (
                Object.entries(oven).map(([category, tiers]: [string, any]) => (
                  <div key={category} className="bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)] flex flex-col">
                    <div className="p-4 border-b border-emerald-900/30 bg-emerald-950/10 flex justify-between items-center">
                      <h3 className="text-sm font-bold font-mono text-emerald-100 uppercase tracking-widest">{category}</h3>
                      <Flame className="w-4 h-4 text-orange-500 animate-pulse" />
                    </div>
                    <div className="p-4 space-y-4 flex-1">
                      {/* Standard */}
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <Shield className="w-3 h-3 text-emerald-500" />
                          <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70">Standard Layer</span>
                        </div>
                        <div className="bg-black/50 rounded border border-emerald-900/30 p-2 max-h-24 overflow-y-auto scrollbar-hide">
                          {tiers.standard.map((p: string, i: number) => (
                            <div key={i} className="text-[9px] font-mono text-emerald-100/60 mb-1 truncate hover:text-emerald-100 transition-colors cursor-default" title={p}>{p}</div>
                          ))}
                        </div>
                      </div>
                      {/* Advanced */}
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <Zap className="w-3 h-3 text-orange-500" />
                          <span className="text-[10px] font-mono uppercase tracking-widest text-orange-500/70">Advanced Layer</span>
                        </div>
                        <div className="bg-black/50 rounded border border-orange-900/30 p-2 max-h-24 overflow-y-auto scrollbar-hide">
                          {tiers.advanced.map((p: string, i: number) => (
                            <div key={i} className="text-[9px] font-mono text-orange-100/60 mb-1 truncate hover:text-orange-100 transition-colors cursor-default" title={p}>{p}</div>
                          ))}
                        </div>
                      </div>
                      {/* Elite */}
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <Skull className="w-3 h-3 text-red-500" />
                          <span className="text-[10px] font-mono uppercase tracking-widest text-red-500/70">Elite Layer</span>
                        </div>
                        <div className="bg-black/50 rounded border border-red-900/30 p-2 max-h-24 overflow-y-auto scrollbar-hide">
                          {tiers.elite.map((p: string, i: number) => (
                            <div key={i} className="text-[9px] font-mono text-red-100/60 mb-1 truncate hover:text-red-100 transition-colors cursor-default" title={p}>{p}</div>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div className="p-4 border-t border-emerald-900/30 bg-black/20">
                      <button 
                        onClick={() => {
                          const all = [...tiers.standard, ...tiers.advanced, ...tiers.elite].join('\n');
                          navigator.clipboard.writeText(all);
                        }}
                        className="w-full py-2 text-[10px] font-mono uppercase tracking-widest text-emerald-400/70 hover:text-emerald-400 hover:bg-emerald-500/10 transition-all rounded border border-emerald-900/50"
                      >
                        Copy All Vectors
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { Terminal, Shield, CheckCircle2, XCircle, AlertTriangle, Search, Zap, Globe, Lock } from 'lucide-react';

interface ToolStatus {
  name: string;
  category: string;
  phase: string;
  status: 'available' | 'missing';
  method: 'BINARY' | 'NPX' | 'POLYFILL' | 'UNAVAILABLE';
}

export default function Tools() {
  const [toolStatuses, setToolStatuses] = useState<ToolStatus[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkTools = async () => {
      setLoading(true);
      try {
        const res = await fetch('/api/tools/status');
        if (res.ok) {
          const data = await res.json();
          setToolStatuses(data);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    checkTools();
  }, []);

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide">
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Shield className="w-8 h-8 text-emerald-400" />
          Security Arsenal
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Backend Toolchain & Subprocess Status</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {toolStatuses.map((tool) => (
          <div key={tool.name} className="bg-black/40 backdrop-blur-md border border-emerald-900/30 p-6 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative group overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            
            <div className="flex justify-between items-start mb-4">
              <div className="p-2 bg-emerald-500/10 rounded-md border border-emerald-500/20">
                {tool.category === 'Recon' && <Search className="w-5 h-5 text-emerald-400" />}
                {tool.category === 'Fuzzing' && <Zap className="w-5 h-5 text-emerald-400" />}
                {tool.category === 'Discovery' && <Globe className="w-5 h-5 text-emerald-400" />}
                {tool.category === 'Vulnerability' && <AlertTriangle className="w-5 h-5 text-emerald-400" />}
                {tool.category === 'Exploitation' && <Lock className="w-5 h-5 text-emerald-400" />}
                {tool.category === 'Fingerprinting' && <Terminal className="w-5 h-5 text-emerald-400" />}
              </div>
              <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-mono uppercase tracking-widest border ${
                loading ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-500/50' :
                tool.status === 'available' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                {loading ? (
                  <div className="w-2 h-2 bg-emerald-500/50 rounded-full animate-pulse" />
                ) : tool.status === 'available' ? (
                  <CheckCircle2 className="w-3 h-3" />
                ) : (
                  <XCircle className="w-3 h-3" />
                )}
                {loading ? 'Checking...' : tool.status === 'available' ? 'Available' : 'Missing'}
              </div>
            </div>

            <h3 className="text-lg font-bold text-emerald-50 mb-2 font-mono">{tool.name}</h3>
            <p className="text-[10px] text-emerald-500/60 mb-4 uppercase tracking-widest">Phase: {tool.phase}</p>
            
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400/50 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10">
                {tool.category}
              </span>
              <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded border ${
                tool.method === 'BINARY' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
                tool.method === 'NPX' ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' :
                tool.method === 'POLYFILL' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                {tool.method}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-12 p-6 bg-emerald-950/20 border border-emerald-900/30 rounded-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 opacity-10">
          <Terminal className="w-24 h-24 text-emerald-500" />
        </div>
        <h3 className="text-sm font-bold text-emerald-100 mb-2 uppercase tracking-widest flex items-center gap-2">
          <Zap className="w-4 h-4 text-emerald-400" />
          Auto-Hunt Integration
        </h3>
        <p className="text-xs text-emerald-500/70 leading-relaxed max-w-2xl">
          The Automation Engine is configured to prioritize installed system tools for maximum performance. 
          If a tool is missing from the environment, the engine automatically falls back to internal Node.js 
          implementations (Puppeteer, Portscanner, Axios) to ensure the hunt continues without interruption.
        </p>
      </div>
    </div>
  );
}

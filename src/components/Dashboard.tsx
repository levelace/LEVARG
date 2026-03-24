import React, { useState, useEffect } from 'react';
import { Activity, Shield, Search, FlaskConical, GitBranch, Database, Terminal } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState({
    scopes: 0,
    endpoints: 0,
    payloads: 0,
    flows: 0
  });
  const [recentActivity, setRecentActivity] = useState<any[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [scopes, endpoints, payloads, flows, history] = await Promise.all([
          fetch('/api/scopes').then(r => r.json()),
          fetch('/api/endpoints').then(r => r.json()),
          fetch('/api/payloads').then(r => r.json()),
          fetch('/api/flows').then(r => r.json()),
          fetch('/api/history').then(r => r.json())
        ]);
        setStats({
          scopes: scopes.length || 0,
          endpoints: endpoints.length || 0,
          payloads: payloads.length || 0,
          flows: flows.length || 0
        });
        setRecentActivity(history.slice(0, 5) || []);
      } catch (err) {
        console.error('Failed to fetch dashboard data', err);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 5000); // Live data polling
    return () => clearInterval(interval);
  }, []);

  const cards = [
    { label: 'Active Scopes', value: stats.scopes, icon: Shield, color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/30' },
    { label: 'Endpoints Found', value: stats.endpoints, icon: Search, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
    { label: 'Payload Sets', value: stats.payloads, icon: Database, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
    { label: 'State Flows', value: stats.flows, icon: GitBranch, color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30' },
  ];

  return (
    <div className="p-8 max-w-6xl mx-auto w-full h-full overflow-y-auto scrollbar-hide">
      <header className="mb-12 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Terminal className="w-8 h-8 text-emerald-400" />
          Mission Control
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">System Overview & Live Metrics</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        {cards.map((card, i) => (
          <div key={i} className={`bg-black/40 backdrop-blur-md border ${card.border} p-6 flex flex-col gap-4 rounded-lg group hover:bg-emerald-900/20 transition-all duration-300 relative overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]`}>
            <div className={`absolute -right-4 -top-4 w-24 h-24 ${card.bg} rounded-full blur-2xl opacity-50 group-hover:opacity-100 transition-opacity`} />
            <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(255,255,255,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none" />
            <div className="flex justify-between items-start relative z-10">
              <div className={`p-2 rounded-md ${card.bg} ${card.border} border shadow-[0_0_10px_rgba(0,0,0,0.5)]`}>
                <card.icon className={`w-5 h-5 ${card.color} drop-shadow-[0_0_5px_currentColor]`} />
              </div>
              <span className="text-[10px] font-mono text-emerald-500/50 uppercase">0{i + 1}</span>
            </div>
            <div className="relative z-10">
              <div className="text-4xl font-bold font-mono text-emerald-50 tracking-tighter drop-shadow-[0_0_8px_rgba(255,255,255,0.3)]">{card.value}</div>
              <div className="text-[10px] uppercase tracking-wider font-mono text-emerald-400/80 mt-1">{card.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-black/40 backdrop-blur-md border border-emerald-900/30 p-8 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
          <h3 className="text-sm font-mono uppercase tracking-widest text-emerald-300 mb-6 flex items-center gap-3">
            <Activity className="w-4 h-4 text-emerald-400 animate-pulse" />
            Live Network Activity
          </h3>
          <div className="space-y-4">
            {recentActivity.length === 0 ? (
              <div className="text-xs font-mono text-emerald-500/50 py-4 text-center border border-dashed border-emerald-900/30 rounded">No recent network activity detected.</div>
            ) : (
              recentActivity.map((item, i) => (
                <div key={i} className="flex items-center gap-4 py-3 border-b border-emerald-900/20 last:border-0 group hover:bg-emerald-900/10 px-2 -mx-2 rounded transition-colors">
                  <div className="w-2 h-2 rounded-full bg-emerald-500/50 group-hover:bg-emerald-400 group-hover:shadow-[0_0_8px_rgba(16,185,129,0.8)] transition-all" />
                  <div className="flex-1 truncate">
                    <div className="text-xs font-mono text-emerald-100 truncate flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${item.method === 'GET' ? 'bg-blue-500/20 text-blue-400' : item.method === 'POST' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}`}>
                        {item.method}
                      </span>
                      <span className="truncate">{item.url}</span>
                    </div>
                    <div className="text-[10px] text-emerald-500/60 font-mono uppercase mt-1">
                      {new Date(item.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                  <div className={`text-[10px] font-mono px-2 py-1 border rounded-sm ${
                    item.status >= 200 && item.status < 300 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
                    item.status >= 400 ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                    'bg-amber-500/10 border-amber-500/30 text-amber-400'
                  }`}>
                    {item.status || 'PENDING'}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-black/60 backdrop-blur-md border border-emerald-900/30 p-8 rounded-lg flex flex-col justify-between relative overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-[0.03] mix-blend-overlay pointer-events-none" />
          <div className="absolute top-0 right-0 w-[150px] h-[150px] bg-emerald-500/10 blur-[50px] rounded-full pointer-events-none" />
          
          <div className="relative z-10">
            <h3 className="text-sm font-mono uppercase tracking-widest text-emerald-300 mb-4 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> System Core
            </h3>
            <p className="text-xs text-emerald-100/70 font-mono leading-relaxed">
              LEVARG Engine is fully operational. Live data streams connected. Background workers standing by for automated recon and fuzzing tasks.
            </p>
          </div>
          <div className="mt-8 pt-8 border-t border-emerald-900/30 relative z-10">
            <div className="flex justify-between text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-3">
              <span>Core Temp</span>
              <span className="text-emerald-400">Optimal</span>
            </div>
            <div className="flex justify-between text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-3">
              <span>Memory</span>
              <span className="text-emerald-400">42%</span>
            </div>
            <div className="flex justify-between text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-3">
              <span>Network I/O</span>
              <span className="text-emerald-400 animate-pulse">Active</span>
            </div>
            <div className="mt-4 h-1.5 bg-emerald-950 rounded-full overflow-hidden relative">
              <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(16,185,129,0.5),transparent)] w-[50%] animate-[shimmer_2s_infinite_linear]" />
              <div className="h-full bg-emerald-500 w-[42%] shadow-[0_0_10px_rgba(16,185,129,0.8)]" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

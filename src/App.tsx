import React, { useState, useEffect } from 'react';
import { 
  Shield, Search, FlaskConical, Database, GitBranch, Terminal, 
  Activity, LayoutDashboard, Binary, Layers, History, Target
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

import Dashboard from './components/Dashboard';
import ScopeManager from './components/ScopeManager';
import ReconEngine from './components/ReconEngine';
import RequestLab from './components/RequestLab';
import FlowCapture from './components/FlowCapture';
import PayloadManager from './components/PayloadManager';
import Scanner from './components/Scanner';
import Encoder from './components/Encoder';
import StackGapAnalyzer from './components/StackGapAnalyzer';
import AutomationDashboard from './components/AutomationDashboard';
import HttpHistory from './components/HttpHistory';
import Methodology from './components/Methodology';
import Tools from './components/Tools';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type View = 'dashboard' | 'scope' | 'recon' | 'lab' | 'scanner' | 'flows' | 'payloads' | 'encoder' | 'stackgap' | 'automation' | 'history' | 'methodology' | 'tools';

const CyberBackground = () => {
  return (
    <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden bg-[#050505]">
      {/* Animated Grid */}
      <div 
        className="absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage: `
            linear-gradient(to right, #10b981 1px, transparent 1px),
            linear-gradient(to bottom, #10b981 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          transform: 'perspective(500px) rotateX(60deg) translateY(-100px) translateZ(-200px)',
          animation: 'grid-move 20s linear infinite',
        }}
      />
      {/* Radial Gradient Overlay */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent_0%,#050505_80%)]" />
      
      {/* Floating Particles/Data streams */}
      <div className="absolute inset-0 opacity-20">
        {Array.from({ length: 20 }).map((_, i) => (
          <div
            key={i}
            className="absolute w-[1px] bg-gradient-to-b from-transparent via-emerald-500 to-transparent"
            style={{
              left: `${Math.random() * 100}%`,
              top: `-${Math.random() * 100}%`,
              height: `${Math.random() * 200 + 50}px`,
              animation: `data-stream ${Math.random() * 3 + 2}s linear infinite`,
              animationDelay: `${Math.random() * 5}s`
            }}
          />
        ))}
      </div>
    </div>
  );
};

export default function App() {
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [repeaterTarget, setRepeaterTarget] = useState<any>(null);
  const [fuzzerTarget, setFuzzerTarget] = useState<string>('');
  const [encoderTarget, setEncoderTarget] = useState<string>('');

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'methodology', label: 'Methodology', icon: Target },
    { id: 'tools', label: 'Arsenal', icon: Shield },
    { id: 'automation', label: 'Auto-Hunter', icon: Terminal },
    { id: 'scope', label: 'Scope Control', icon: Shield },
    { id: 'recon', label: 'Recon Engine', icon: Search },
    { id: 'lab', label: 'Request Lab', icon: FlaskConical },
    { id: 'history', label: 'HTTP History', icon: History },
    { id: 'scanner', label: 'Fuzzing Scanner', icon: Activity },
    { id: 'stackgap', label: 'Stack Gap Analyzer', icon: Layers },
    { id: 'encoder', label: 'Data Encoder', icon: Binary },
    { id: 'flows', label: 'State Engine', icon: GitBranch },
    { id: 'payloads', label: 'Payloads', icon: Database },
  ];

  const handleSendToRepeater = (req: any) => { setRepeaterTarget(req); setActiveView('lab'); };
  const handleSendToFuzzer = (url: string) => { setFuzzerTarget(url); setActiveView('scanner'); };
  const handleSendToEncoder = (text: string) => { setEncoderTarget(text); setActiveView('encoder'); };

  return (
    <div className="flex h-screen bg-transparent text-zinc-300 font-sans selection:bg-emerald-500/30 selection:text-emerald-200 relative">
      <CyberBackground />
      
      {/* Sidebar */}
      <aside className="w-64 border-r border-emerald-900/30 flex flex-col bg-black/40 backdrop-blur-md z-10 shadow-[4px_0_24px_rgba(16,185,129,0.05)]">
        <div className="p-6 border-b border-emerald-900/30 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent" />
          <h1 className="text-2xl font-bold tracking-tighter flex items-center gap-2 text-emerald-50 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]">
            <Terminal className="w-6 h-6 text-emerald-400" />
            LEVARG
          </h1>
          <p className="text-[10px] uppercase tracking-widest text-emerald-500/70 mt-1 font-mono">Cyber Lab Engine</p>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto scrollbar-hide">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id as View)}
              className={cn(
                "w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-all duration-200 group rounded-md relative overflow-hidden",
                activeView === item.id 
                  ? "bg-emerald-500/15 text-emerald-300 shadow-[inset_0_0_12px_rgba(16,185,129,0.1)] border border-emerald-500/20" 
                  : "hover:bg-emerald-900/20 text-zinc-400 hover:text-emerald-100 border border-transparent"
              )}
            >
              <item.icon className={cn("w-4 h-4 relative z-10", activeView === item.id ? "text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.8)]" : "text-zinc-500 group-hover:text-emerald-400/70")} />
              <span className="font-medium font-mono text-xs uppercase tracking-wider relative z-10">{item.label}</span>
              {activeView === item.id && (
                <motion.div layoutId="active-pill" className="absolute left-0 top-0 bottom-0 w-1 bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,1)]" />
              )}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-emerald-900/30 bg-black/20">
          <div className="flex items-center gap-3 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-900/50">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400/90">System Online</span>
            <div className="ml-auto text-[9px] font-mono text-emerald-500/50">v1.0.0</div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden bg-transparent relative flex flex-col z-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeView}
            initial={{ opacity: 0, scale: 0.98, filter: 'blur(4px)' }}
            animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
            exit={{ opacity: 0, scale: 1.02, filter: 'blur(4px)' }}
            transition={{ duration: 0.3, ease: "easeOut" }}
            className="h-full flex flex-col overflow-hidden p-2"
          >
            <div className="h-full bg-black/60 backdrop-blur-xl border border-emerald-900/30 rounded-xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.5)] relative">
              {/* Scanline effect */}
              <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:100%_4px] z-50 opacity-50" />
              
              {activeView === 'dashboard' && <Dashboard />}
              {activeView === 'automation' && <AutomationDashboard />}
              {activeView === 'scope' && <ScopeManager />}
              {activeView === 'recon' && <ReconEngine onSendToRepeater={handleSendToRepeater} onSendToFuzzer={handleSendToFuzzer} onSendToEncoder={handleSendToEncoder} />}
              {activeView === 'lab' && <RequestLab initialRequest={repeaterTarget} />}
              {activeView === 'history' && <HttpHistory />}
              {activeView === 'scanner' && <Scanner initialUrl={fuzzerTarget} />}
              {activeView === 'stackgap' && <StackGapAnalyzer />}
              {activeView === 'encoder' && <Encoder initialText={encoderTarget} />}
              {activeView === 'flows' && <FlowCapture />}
              {activeView === 'payloads' && <PayloadManager />}
              {activeView === 'methodology' && <Methodology />}
              {activeView === 'tools' && <Tools />}
            </div>
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

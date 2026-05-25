import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Shield, Search, FlaskConical, Database, GitBranch, Terminal,
  Activity, LayoutDashboard, Binary, Layers, History, Target,
  Globe, KeyRound, Lock, LogIn, Smartphone, ChevronDown, ChevronRight,
  Compass, Crosshair, Beaker, Wrench, Archive, UserCheck,
  Menu, X, Info, Replace, ShieldAlert,
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
import BrowserPanel from './components/BrowserPanel';
import SessionsPanel from './components/SessionsPanel';
import CredentialsPanel from './components/CredentialsPanel';
import AuthFlowsPanel from './components/AuthFlowsPanel';
import OSBrowserPairPanel from './components/OSBrowserPairPanel';
import IdentityDashboard from './components/IdentityDashboard';
import About from './components/About';
import WafPanel from './components/WafPanel';
import OriginIpPanel from './components/OriginIpPanel';
import EndpointHeadersPanel from './components/EndpointHeadersPanel';
import MatchReplacePanel from './components/MatchReplacePanel';
import StridePanel from './components/StridePanel';
import SubdomainPanel from './components/SubdomainPanel';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type View =
  | 'dashboard' | 'methodology' | 'tools'
  | 'scope' | 'recon'
  | 'identity' | 'browser' | 'sessions' | 'credentials' | 'authflows' | 'osbridge'
  | 'automation' | 'lab' | 'scanner' | 'stackgap' | 'flows' | 'waf' | 'originip'
  | 'encoder' | 'payloads' | 'endpointheaders' | 'matchreplace'
  | 'stride' | 'subdomains'
  | 'history'
  | 'about';

interface NavItem { id: View; label: string; icon: React.ComponentType<{ className?: string }>; }
interface NavSection { id: string; label: string; icon: React.ComponentType<{ className?: string }>; items: NavItem[]; }

const NAV_SECTIONS: NavSection[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: Compass,
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { id: 'methodology', label: 'Methodology', icon: Target },
      { id: 'tools', label: 'Arsenal', icon: Shield },
    ],
  },
  {
    id: 'targeting',
    label: 'Targeting',
    icon: Crosshair,
    items: [
      { id: 'scope', label: 'Scope Control', icon: Shield },
      { id: 'recon', label: 'Recon Engine', icon: Search },
      { id: 'subdomains', label: 'Subdomain Enum', icon: Globe },
    ],
  },
  {
    id: 'identity',
    label: 'Auth & Identity',
    icon: UserCheck,
    items: [
      { id: 'identity', label: 'Identity Hub', icon: LayoutDashboard },
      { id: 'browser', label: 'Built-in Browser', icon: Globe },
      { id: 'sessions', label: 'Auth Sessions', icon: KeyRound },
      { id: 'credentials', label: 'Credentials', icon: Lock },
      { id: 'authflows', label: 'Auth Flows', icon: LogIn },
      { id: 'osbridge', label: 'OS Browser Bridge', icon: Smartphone },
    ],
  },
  {
    id: 'testing',
    label: 'Testing',
    icon: Beaker,
    items: [
      { id: 'automation', label: 'Auto-Hunter', icon: Terminal },
      { id: 'lab', label: 'Request Lab', icon: FlaskConical },
      { id: 'scanner', label: 'Fuzzing Scanner', icon: Activity },
      { id: 'stackgap', label: 'Stack Gap', icon: Layers },
      { id: 'waf', label: 'WAF Analysis', icon: Shield },
      { id: 'originip', label: 'Origin IP', icon: Globe },
      { id: 'stride', label: 'STRIDE Model', icon: ShieldAlert },
      { id: 'flows', label: 'State Engine', icon: GitBranch },
    ],
  },
  {
    id: 'tooling',
    label: 'Tooling',
    icon: Wrench,
    items: [
      { id: 'encoder', label: 'Data Encoder', icon: Binary },
      { id: 'payloads', label: 'Payloads', icon: Database },
      { id: 'endpointheaders', label: 'Endpoint Headers', icon: Terminal },
      { id: 'matchreplace', label: 'Match & Replace', icon: Replace },
    ],
  },
  {
    id: 'records',
    label: 'Records',
    icon: Archive,
    items: [
      { id: 'history', label: 'HTTP History', icon: History },
    ],
  },
  {
    id: 'system',
    label: 'System',
    icon: Info,
    items: [
      { id: 'about', label: 'About', icon: Info },
    ],
  },
];

const sectionFor = (view: View): string =>
  NAV_SECTIONS.find((s) => s.items.some((i) => i.id === view))?.id ?? 'overview';

const CyberBackground = () => {
  return (
    <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden bg-[#050505]">
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
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent_0%,#050505_80%)]" />
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
              animationDelay: `${Math.random() * 5}s`,
            }}
          />
        ))}
      </div>
    </div>
  );
};

function useIsMobile() {
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 767px)');
    const handler = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return isMobile;
}

export default function App() {
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const isMobile = useIsMobile();
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    overview: true,
    targeting: true,
    identity: true,
    testing: true,
    tooling: false,
    records: false,
    system: false,
  });
  const [repeaterTarget, setRepeaterTarget] = useState<unknown>(null);
  const [fuzzerTarget, setFuzzerTarget] = useState<string>('');
  const [encoderTarget, setEncoderTarget] = useState<string>('');

  const handleNavSelect = useCallback((view: View) => {
    setActiveView(view);
    if (isMobile) setSidebarOpen(false);
  }, [isMobile]);

  // Auto-expand the section containing the active view.
  useEffect(() => {
    const sec = sectionFor(activeView);
    setOpenSections((prev) => (prev[sec] ? prev : { ...prev, [sec]: true }));
  }, [activeView]);

  const handleSendToRepeater = (req: unknown) => { setRepeaterTarget(req); setActiveView('lab'); };
  const handleSendToFuzzer = (url: string) => { setFuzzerTarget(url); setActiveView('scanner'); };
  const handleSendToEncoder = (text: string) => { setEncoderTarget(text); setActiveView('encoder'); };

  const breadcrumb = useMemo(() => {
    const sec = NAV_SECTIONS.find((s) => s.items.some((i) => i.id === activeView));
    const item = sec?.items.find((i) => i.id === activeView);
    return { sectionLabel: sec?.label ?? '', itemLabel: item?.label ?? '' };
  }, [activeView]);

  const toggleSection = (id: string) =>
    setOpenSections((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="flex h-screen bg-transparent text-zinc-300 font-sans selection:bg-emerald-500/30 selection:text-emerald-200 relative">
      <CyberBackground />

      {/* Mobile overlay */}
      {isMobile && sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 backdrop-blur-sm"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar — fixed drawer on mobile, static on desktop */}
      <aside
        className={cn(
          'border-r border-emerald-900/30 flex flex-col bg-black/90 md:bg-black/40 backdrop-blur-md shadow-[4px_0_24px_rgba(16,185,129,0.05)]',
          'transition-transform duration-300 ease-in-out',
          isMobile
            ? 'fixed inset-y-0 left-0 w-72 z-40 pt-[env(safe-area-inset-top)]'
            : 'w-64 z-10 relative',
          isMobile && !sidebarOpen && '-translate-x-full',
        )}
      >
        <div className="p-4 md:p-6 border-b border-emerald-900/30 relative overflow-hidden flex items-center justify-between">
          <div>
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent" />
            <h1 className="text-xl md:text-2xl font-bold tracking-tighter flex items-center gap-2 text-emerald-50 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]">
              <Terminal className="w-5 h-5 md:w-6 md:h-6 text-emerald-400" />
              LEVARG
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-emerald-500/70 mt-1 font-mono">
              Cyber Lab Engine
            </p>
          </div>
          {isMobile && (
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-2 rounded-lg text-emerald-400 hover:bg-emerald-900/30 active:bg-emerald-900/50 min-w-[44px] min-h-[44px] flex items-center justify-center"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        <nav className="flex-1 px-3 py-3 md:py-4 space-y-2 md:space-y-3 overflow-y-auto scrollbar-hide">
          {NAV_SECTIONS.map((section) => {
            const SectionIcon = section.icon;
            const isOpen = openSections[section.id];
            const containsActive = section.items.some((i) => i.id === activeView);
            return (
              <div key={section.id}>
                <button
                  onClick={() => toggleSection(section.id)}
                  className={cn(
                    'w-full flex items-center gap-2 px-2 py-2.5 md:py-1.5 text-[11px] md:text-[10px] uppercase tracking-[0.18em] font-mono rounded transition-colors min-h-[44px] md:min-h-0',
                    containsActive
                      ? 'text-emerald-300'
                      : 'text-emerald-500/60 hover:text-emerald-300',
                  )}
                >
                  <SectionIcon className="w-4 h-4 md:w-3 md:h-3" />
                  <span className="flex-1 text-left">{section.label}</span>
                  {isOpen ? (
                    <ChevronDown className="w-4 h-4 md:w-3 md:h-3 opacity-70" />
                  ) : (
                    <ChevronRight className="w-4 h-4 md:w-3 md:h-3 opacity-70" />
                  )}
                </button>
                <AnimatePresence initial={false}>
                  {isOpen && (
                    <motion.div
                      key="section-body"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.18 }}
                      className="overflow-hidden"
                    >
                      <div className="mt-1 ml-2 pl-2 border-l border-emerald-900/40 space-y-0.5">
                        {section.items.map((item) => {
                          const Icon = item.icon;
                          const isActive = activeView === item.id;
                          return (
                            <button
                              key={item.id}
                              onClick={() => handleNavSelect(item.id)}
                              className={cn(
                                'w-full flex items-center gap-3 md:gap-2 px-3 md:px-2 py-3 md:py-1.5 text-xs transition-all rounded relative overflow-hidden min-h-[44px] md:min-h-0 active:scale-[0.98]',
                                isActive
                                  ? 'bg-emerald-500/15 text-emerald-300 shadow-[inset_0_0_12px_rgba(16,185,129,0.1)] border border-emerald-500/25'
                                  : 'hover:bg-emerald-900/20 text-zinc-400 hover:text-emerald-100 border border-transparent',
                              )}
                            >
                              <Icon
                                className={cn(
                                  'w-4.5 h-4.5 md:w-3.5 md:h-3.5 shrink-0',
                                  isActive
                                    ? 'text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.8)]'
                                    : 'text-zinc-500',
                                )}
                              />
                              <span className="font-mono uppercase tracking-wider text-xs md:text-[11px] truncate">
                                {item.label}
                              </span>
                              {isActive && (
                                <motion.div
                                  layoutId="active-pill"
                                  className="absolute left-0 top-0 bottom-0 w-1 bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,1)]"
                                />
                              )}
                            </button>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </nav>

        <div className="p-3 md:p-4 border-t border-emerald-900/30 bg-black/20" style={{ paddingBottom: 'max(0.75rem, env(safe-area-inset-bottom))' }}>
          <div className="flex items-center gap-3 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-900/50">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            <button
              onClick={() => handleNavSelect('about')}
              className="flex-1 flex items-center justify-between hover:text-emerald-300 transition-colors cursor-pointer bg-transparent border-none p-0"
            >
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400/90">System Online</span>
              <span className="text-[9px] font-mono text-emerald-500/50 hover:text-emerald-400 transition-colors">v1.0.0</span>
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden bg-transparent relative flex flex-col z-10 min-w-0">
        {/* Mobile header + Breadcrumb */}
        <div className="px-3 md:px-4 pt-2 md:pt-3 pb-1 flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-emerald-500/70" style={{ paddingTop: 'max(0.5rem, env(safe-area-inset-top))' }}>
          {isMobile && (
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 -ml-1 rounded-lg text-emerald-400 hover:bg-emerald-900/30 active:bg-emerald-900/50 min-w-[44px] min-h-[44px] flex items-center justify-center mr-1"
            >
              <Menu className="w-5 h-5" />
            </button>
          )}
          <span>{breadcrumb.sectionLabel}</span>
          <ChevronRight className="w-3 h-3 opacity-60" />
          <span className="text-emerald-300">{breadcrumb.itemLabel}</span>
        </div>

        <AnimatePresence mode="wait">
          <motion.div
            key={activeView}
            initial={{ opacity: 0, scale: 0.98, filter: 'blur(4px)' }}
            animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
            exit={{ opacity: 0, scale: 1.02, filter: 'blur(4px)' }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
            className="h-full flex flex-col overflow-hidden p-1.5 md:p-2"
          >
            <div className="h-full bg-black/60 backdrop-blur-xl border border-emerald-900/30 rounded-xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.5)] relative">
              <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:100%_4px] z-50 opacity-50" />

              {activeView === 'dashboard' && <Dashboard />}
              {activeView === 'methodology' && <Methodology />}
              {activeView === 'tools' && <Tools />}

              {activeView === 'scope' && <ScopeManager />}
              {activeView === 'recon' && (
                <ReconEngine
                  onSendToRepeater={handleSendToRepeater}
                  onSendToFuzzer={handleSendToFuzzer}
                  onSendToEncoder={handleSendToEncoder}
                />
              )}

              {activeView === 'identity' && (
                <IdentityDashboard onNavigate={(v) => setActiveView(v)} />
              )}
              {activeView === 'browser' && <BrowserPanel />}
              {activeView === 'sessions' && <SessionsPanel />}
              {activeView === 'credentials' && <CredentialsPanel />}
              {activeView === 'authflows' && <AuthFlowsPanel />}
              {activeView === 'osbridge' && <OSBrowserPairPanel />}

              {activeView === 'automation' && <AutomationDashboard />}
              {activeView === 'lab' && <RequestLab initialRequest={repeaterTarget} />}
              {activeView === 'scanner' && <Scanner initialUrl={fuzzerTarget} />}
              {activeView === 'stackgap' && <StackGapAnalyzer />}
              {activeView === 'waf' && <WafPanel />}
              {activeView === 'originip' && <OriginIpPanel />}
              {activeView === 'subdomains' && <SubdomainPanel />}
              {activeView === 'flows' && <FlowCapture />}

              {activeView === 'encoder' && <Encoder initialText={encoderTarget} />}
              {activeView === 'payloads' && <PayloadManager />}
              {activeView === 'endpointheaders' && <EndpointHeadersPanel />}
              {activeView === 'matchreplace' && <MatchReplacePanel />}

              {activeView === 'stride' && <StridePanel />}

              {activeView === 'history' && <HttpHistory />}

              {activeView === 'about' && <About />}
            </div>
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

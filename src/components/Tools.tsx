import React, { useState, useEffect, useCallback } from 'react';
import { Terminal, Shield, CheckCircle2, XCircle, AlertTriangle, Search, Zap, Globe, Lock, Download, FolderOpen, ChevronRight, Loader2, Package, Database, FileText, Wrench, RefreshCw } from 'lucide-react';

interface InstallMethod {
  label: string;
  command: string;
}

interface ToolStatus {
  name: string;
  category: string;
  phase: string;
  description: string;
  status: 'installed' | 'missing' | 'fallback';
  method: 'BINARY' | 'NPX' | 'POLYFILL' | 'UNAVAILABLE';
  version: string | null;
  installMethods: InstallMethod[];
}

interface ResourceStatus {
  name: string;
  type: 'wordlist' | 'templates';
  description: string;
  installed: boolean;
  path: string;
  size: string | null;
  installMethods: InstallMethod[];
}

const categoryIcons: Record<string, React.ReactNode> = {
  Recon: <Search className="w-5 h-5 text-emerald-400" />,
  Fingerprinting: <Terminal className="w-5 h-5 text-emerald-400" />,
  Discovery: <Globe className="w-5 h-5 text-emerald-400" />,
  Vulnerability: <AlertTriangle className="w-5 h-5 text-emerald-400" />,
  Exploitation: <Lock className="w-5 h-5 text-emerald-400" />,
  Utility: <Wrench className="w-5 h-5 text-emerald-400" />,
};

export default function Tools() {
  const [toolStatuses, setToolStatuses] = useState<ToolStatus[]>([]);
  const [resources, setResources] = useState<ResourceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState<string | null>(null);
  const [installOutput, setInstallOutput] = useState<{ name: string; success: boolean; output: string } | null>(null);
  const [expandedInstall, setExpandedInstall] = useState<string | null>(null);
  const [pdtmBatchRunning, setPdtmBatchRunning] = useState(false);
  const [activeTab, setActiveTab] = useState<'tools' | 'resources'>('tools');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [toolsRes, resourcesRes] = await Promise.all([
        fetch('/api/tools/status'),
        fetch('/api/resources/status'),
      ]);
      if (toolsRes.ok) setToolStatuses(await toolsRes.json());
      if (resourcesRes.ok) setResources(await resourcesRes.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleInstallTool = async (toolName: string, methodIndex: number) => {
    setInstalling(toolName);
    setInstallOutput(null);
    try {
      const res = await fetch('/api/tools/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolName, methodIndex }),
      });
      const data = await res.json();
      setInstallOutput({ name: toolName, ...data });
      await fetchAll();
    } catch (err: any) {
      setInstallOutput({ name: toolName, success: false, output: err.message });
    } finally {
      setInstalling(null);
    }
  };

  const handleInstallResource = async (resourceName: string, methodIndex: number) => {
    setInstalling(resourceName);
    setInstallOutput(null);
    try {
      const res = await fetch('/api/resources/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resourceName, methodIndex }),
      });
      const data = await res.json();
      setInstallOutput({ name: resourceName, ...data });
      await fetchAll();
    } catch (err: any) {
      setInstallOutput({ name: resourceName, success: false, output: err.message });
    } finally {
      setInstalling(null);
    }
  };

  const handlePdtmInstallAll = async () => {
    setPdtmBatchRunning(true);
    setInstallOutput(null);
    try {
      const res = await fetch('/api/tools/pdtm-install-all', { method: 'POST' });
      const data = await res.json();
      setInstallOutput({ name: 'pdtm batch install', ...data });
      await fetchAll();
    } catch (err: any) {
      setInstallOutput({ name: 'pdtm batch install', success: false, output: err.message });
    } finally {
      setPdtmBatchRunning(false);
    }
  };

  const installedCount = toolStatuses.filter(t => t.status === 'installed').length;
  const totalCount = toolStatuses.length;
  const pdtmInstalled = toolStatuses.find(t => t.name === 'pdtm')?.status === 'installed';

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide">
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Shield className="w-8 h-8 text-emerald-400" />
          Security Arsenal
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">
          {loading ? 'Scanning...' : `${installedCount}/${totalCount} tools installed`}
        </p>
      </header>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setActiveTab('tools')}
          className={`px-4 py-2 rounded-md text-xs font-mono uppercase tracking-widest transition-all ${
            activeTab === 'tools'
              ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-300'
              : 'bg-black/30 border border-emerald-900/30 text-emerald-500/50 hover:text-emerald-400'
          }`}
        >
          <Package className="w-3.5 h-3.5 inline mr-2" />Tools
        </button>
        <button
          onClick={() => setActiveTab('resources')}
          className={`px-4 py-2 rounded-md text-xs font-mono uppercase tracking-widest transition-all ${
            activeTab === 'resources'
              ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-300'
              : 'bg-black/30 border border-emerald-900/30 text-emerald-500/50 hover:text-emerald-400'
          }`}
        >
          <Database className="w-3.5 h-3.5 inline mr-2" />Wordlists & Templates
        </button>
        <button
          onClick={fetchAll}
          disabled={loading}
          className="ml-auto px-3 py-2 rounded-md text-xs font-mono uppercase tracking-widest bg-black/30 border border-emerald-900/30 text-emerald-500/50 hover:text-emerald-400 transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 inline mr-1 ${loading ? 'animate-spin' : ''}`} />Refresh
        </button>
      </div>

      {/* Install output banner */}
      {installOutput && (
        <div className={`mb-6 p-4 rounded-lg border text-xs font-mono ${
          installOutput.success
            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
            : 'bg-red-950/40 border-red-500/30 text-red-300'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            {installOutput.success ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
            <span className="font-bold uppercase tracking-widest">{installOutput.name}</span>
            <span>{installOutput.success ? 'installed successfully' : 'installation failed'}</span>
            <button onClick={() => setInstallOutput(null)} className="ml-auto text-emerald-500/50 hover:text-emerald-400">&times;</button>
          </div>
          <pre className="whitespace-pre-wrap max-h-32 overflow-y-auto text-[10px] opacity-70">{installOutput.output}</pre>
        </div>
      )}

      {activeTab === 'tools' && (
        <>
          {/* pdtm batch install bar */}
          {pdtmInstalled && (
            <div className="mb-6 p-4 bg-emerald-950/20 border border-emerald-900/30 rounded-lg flex items-center gap-4">
              <Wrench className="w-5 h-5 text-emerald-400 shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-emerald-200 font-mono uppercase tracking-widest">pdtm detected</p>
                <p className="text-[10px] text-emerald-500/60 mt-1">Install all missing ProjectDiscovery tools in one click.</p>
              </div>
              <button
                onClick={handlePdtmInstallAll}
                disabled={pdtmBatchRunning}
                className="px-4 py-2 rounded-md text-xs font-mono uppercase tracking-widest bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 transition-all disabled:opacity-50"
              >
                {pdtmBatchRunning ? <Loader2 className="w-3.5 h-3.5 inline mr-1 animate-spin" /> : <Download className="w-3.5 h-3.5 inline mr-1" />}
                {pdtmBatchRunning ? 'Installing...' : 'Install All PD Tools'}
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {toolStatuses.map((tool) => (
              <div key={tool.name} className="bg-black/40 backdrop-blur-md border border-emerald-900/30 p-6 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative group overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

                <div className="flex justify-between items-start mb-3">
                  <div className="p-2 bg-emerald-500/10 rounded-md border border-emerald-500/20">
                    {categoryIcons[tool.category] || <Terminal className="w-5 h-5 text-emerald-400" />}
                  </div>
                  <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-mono uppercase tracking-widest border ${
                    loading ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-500/50' :
                    tool.status === 'installed' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
                    tool.status === 'fallback' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                    'bg-red-500/10 border-red-500/30 text-red-400'
                  }`}>
                    {loading ? (
                      <div className="w-2 h-2 bg-emerald-500/50 rounded-full animate-pulse" />
                    ) : tool.status === 'installed' ? (
                      <CheckCircle2 className="w-3 h-3" />
                    ) : tool.status === 'fallback' ? (
                      <AlertTriangle className="w-3 h-3" />
                    ) : (
                      <XCircle className="w-3 h-3" />
                    )}
                    {loading ? 'Checking...' : tool.status === 'installed' ? 'Installed' : tool.status === 'fallback' ? tool.method : 'Missing'}
                  </div>
                </div>

                <h3 className="text-lg font-bold text-emerald-50 mb-1 font-mono">{tool.name}</h3>
                {tool.version && (
                  <p className="text-[10px] text-emerald-400/60 font-mono mb-1">v{tool.version}</p>
                )}
                <p className="text-[10px] text-emerald-500/60 mb-3">{tool.description}</p>

                <div className="flex items-center gap-2 mb-3">
                  <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400/50 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10">
                    {tool.category}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400/50 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10">
                    {tool.phase}
                  </span>
                </div>

                {/* Install dropdown */}
                {tool.status !== 'installed' && (
                  <div className="mt-3 border-t border-emerald-900/20 pt-3">
                    <button
                      onClick={() => setExpandedInstall(expandedInstall === tool.name ? null : tool.name)}
                      className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-widest text-emerald-400 hover:text-emerald-300 transition-colors"
                    >
                      <Download className="w-3 h-3" />
                      Install
                      <ChevronRight className={`w-3 h-3 transition-transform ${expandedInstall === tool.name ? 'rotate-90' : ''}`} />
                    </button>
                    {expandedInstall === tool.name && (
                      <div className="mt-2 space-y-1">
                        {tool.installMethods.map((method, i) => (
                          <button
                            key={i}
                            onClick={() => handleInstallTool(tool.name, i)}
                            disabled={installing !== null}
                            className="w-full text-left px-3 py-1.5 rounded text-[10px] font-mono bg-emerald-500/5 border border-emerald-500/10 text-emerald-400/70 hover:bg-emerald-500/15 hover:text-emerald-300 transition-all disabled:opacity-30"
                          >
                            {installing === tool.name ? <Loader2 className="w-3 h-3 inline mr-1 animate-spin" /> : <ChevronRight className="w-3 h-3 inline mr-1" />}
                            {method.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {activeTab === 'resources' && (
        <div className="space-y-6">
          {resources.map((res) => (
            <div key={res.name} className="bg-black/40 backdrop-blur-md border border-emerald-900/30 p-6 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative group overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-emerald-500/10 rounded-md border border-emerald-500/20">
                    {res.type === 'wordlist' ? <FileText className="w-5 h-5 text-emerald-400" /> : <FolderOpen className="w-5 h-5 text-emerald-400" />}
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-emerald-50 font-mono">{res.name}</h3>
                    <p className="text-[10px] text-emerald-500/60 mt-0.5">{res.description}</p>
                  </div>
                </div>
                <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-mono uppercase tracking-widest border ${
                  res.installed
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-red-500/10 border-red-500/30 text-red-400'
                }`}>
                  {res.installed ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                  {res.installed ? 'Installed' : 'Not installed'}
                </div>
              </div>

              {res.installed && (
                <div className="flex gap-4 text-[10px] font-mono text-emerald-400/50 mb-3">
                  <span>Path: {res.path}</span>
                  {res.size && <span>Size: {res.size}</span>}
                </div>
              )}

              {!res.installed && (
                <div className="mt-3 border-t border-emerald-900/20 pt-3">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 mb-2">
                    <Download className="w-3 h-3 inline mr-1" /> Install
                  </p>
                  <div className="space-y-1">
                    {res.installMethods.map((method, i) => (
                      <button
                        key={i}
                        onClick={() => handleInstallResource(res.name, i)}
                        disabled={installing !== null}
                        className="w-full text-left px-3 py-1.5 rounded text-[10px] font-mono bg-emerald-500/5 border border-emerald-500/10 text-emerald-400/70 hover:bg-emerald-500/15 hover:text-emerald-300 transition-all disabled:opacity-30"
                      >
                        {installing === res.name ? <Loader2 className="w-3 h-3 inline mr-1 animate-spin" /> : <ChevronRight className="w-3 h-3 inline mr-1" />}
                        {method.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-12 p-6 bg-emerald-950/20 border border-emerald-900/30 rounded-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 opacity-10">
          <Terminal className="w-24 h-24 text-emerald-500" />
        </div>
        <h3 className="text-sm font-bold text-emerald-100 mb-2 uppercase tracking-widest flex items-center gap-2">
          <Zap className="w-4 h-4 text-emerald-400" />
          Auto-Hunt Integration
        </h3>
        <p className="text-xs text-emerald-500/70 leading-relaxed max-w-2xl">
          The Automation Engine prioritizes installed system tools for maximum performance.
          Missing tools fall back to internal Node.js implementations (Puppeteer, Portscanner, Axios).
          Use <strong>pdtm</strong> to batch-install all ProjectDiscovery tools, then add <strong>SecLists</strong> and
          <strong> Nuclei Templates</strong> for full coverage.
        </p>
      </div>
    </div>
  );
}

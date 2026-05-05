import React, { useState, useEffect, useCallback } from 'react';
import {
  Info, Download, RefreshCw, CheckCircle, AlertTriangle,
  GitBranch, Clock, Cpu, Server, Package, ArrowUpCircle,
  Loader2, ChevronDown, ChevronRight,
} from 'lucide-react';

interface VersionInfo {
  version: string;
  branch: string;
  commit: string;
  commitDate: string;
  nodeVersion: string;
  platform: string;
  uptime: number;
  pid: number;
}

interface UpgradeCheck {
  currentVersion: string;
  latestVersion: string;
  currentCommit: string;
  latestCommit: string;
  behind: number;
  updateAvailable: boolean;
  branch: string;
  changelog: string[];
}

interface UpgradeResult {
  success: boolean;
  version: string;
  commit: string;
  pullOutput: string;
  installOutput: string;
  restarting: boolean;
  error?: string;
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

export default function About() {
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [upgrade, setUpgrade] = useState<UpgradeCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [upgrading, setUpgrading] = useState(false);
  const [upgradeResult, setUpgradeResult] = useState<UpgradeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [changelogOpen, setChangelogOpen] = useState(false);

  const fetchVersion = useCallback(async () => {
    try {
      const res = await fetch('/api/version');
      if (!res.ok) throw new Error('Failed to fetch version');
      setVersion(await res.json());
    } catch (err: any) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    fetchVersion();
    const interval = setInterval(fetchVersion, 10_000);
    return () => clearInterval(interval);
  }, [fetchVersion]);

  const checkForUpdates = async () => {
    setChecking(true);
    setError(null);
    setUpgrade(null);
    setUpgradeResult(null);
    try {
      const res = await fetch('/api/upgrade/check');
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Check failed');
      }
      setUpgrade(await res.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setChecking(false);
    }
  };

  const applyUpgrade = async () => {
    setUpgrading(true);
    setError(null);
    try {
      const res = await fetch('/api/upgrade/apply', { method: 'POST' });
      const data: UpgradeResult = await res.json();
      if (!data.success) throw new Error(data.error || 'Upgrade failed');
      setUpgradeResult(data);
      // The server will restart — poll until it's back
      if (data.restarting) {
        setTimeout(pollServerRestart, 3000);
      }
    } catch (err: any) {
      setError(err.message);
      setUpgrading(false);
    }
  };

  const pollServerRestart = async () => {
    let attempts = 0;
    const maxAttempts = 30;
    const poll = async () => {
      try {
        const res = await fetch('/api/version');
        if (res.ok) {
          setUpgrading(false);
          setUpgrade(null);
          fetchVersion();
          return;
        }
      } catch { /* server still restarting */ }

      attempts++;
      if (attempts < maxAttempts) {
        setTimeout(poll, 2000);
      } else {
        setUpgrading(false);
        setError('Server did not come back after upgrade. Refresh the page manually.');
      }
    };
    poll();
  };

  const infoCards = version ? [
    { label: 'Version', value: `v${version.version}`, icon: Package, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
    { label: 'Git Branch', value: version.branch, icon: GitBranch, color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/30' },
    { label: 'Commit', value: version.commit, icon: Info, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
    { label: 'Uptime', value: formatUptime(version.uptime), icon: Clock, color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30' },
  ] : [];

  return (
    <div className="p-8 max-w-5xl mx-auto w-full h-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />

      <header className="mb-12 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Info className="w-8 h-8 text-emerald-400" />
          About LEVARG
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">
          System Information & Upgrades
        </p>
      </header>

      {/* Version Cards */}
      {version && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
          {infoCards.map((card, i) => (
            <div
              key={i}
              className={`cyber-card ${card.border} p-5 flex flex-col gap-3 group hover:bg-emerald-900/20 transition-all duration-300`}
            >
              <div className={`absolute -right-4 -top-4 w-24 h-24 ${card.bg} rounded-full blur-2xl opacity-50 group-hover:opacity-100 transition-opacity`} />
              <div className="flex items-center gap-2 relative z-10">
                <div className={`p-1.5 rounded-md ${card.bg} ${card.border} border`}>
                  <card.icon className={`w-4 h-4 ${card.color}`} />
                </div>
                <span className="text-[10px] uppercase tracking-wider font-mono text-emerald-400/70">{card.label}</span>
              </div>
              <div className="text-lg font-bold font-mono text-emerald-50 tracking-tight relative z-10 truncate">{card.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* System Details */}
      {version && (
        <div className="cyber-card p-6 mb-10">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
          <h3 className="text-sm uppercase tracking-widest font-mono text-emerald-400 mb-4 flex items-center gap-2">
            <Server className="w-4 h-4" />
            System Details
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              { label: 'Node.js', value: version.nodeVersion },
              { label: 'Platform', value: version.platform },
              { label: 'Process ID', value: String(version.pid) },
              { label: 'Last Commit', value: version.commitDate || 'N/A' },
            ].map((item, i) => (
              <div key={i} className="flex items-center justify-between px-4 py-3 rounded-lg bg-black/30 border border-emerald-900/20">
                <span className="text-xs font-mono text-emerald-500/70 uppercase tracking-wider">{item.label}</span>
                <span className="text-sm font-mono text-emerald-100">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Upgrade Section */}
      <div className="cyber-card p-6">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <h3 className="text-sm uppercase tracking-widest font-mono text-emerald-400 mb-6 flex items-center gap-2">
          <ArrowUpCircle className="w-4 h-4" />
          Software Upgrade
        </h3>

        {/* Check for Updates Button */}
        {!upgrading && (
          <button
            onClick={checkForUpdates}
            disabled={checking}
            className="flex items-center gap-2 px-5 py-3 rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 hover:border-emerald-400/60 transition-all text-sm font-mono uppercase tracking-wider disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {checking ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Checking...
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4" />
                Check for Updates
              </>
            )}
          </button>
        )}

        {/* Error Display */}
        {error && (
          <div className="mt-4 flex items-start gap-3 p-4 rounded-lg bg-red-900/20 border border-red-500/30">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-red-300 font-mono">{error}</p>
            </div>
          </div>
        )}

        {/* No Update Available */}
        {upgrade && !upgrade.updateAvailable && (
          <div className="mt-6 flex items-center gap-3 p-4 rounded-lg bg-emerald-900/20 border border-emerald-500/30">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <div>
              <p className="text-sm text-emerald-300 font-mono">You're up to date!</p>
              <p className="text-xs text-emerald-500/70 font-mono mt-1">
                v{upgrade.currentVersion} ({upgrade.currentCommit}) on {upgrade.branch}
              </p>
            </div>
          </div>
        )}

        {/* Update Available */}
        {upgrade && upgrade.updateAvailable && !upgradeResult && (
          <div className="mt-6 space-y-4">
            <div className="flex items-start gap-3 p-4 rounded-lg bg-amber-900/20 border border-amber-500/30">
              <Download className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm text-amber-200 font-mono font-bold">
                  Update available: v{upgrade.currentVersion} → v{upgrade.latestVersion}
                </p>
                <p className="text-xs text-amber-400/70 font-mono mt-1">
                  {upgrade.behind} commit{upgrade.behind === 1 ? '' : 's'} behind origin/{upgrade.branch}
                </p>

                {/* Changelog */}
                {upgrade.changelog.length > 0 && (
                  <div className="mt-3">
                    <button
                      onClick={() => setChangelogOpen(!changelogOpen)}
                      className="flex items-center gap-1 text-xs font-mono text-amber-400/80 hover:text-amber-300 transition-colors"
                    >
                      {changelogOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      Changelog ({upgrade.changelog.length} commit{upgrade.changelog.length === 1 ? '' : 's'})
                    </button>
                    {changelogOpen && (
                      <div className="mt-2 max-h-40 overflow-y-auto scrollbar-hide rounded bg-black/30 p-3 border border-amber-900/30">
                        {upgrade.changelog.map((line, i) => (
                          <div key={i} className="text-xs font-mono text-amber-200/80 py-0.5">
                            {line}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Upgrade Button */}
            <button
              onClick={applyUpgrade}
              disabled={upgrading}
              className="flex items-center gap-2 px-6 py-3 rounded-lg bg-emerald-500/30 border border-emerald-400/50 text-emerald-200 hover:bg-emerald-500/40 hover:border-emerald-400/70 hover:shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all text-sm font-mono uppercase tracking-wider font-bold"
            >
              <Download className="w-4 h-4" />
              Upgrade to v{upgrade.latestVersion}
            </button>
          </div>
        )}

        {/* Upgrading State */}
        {upgrading && (
          <div className="mt-6 flex items-center gap-3 p-6 rounded-lg bg-cyan-900/20 border border-cyan-500/30">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
            <div>
              <p className="text-sm text-cyan-300 font-mono font-bold">
                {upgradeResult ? 'Restarting server...' : 'Applying upgrade...'}
              </p>
              <p className="text-xs text-cyan-500/70 font-mono mt-1">
                {upgradeResult
                  ? 'Please wait while the server restarts. This page will auto-refresh.'
                  : 'Pulling latest changes and installing dependencies...'}
              </p>
            </div>
          </div>
        )}

        {/* Upgrade Complete (before restart) */}
        {upgradeResult && upgradeResult.success && !upgrading && (
          <div className="mt-6 space-y-3">
            <div className="flex items-center gap-3 p-4 rounded-lg bg-emerald-900/20 border border-emerald-500/30">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              <div>
                <p className="text-sm text-emerald-300 font-mono font-bold">
                  Upgrade complete! Now running v{upgradeResult.version} ({upgradeResult.commit})
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

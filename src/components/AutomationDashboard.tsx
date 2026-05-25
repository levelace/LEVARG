import React, { useState, useEffect } from 'react';
import { Play, CheckCircle2, XCircle, Clock, Download, FileJson, FileText, FileCode2, Terminal, AlertCircle, Activity, ChevronDown, ChevronRight, Shield, Search, Globe, Zap, Eye, Lock, BarChart3, Wrench } from 'lucide-react';
import SessionSelector from './SessionSelector';

interface PhaseResult {
  status: 'completed' | 'failed' | 'skipped';
  findings: number;
  tools: { name: string; status: 'ok' | 'failed' | 'skipped'; detail?: string }[];
  data?: Record<string, unknown>;
  timestamp?: string;
}

const PHASE_META: Record<string, { label: string; description: string; icon: React.ComponentType<{ className?: string }> }> = {
  phase1: { label: 'Phase 1: Reconnaissance', description: 'Subdomain discovery, port scanning, asset enumeration', icon: Search },
  phase2: { label: 'Phase 2: Fingerprinting', description: 'HTTP fingerprinting, tech stack detection', icon: Eye },
  phase3: { label: 'Phase 3: Discovery', description: 'Active crawling, endpoint discovery, sensitive file probing', icon: Globe },
  phase4: { label: 'Phase 4: Exploitation', description: 'Fuzzing, 0day discovery, UEBA, WAF bypass, auth deep dive', icon: Zap },
  phase5: { label: 'Phase 5: Reporting', description: 'Final synthesis, PoC generation, vulnerability summary', icon: BarChart3 },
};

export default function AutomationDashboard() {
  const [targetUrl, setTargetUrl] = useState('');
  const [jobs, setJobs] = useState<any[]>([]);
  const [selectedJob, setSelectedJob] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [logFilter, setLogFilter] = useState<'all' | 'info' | 'warn' | 'vuln'>('all');
  const [error, setError] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [expandedPhases, setExpandedPhases] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'phases' | 'logs' | 'findings'>('phases');

  const fetchJobs = async () => {
    try {
      const res = await fetch('/api/automation/jobs');
      const data = await res.json();
      setJobs(data);
      
      if (selectedJob && selectedJob.status === 'running') {
        const updated = data.find((j: any) => j.id === selectedJob.id);
        if (updated) setSelectedJob(updated);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async (jobId: string) => {
    try {
      const res = await fetch(`/api/automation/jobs/${jobId}/logs`);
      const data = await res.json();
      setLogs(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchJobs();
    const interval = setInterval(fetchJobs, 5000);
    return () => clearInterval(interval);
  }, [selectedJob?.id]);

  useEffect(() => {
    if (selectedJob) {
      fetchLogs(selectedJob.id);
      const interval = setInterval(() => fetchLogs(selectedJob.id), 3000);
      return () => clearInterval(interval);
    }
  }, [selectedJob?.id]);

  const handleStart = async () => {
    if (!targetUrl) return;
    setLoading(true);
    setError('');
    
    try {
      const res = await fetch('/api/automation/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, sessionId: sessionId || undefined })
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      
      setTargetUrl('');
      fetchJobs();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = (format: 'json' | 'md' | 'txt') => {
    if (!selectedJob) return;

    let content = '';
    let mimeType = '';
    let extension = '';

    if (format === 'json') {
      content = JSON.stringify(selectedJob, null, 2);
      mimeType = 'application/json';
      extension = 'json';
    } else if (format === 'md') {
      content = `# Automation Report: ${selectedJob.target_url}\n\n`;
      content += `**Status:** ${selectedJob.status}\n`;
      content += `**Started:** ${new Date(selectedJob.created_at).toLocaleString()}\n`;
      content += `**Completed:** ${selectedJob.completed_at ? new Date(selectedJob.completed_at).toLocaleString() : 'N/A'}\n\n`;
      content += `## Findings\n\n`;
      
      if (selectedJob.findings && selectedJob.findings.length > 0) {
        selectedJob.findings.forEach((f: any, i: number) => {
          content += `### Finding ${i + 1}: ${f.phase} - ${f.type}\n`;
          content += "```json\n" + JSON.stringify(f, null, 2) + "\n```\n\n";
        });
      } else {
        content += "No findings recorded.\n";
      }
      mimeType = 'text/markdown';
      extension = 'md';
    } else if (format === 'txt') {
      content = `AUTOMATION REPORT\n=================\n`;
      content += `Target: ${selectedJob.target_url}\n`;
      content += `Status: ${selectedJob.status}\n`;
      content += `Started: ${new Date(selectedJob.created_at).toLocaleString()}\n`;
      content += `Completed: ${selectedJob.completed_at ? new Date(selectedJob.completed_at).toLocaleString() : 'N/A'}\n\n`;
      content += `FINDINGS:\n---------\n`;
      
      if (selectedJob.findings && selectedJob.findings.length > 0) {
        selectedJob.findings.forEach((f: any, i: number) => {
          content += `[${i + 1}] Phase: ${f.phase} | Type: ${f.type}\n`;
          content += `Details: ${JSON.stringify(f)}\n\n`;
        });
      } else {
        content += "No findings recorded.\n";
      }
      mimeType = 'text/plain';
      extension = 'txt';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `levarg-report-${selectedJob.id.substring(0, 8)}.${extension}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const togglePhase = (phaseId: string) => {
    setExpandedPhases(prev => {
      const next = new Set(prev);
      if (next.has(phaseId)) next.delete(phaseId);
      else next.add(phaseId);
      return next;
    });
  };

  const phaseResults: Record<string, PhaseResult> | null = selectedJob?.phase_results ?? null;

  const getPhaseStatus = (phaseId: string): 'completed' | 'running' | 'pending' | 'failed' => {
    if (phaseResults?.[phaseId]) return phaseResults[phaseId].status === 'completed' ? 'completed' : 'failed';
    if (selectedJob?.status === 'completed') return 'completed';
    if (selectedJob?.status === 'failed') return 'failed';
    // Infer from current phase
    const phaseNum = parseInt(phaseId.replace('phase', ''));
    const currentPhaseMatch = selectedJob?.phase?.match(/\d+/);
    const currentNum = currentPhaseMatch ? parseInt(currentPhaseMatch[0]) : 0;
    if (currentNum > phaseNum) return 'completed';
    if (currentNum === phaseNum) return 'running';
    return 'pending';
  };

  const toolStatusIcon = (status: 'ok' | 'failed' | 'skipped') => {
    if (status === 'ok') return <CheckCircle2 className="w-3 h-3 text-emerald-400" />;
    if (status === 'failed') return <XCircle className="w-3 h-3 text-red-400" />;
    return <Clock className="w-3 h-3 text-gray-500" />;
  };

  const phaseStatusColor = (status: string) => {
    if (status === 'completed') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (status === 'running') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    if (status === 'failed') return 'text-red-400 bg-red-500/10 border-red-500/30';
    return 'text-gray-500 bg-gray-500/10 border-gray-500/30';
  };

  // Get findings for a specific phase
  const getFindingsForPhase = (phaseId: string) => {
    if (!selectedJob?.findings) return [];
    const phaseNum = phaseId.replace('phase', '');
    return selectedJob.findings.filter((f: any) => {
      const fp = String(f.phase || '').replace('Phase ', '');
      return fp === phaseNum || fp.startsWith(`${phaseNum}.`) || fp.startsWith(`${phaseNum}:`) || fp === `Phase ${phaseNum}`;
    });
  };

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Terminal className="w-8 h-8 text-emerald-400" />
          Auto-Hunter
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Automated Recon, Fingerprinting, WAF Bypass, and Fuzzing Workflow</p>
      </header>

      <div className="cyber-card p-6 mb-8">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <div className="flex gap-4 items-end relative z-10">
          <div className="flex-1">
            <label className="block text-[10px] uppercase font-mono tracking-widest text-emerald-500/70 mb-2">Target URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com"
              className="cyber-input w-full"
            />
          </div>
          <button
            onClick={handleStart}
            disabled={loading || !targetUrl}
            className="cyber-button px-8"
          >
            {loading ? <Clock className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} 
            Start Hunt
          </button>
        </div>
        <div className="mt-3 relative z-10">
          <SessionSelector value={sessionId} onChange={setSessionId} />
          <p className="text-[10px] text-emerald-500/50 font-mono mt-1">
            When set, the picked session's cookies + auth headers permeate every phase of the hunt
            (recon, fingerprinting, fuzzing, auth audit). Out-of-scope hosts are auto-skipped.
          </p>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2 rounded-md shadow-[0_0_10px_rgba(239,68,68,0.2)]">
            <AlertCircle className="w-4 h-4" /> {error}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
        {/* Job History Sidebar */}
        <div className="lg:col-span-1 cyber-card flex flex-col">
          <div className="p-4 bg-emerald-950/20 border-b border-emerald-900/30 text-[10px] uppercase font-mono tracking-widest text-emerald-400/80 flex items-center gap-2 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <Activity className="w-3 h-3" /> Job History
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-hide p-2 space-y-2">
            {jobs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center opacity-50 p-4">
                <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/50 text-center border border-dashed border-emerald-900/30 p-4 rounded w-full">No jobs run yet</p>
              </div>
            ) : (
              jobs.map(job => (
                <button
                  key={job.id}
                  onClick={() => { setSelectedJob(job); setActiveTab('phases'); }}
                  className={`w-full text-left p-3 rounded-md border transition-all ${selectedJob?.id === job.id ? 'bg-emerald-900/30 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.1)]' : 'bg-black/40 border-emerald-900/20 hover:border-emerald-700/50 hover:bg-emerald-950/30'}`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs font-mono text-emerald-100 truncate max-w-[150px]" title={job.target_url}>{job.target_url}</span>
                    {job.status === 'running' && <Clock className="w-3 h-3 text-amber-400 animate-pulse drop-shadow-[0_0_5px_rgba(251,191,36,0.5)]" />}
                    {job.status === 'completed' && <CheckCircle2 className="w-3 h-3 text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]" />}
                    {job.status === 'failed' && <XCircle className="w-3 h-3 text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]" />}
                  </div>
                  <div className="flex justify-between items-center text-[10px] font-mono text-emerald-500/60 uppercase tracking-wider">
                    <span>{new Date(job.created_at).toLocaleTimeString()}</span>
                    <span>{job.status}</span>
                  </div>
                  {job.phase_results && (
                    <div className="mt-1 flex gap-1">
                      {Object.entries(job.phase_results).map(([id, pr]: [string, any]) => (
                        <div key={id} className={`w-2 h-2 rounded-full ${pr.status === 'completed' ? 'bg-emerald-500' : pr.status === 'failed' ? 'bg-red-500' : 'bg-gray-500'}`} title={`${PHASE_META[id]?.label || id}: ${pr.findings} findings`} />
                      ))}
                    </div>
                  )}
                </button>
              ))
            )}
          </div>
        </div>

        {/* Main Content Panel */}
        <div className="lg:col-span-2 cyber-card flex flex-col">
          <div className="p-4 bg-emerald-950/20 border-b border-emerald-900/30 flex justify-between items-center relative z-10 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <div className="flex items-center gap-4">
              <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-400/80 flex items-center gap-2">
                <Terminal className="w-3 h-3" /> Job Details
              </span>
              {selectedJob && (
                <div className="flex gap-1">
                  {(['phases', 'logs', 'findings'] as const).map(tab => (
                    <button key={tab} onClick={() => setActiveTab(tab)} className={`text-[9px] font-mono uppercase px-2 py-1 rounded border transition-all ${activeTab === tab ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' : 'bg-black/40 border-emerald-900/50 text-emerald-500/50 hover:text-emerald-400'}`}>
                      {tab}
                    </button>
                  ))}
                </div>
              )}
            </div>
            
            {selectedJob && selectedJob.status === 'completed' && (
              <div className="flex gap-2">
                <button onClick={() => handleExport('txt')} className="p-1.5 bg-black/50 border border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-500/70 hover:text-emerald-300 rounded-md transition-colors" title="Export TXT">
                  <FileText className="w-3.5 h-3.5" />
                </button>
                <button onClick={() => handleExport('md')} className="p-1.5 bg-black/50 border border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-500/70 hover:text-emerald-300 rounded-md transition-colors" title="Export Markdown">
                  <FileCode2 className="w-3.5 h-3.5" />
                </button>
                <button onClick={() => handleExport('json')} className="p-1.5 bg-black/50 border border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-500/70 hover:text-emerald-300 rounded-md transition-colors" title="Export JSON">
                  <FileJson className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
          
          <div className="flex-1 overflow-y-auto scrollbar-hide p-6 relative z-10">
            {!selectedJob ? (
              <div className="h-full flex flex-col items-center justify-center opacity-50">
                <Terminal className="w-12 h-12 mb-4 text-emerald-500/30 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
                <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">Select a job to view details</p>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Job Summary Bar */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/30" />
                    <div className="text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest mb-1">Target</div>
                    <div className="text-sm font-mono text-emerald-100 truncate" title={selectedJob.target_url}>{selectedJob.target_url}</div>
                  </div>
                  <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/30" />
                    <div className="text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest mb-1">Status</div>
                    <div className={`text-sm font-mono uppercase tracking-wider font-bold ${selectedJob.status === 'running' ? 'text-amber-400' : selectedJob.status === 'completed' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {selectedJob.status} {selectedJob.phase && `(${selectedJob.phase})`}
                    </div>
                  </div>
                  <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/30" />
                    <div className="text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest mb-1">Findings</div>
                    <div className="text-sm font-mono text-emerald-100">{selectedJob.findings?.length || 0} total</div>
                  </div>
                </div>

                {/* === PHASES TAB === */}
                {activeTab === 'phases' && (
                  <div className="space-y-3">
                    <h3 className="text-xs font-mono text-emerald-300 uppercase tracking-wider flex items-center gap-2 border-b border-emerald-900/30 pb-2">
                      <Wrench className="w-3 h-3" /> Phase Results & Tool Status
                    </h3>

                    {Object.entries(PHASE_META).map(([phaseId, meta]) => {
                      const status = getPhaseStatus(phaseId);
                      const pr = phaseResults?.[phaseId] as PhaseResult | undefined;
                      const phaseFindings = getFindingsForPhase(phaseId);
                      const isExpanded = expandedPhases.has(phaseId);
                      const Icon = meta.icon;

                      return (
                        <div key={phaseId} className={`border rounded-md overflow-hidden transition-all ${status === 'running' ? 'border-amber-500/40 bg-amber-900/5' : status === 'completed' ? 'border-emerald-900/30 bg-black/30' : status === 'failed' ? 'border-red-900/30 bg-red-900/5' : 'border-gray-800/30 bg-black/20 opacity-50'}`}>
                          <button onClick={() => togglePhase(phaseId)} className="w-full flex items-center justify-between p-4 hover:bg-emerald-900/10 transition-colors">
                            <div className="flex items-center gap-3">
                              {isExpanded ? <ChevronDown className="w-4 h-4 text-emerald-500/50" /> : <ChevronRight className="w-4 h-4 text-emerald-500/50" />}
                              <Icon className={`w-4 h-4 ${status === 'completed' ? 'text-emerald-400' : status === 'running' ? 'text-amber-400 animate-pulse' : status === 'failed' ? 'text-red-400' : 'text-gray-600'}`} />
                              <div className="text-left">
                                <div className="text-xs font-mono text-emerald-100">{meta.label}</div>
                                <div className="text-[9px] font-mono text-emerald-500/50">{meta.description}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-3">
                              {pr && (
                                <span className="text-[9px] font-mono text-emerald-500/70">
                                  {pr.findings} finding{pr.findings !== 1 ? 's' : ''} · {pr.tools.length} tool{pr.tools.length !== 1 ? 's' : ''}
                                </span>
                              )}
                              <span className={`text-[8px] font-mono uppercase px-2 py-0.5 rounded border ${phaseStatusColor(status)}`}>
                                {status}
                              </span>
                            </div>
                          </button>

                          {isExpanded && (
                            <div className="border-t border-emerald-900/20 p-4 space-y-3">
                              {/* Tool Status Grid */}
                              {pr?.tools && pr.tools.length > 0 && (
                                <div>
                                  <div className="text-[9px] font-mono text-emerald-500/60 uppercase tracking-widest mb-2">Tools</div>
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    {pr.tools.map((tool, idx) => (
                                      <div key={idx} className="flex items-center gap-2 p-2 bg-black/40 border border-emerald-900/20 rounded">
                                        {toolStatusIcon(tool.status)}
                                        <div className="flex-1 min-w-0">
                                          <div className="text-[10px] font-mono text-emerald-100 truncate">{tool.name}</div>
                                          {tool.detail && <div className="text-[9px] font-mono text-emerald-500/50 truncate">{tool.detail}</div>}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Phase Data */}
                              {pr?.data && Object.keys(pr.data).length > 0 && (
                                <div>
                                  <div className="text-[9px] font-mono text-emerald-500/60 uppercase tracking-widest mb-2">Summary</div>
                                  <div className="flex flex-wrap gap-3">
                                    {Object.entries(pr.data).map(([key, val]) => (
                                      <div key={key} className="px-3 py-1.5 bg-black/50 border border-emerald-900/20 rounded text-center">
                                        <div className="text-[8px] font-mono text-emerald-500/50 uppercase">{key.replace(/([A-Z])/g, ' $1').trim()}</div>
                                        <div className="text-xs font-mono text-emerald-300">{String(val)}</div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Phase-specific findings */}
                              {phaseFindings.length > 0 && (
                                <div>
                                  <div className="text-[9px] font-mono text-emerald-500/60 uppercase tracking-widest mb-2">Findings ({phaseFindings.length})</div>
                                  <div className="space-y-2 max-h-[300px] overflow-y-auto scrollbar-hide">
                                    {phaseFindings.map((finding: any, idx: number) => (
                                      <div key={idx} className="p-3 bg-black/50 border border-emerald-900/20 rounded hover:border-emerald-500/30 transition-colors">
                                        <div className="flex justify-between items-start mb-1">
                                          <span className="text-[10px] font-mono text-emerald-400 uppercase">{finding.type}</span>
                                          {finding.data?.length !== undefined && (
                                            <span className="text-[9px] font-mono text-emerald-500/50">{finding.data.length} items</span>
                                          )}
                                        </div>
                                        <pre className="text-[9px] font-mono text-emerald-100/70 whitespace-pre-wrap overflow-hidden max-h-[100px]">
                                          {typeof finding.data === 'object' ? JSON.stringify(finding.data, null, 2).substring(0, 500) : String(finding.data || '').substring(0, 500)}
                                        </pre>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {!pr && status === 'pending' && (
                                <div className="text-[10px] font-mono text-gray-600 italic">Waiting for previous phases to complete...</div>
                              )}
                              {status === 'running' && (
                                <div className="text-[10px] font-mono text-amber-400 flex items-center gap-2">
                                  <Clock className="w-3 h-3 animate-spin" /> Running...
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* === LOGS TAB === */}
                {activeTab === 'logs' && (
                  <div className="flex-1 flex flex-col min-h-[300px]">
                    <div className="flex justify-between items-center mb-4 border-b border-emerald-900/30 pb-2">
                      <h3 className="text-xs font-mono text-emerald-300 uppercase tracking-wider flex items-center gap-2">
                        <Terminal className="w-3 h-3" /> Live Execution Logs
                      </h3>
                      <div className="flex gap-2">
                        {(['all', 'info', 'warn', 'vuln'] as const).map(f => (
                          <button
                            key={f}
                            onClick={() => setLogFilter(f)}
                            className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border transition-all ${
                              logFilter === f ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' : 'bg-black/40 border-emerald-900/50 text-emerald-500/50 hover:text-emerald-400'
                            }`}
                          >
                            {f}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="flex-1 bg-black/80 border border-emerald-900/50 rounded-md p-4 font-mono text-[10px] overflow-y-auto space-y-1 scrollbar-hide max-h-[500px]">
                      {logs.length === 0 ? (
                        <div className="text-emerald-900/50 italic">Waiting for logs...</div>
                      ) : (
                        logs.filter(log => logFilter === 'all' || log.level === logFilter).map((log, i) => (
                          <div key={i} className="flex gap-2">
                            <span className="text-emerald-900/50 shrink-0">[{new Date(log.created_at).toLocaleTimeString()}]</span>
                            <span className={`uppercase font-bold shrink-0 ${
                              log.level === 'vuln' ? 'text-red-400' : 
                              log.level === 'warn' ? 'text-amber-400' : 
                              log.level === 'error' ? 'text-red-600' : 'text-emerald-500/70'
                            }`}>
                              {log.level}
                            </span>
                            <span className="text-emerald-100/80">{log.message}</span>
                            {log.data && (
                              <span className="text-emerald-500/40 truncate max-w-[200px]" title={JSON.stringify(log.data)}>
                                - {JSON.stringify(log.data)}
                              </span>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* === FINDINGS TAB === */}
                {activeTab === 'findings' && (
                  <div>
                    {selectedJob.findings && selectedJob.findings.length > 0 ? (
                      <>
                        <h3 className="text-xs font-mono text-emerald-300 uppercase tracking-wider mb-4 border-b border-emerald-900/30 pb-2 flex items-center gap-2">
                          <Shield className="w-3 h-3" /> All Findings ({selectedJob.findings.length})
                        </h3>
                        <div className="space-y-4">
                          {selectedJob.findings.map((finding: any, idx: number) => (
                            <div key={idx} className="p-4 bg-black/50 border border-emerald-900/30 rounded-md hover:border-emerald-500/30 transition-colors group">
                              <div className="flex justify-between items-start mb-3">
                                <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-sm border border-emerald-500/30">
                                  {finding.phase}
                                </span>
                                <span className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest">{finding.type}</span>
                              </div>
                              <pre className="text-[10px] font-mono text-emerald-100/80 whitespace-pre-wrap overflow-x-auto p-3 bg-black/80 rounded border border-emerald-900/50 shadow-inner">
                                {JSON.stringify(finding.data || finding, null, 2)}
                              </pre>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <div className="p-8 border border-dashed border-emerald-900/30 bg-black/30 rounded-lg flex flex-col items-center justify-center">
                        <CheckCircle2 className="w-8 h-8 text-emerald-500/30 mb-4" />
                        <p className="text-xs font-mono text-emerald-500/50 uppercase tracking-widest">
                          {selectedJob.status === 'completed' ? 'Job completed. No significant findings.' : 'Findings will appear here as the hunt progresses.'}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

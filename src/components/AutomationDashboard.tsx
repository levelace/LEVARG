import React, { useState, useEffect } from 'react';
import { Play, CheckCircle2, XCircle, Clock, Download, FileJson, FileText, FileCode2, Terminal, AlertCircle, Activity } from 'lucide-react';

export default function AutomationDashboard() {
  const [targetUrl, setTargetUrl] = useState('');
  const [jobs, setJobs] = useState<any[]>([]);
  const [selectedJob, setSelectedJob] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [logFilter, setLogFilter] = useState<'all' | 'info' | 'warn' | 'vuln'>('all');
  const [error, setError] = useState('');

  const fetchJobs = async () => {
    try {
      const res = await fetch('/api/automation/jobs');
      const data = await res.json();
      setJobs(data);
      
      // Update selected job if it's running
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
        body: JSON.stringify({ targetUrl })
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

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Terminal className="w-8 h-8 text-emerald-400" />
          Auto-Hunter
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Automated Recon, Fingerprinting, and Fuzzing Workflow</p>
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
        
        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2 rounded-md shadow-[0_0_10px_rgba(239,68,68,0.2)]">
            <AlertCircle className="w-4 h-4" /> {error}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
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
                  onClick={() => setSelectedJob(job)}
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
                </button>
              ))
            )}
          </div>
        </div>

        <div className="lg:col-span-2 cyber-card flex flex-col">
          <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-emerald-500/5 blur-[100px] rounded-full pointer-events-none" />
          
          <div className="p-4 bg-emerald-950/20 border-b border-emerald-900/30 flex justify-between items-center relative z-10 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-400/80 flex items-center gap-2">
              <Terminal className="w-3 h-3" /> Job Details & Findings
            </span>
            
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
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/30" />
                    <div className="text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest mb-1">Target</div>
                    <div className="text-sm font-mono text-emerald-100 truncate" title={selectedJob.target_url}>{selectedJob.target_url}</div>
                  </div>
                  <div className="p-3 bg-black/50 border border-emerald-900/30 rounded-md shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/30" />
                    <div className="text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest mb-1">Status</div>
                    <div className={`text-sm font-mono uppercase tracking-wider font-bold ${selectedJob.status === 'running' ? 'text-amber-400 drop-shadow-[0_0_5px_rgba(251,191,36,0.5)]' : selectedJob.status === 'completed' ? 'text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]' : 'text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]'}`}>
                      {selectedJob.status} {selectedJob.phase && `(${selectedJob.phase})`}
                    </div>
                  </div>
                </div>

                {/* Intelligence Status */}
                {selectedJob.status === 'running' && logs.some(l => l.data?.active_intelligence) && (
                  <div className="p-4 bg-emerald-900/10 border border-emerald-500/20 rounded-md flex gap-4 items-center">
                    <Activity className="w-5 h-5 text-emerald-400 animate-pulse" />
                    <div className="flex-1 grid grid-cols-3 gap-2">
                      {(() => {
                        const intelLog = [...logs].reverse().find(l => l.data?.active_intelligence);
                        const intel = intelLog?.data?.active_intelligence;
                        return (
                          <>
                            <div className="text-center">
                              <div className="text-[8px] uppercase font-mono text-emerald-500/50">Prioritized Targets</div>
                              <div className="text-xs font-mono text-emerald-300">{intel?.prioritized_targets || 0}</div>
                            </div>
                            <div className="text-center border-x border-emerald-500/10">
                              <div className="text-[8px] uppercase font-mono text-emerald-500/50">Discovered Users</div>
                              <div className="text-xs font-mono text-emerald-300">{intel?.users || 0}</div>
                            </div>
                            <div className="text-center">
                              <div className="text-[8px] uppercase font-mono text-emerald-500/50">Active Identifiers</div>
                              <div className="text-xs font-mono text-emerald-300">{intel?.identifiers || 0}</div>
                            </div>
                          </>
                        );
                      })()}
                    </div>
                    <div className="text-[8px] uppercase font-mono text-emerald-400 font-bold tracking-tighter">
                      Autonomous Chain Active
                    </div>
                  </div>
                )}

                {/* Workflow Progress Bar */}
                <div className="py-4 px-2">
                  <div className="flex justify-between mb-2">
                    {['Phase 1', 'Phase 2', 'Phase 3', 'Phase 3.5', 'Phase 4', 'Phase 5'].map((phase, idx) => {
                      const isCompleted = selectedJob.status === 'completed' || (selectedJob.phase && parseInt(selectedJob.phase.match(/\d+/)?.[0] || '0') > (idx + 1));
                      const isCurrent = selectedJob.phase?.includes(phase);
                      return (
                        <div key={phase} className="flex flex-col items-center gap-1 w-full relative">
                          <div className={`w-3 h-3 rounded-full border-2 transition-all ${
                            isCompleted ? 'bg-emerald-500 border-emerald-400 shadow-[0_0_8px_rgba(16,185,129,1)]' :
                            isCurrent ? 'bg-amber-500 border-amber-400 animate-pulse' :
                            'bg-black border-emerald-900/50'
                          }`} />
                          <span className={`text-[8px] font-mono uppercase tracking-tighter ${
                            isCompleted || isCurrent ? 'text-emerald-400' : 'text-emerald-900/50'
                          }`}>{phase.replace('Phase ', '')}</span>
                          {idx < 5 && (
                            <div className={`absolute left-[50%] top-1.5 w-full h-[1px] -z-10 ${
                              isCompleted ? 'bg-emerald-500' : 'bg-emerald-900/30'
                            }`} />
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Live Logs */}
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
                  <div className="flex-1 bg-black/80 border border-emerald-900/50 rounded-md p-4 font-mono text-[10px] overflow-y-auto space-y-1 scrollbar-hide max-h-[400px]">
                    {logs.length === 0 ? (
                      <div className="text-emerald-900/50 italic italic">Waiting for logs...</div>
                    ) : (
                      logs.filter(log => logFilter === 'all' || log.level === logFilter).map((log, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="text-emerald-900/50">[{new Date(log.created_at).toLocaleTimeString()}]</span>
                          <span className={`uppercase font-bold ${
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

                {selectedJob.findings && selectedJob.findings.length > 0 && (
                  <div>
                    <h3 className="text-xs font-mono text-emerald-300 uppercase tracking-wider mb-4 border-b border-emerald-900/30 pb-2 flex items-center gap-2">
                      <Terminal className="w-3 h-3" /> Findings Log
                    </h3>
                    <div className="space-y-4">
                      {selectedJob.findings.map((finding: any, idx: number) => (
                        <div key={idx} className="p-4 bg-black/50 border border-emerald-900/30 rounded-md hover:border-emerald-500/30 transition-colors group">
                          <div className="flex justify-between items-start mb-3">
                            <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-sm border border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.1)]">
                              Phase: {finding.phase}
                            </span>
                            <span className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest">{finding.type}</span>
                          </div>
                          <pre className="text-[10px] font-mono text-emerald-100/80 whitespace-pre-wrap overflow-x-auto p-3 bg-black/80 rounded border border-emerald-900/50 shadow-inner group-hover:border-emerald-700/50 transition-colors">
                            {JSON.stringify(finding.data || finding, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {selectedJob.status === 'completed' && (!selectedJob.findings || selectedJob.findings.length === 0) && (
                  <div className="p-8 border border-dashed border-emerald-900/30 bg-black/30 rounded-lg flex flex-col items-center justify-center">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500/30 mb-4" />
                    <p className="text-xs font-mono text-emerald-500/50 uppercase tracking-widest">Job completed. No significant findings.</p>
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

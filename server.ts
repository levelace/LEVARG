
import express from 'express';
import path from 'path';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { createServer as createViteServer } from 'vite';
import db from './db.js';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import { AutomationEngine } from './automation_engine.js';

import { ToolManager } from './tool_manager.js';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // Request logging middleware
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
  });

  // Root route for connectivity check
  app.get('/', (req, res, next) => {
    if (req.url === '/' || req.url === '/index.html') {
      return next(); // Let Vite handle it
    }
    next();
  });

  app.get('/health', (req, res) => {
    res.send('OK');
  });

  // --- API Routes ---

  // Scope Control
  app.get('/api/scopes', (req, res) => {
    try {
      const scopes = db.prepare('SELECT * FROM scopes ORDER BY created_at DESC').all();
      res.json(scopes);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/scopes', (req, res) => {
    let { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    try {
      // Normalize domain to hostname
      domain = domain.trim();
      if (domain.startsWith('http://') || domain.startsWith('https://')) {
        try {
          domain = new URL(domain).hostname;
        } catch (e) {}
      } else {
        // Strip out paths and ports if user pastes examples like example.com/path or example.com:8080
        domain = domain.split('/')[0].split(':')[0];
      }

      const id = uuidv4();
      db.prepare('INSERT INTO scopes (id, domain) VALUES (?, ?)').run(id, domain);
      res.json({ id, domain });
    } catch (err) {
      res.status(400).json({ error: 'Domain already exists or invalid' });
    }
  });

  app.delete('/api/scopes/:id', (req, res) => {
    try {
      db.prepare('DELETE FROM scopes WHERE id = ?').run(req.params.id);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Recon Engine
  app.get('/api/endpoints', (req, res) => {
    const endpoints = db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC').all();
    res.json(endpoints);
  });

  app.get('/api/discoveries/fuzzable', (req, res) => {
    try {
      const endpoints = db.prepare('SELECT url, method FROM endpoints').all() as { url: string, method: string }[];
      const fuzzable = AutomationEngine.selectFuzzableEndpoints(endpoints, 20);
      res.json(fuzzable);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/endpoints/import', (req, res) => {
    const { endpoints } = req.body; // Array of { url, method, source }
    const insert = db.prepare('INSERT OR IGNORE INTO endpoints (id, url, method, source) VALUES (?, ?, ?, ?)');
    const transaction = db.transaction((items) => {
      for (const item of items) {
        insert.run(uuidv4(), item.url, item.method || 'GET', item.source || 'manual');
      }
    });
    transaction(endpoints);
    res.json({ success: true, count: endpoints.length });
  });

  // Request Laboratory
  app.post('/api/lab/proxy', async (req, res) => {
    const { method, url, headers, body } = req.body;

    // Scope Check
    const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
    const isAllowed = scopes.some(s => {
      try {
        const targetHost = new URL(url).hostname;
        return targetHost === s.domain || targetHost.endsWith(`.${s.domain}`);
      } catch (e) {
        return false;
      }
    });
    
    if (scopes.length > 0 && !isAllowed) {
      return res.status(403).json({ error: 'Target domain not in scope' });
    }

    try {
      const startTime = Date.now();
      const response = await axios({
        method,
        url,
        headers,
        data: body,
        validateStatus: () => true,
        timeout: 10000
      });
      const duration = Date.now() - startTime;

      const requestId = uuidv4();
      const responseId = uuidv4();

      // Save request/response for history/diff
      db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(requestId, method, url, JSON.stringify(headers), typeof body === 'string' ? body : JSON.stringify(body));
      
      db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(responseId, requestId, response.status, JSON.stringify(response.headers), typeof response.data === 'string' ? response.data : JSON.stringify(response.data));

      res.json({
        id: responseId,
        status: response.status,
        headers: response.headers,
        body: response.data,
        duration
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Payloads
  app.get('/api/payloads', (req, res) => {
    const payloads = db.prepare('SELECT * FROM payloads ORDER BY created_at DESC').all();
    res.json(payloads);
  });

  app.get('/api/oven', (req, res) => {
    try {
      const categories = AutomationEngine.getPayloadOvenCategories();
      console.log(`[Oven] Fetching oven data for ${categories.length} categories: ${categories.join(', ')}`);
      const ovenData: Record<string, any> = {};
      for (const cat of categories) {
        ovenData[cat] = {
          standard: AutomationEngine.getPayloadOvenPayloads(cat, 1, 100),
          advanced: AutomationEngine.getPayloadOvenPayloads(cat, 2, 100),
          elite: AutomationEngine.getPayloadOvenPayloads(cat, 3, 100),
        };
      }
      res.json(ovenData);
    } catch (err: any) {
      console.error('[Oven] Error generating oven data:', err);
      res.status(500).json({ error: 'Failed to generate oven data' });
    }
  });

  app.post('/api/payloads', (req, res) => {
    const { name, content, type } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO payloads (id, name, content, type) VALUES (?, ?, ?, ?)').run(id, name, content, type);
    res.json({ id, name, content, type });
  });

  app.delete('/api/payloads/:id', (req, res) => {
    db.prepare('DELETE FROM payloads WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  });

  // History
  app.get('/api/history', (req, res) => {
    const history = db.prepare(`
      SELECT req.id, req.method, req.url, req.headers as req_headers, req.body as req_body, req.created_at,
             res.status, res.headers as res_headers, res.body as res_body, res.id as res_id
      FROM requests req
      LEFT JOIN responses res ON req.id = res.request_id
      ORDER BY req.created_at DESC
      LIMIT 100
    `).all();
    res.json(history);
  });

  // Flows
  app.get('/api/flows', (req, res) => {
    const flows = db.prepare('SELECT * FROM flows ORDER BY created_at DESC').all();
    res.json(flows.map((f: any) => ({ ...f, steps: JSON.parse(f.steps) })));
  });

  app.post('/api/flows', (req, res) => {
    const { name, steps } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO flows (id, name, steps) VALUES (?, ?, ?)').run(id, name, JSON.stringify(steps));
    res.json({ id, name, steps });
  });

  app.delete('/api/flows/:id', (req, res) => {
    db.prepare('DELETE FROM flows WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  });

  app.post('/api/flows/:id/run', async (req, res) => {
    try {
      const flow = db.prepare('SELECT * FROM flows WHERE id = ?').get(req.params.id) as any;
      if (!flow) return res.status(404).json({ error: 'Flow not found' });
      
      const steps = JSON.parse(flow.steps);
      const results = [];
      
      for (const step of steps) {
        const startTime = Date.now();
        try {
          const stepRes = await axios({
            method: step.method,
            url: step.url,
            headers: step.headers || {},
            data: step.body,
            validateStatus: () => true,
            timeout: 10000
          });
          results.push({
            step: step.name || step.url,
            status: stepRes.status,
            duration: Date.now() - startTime,
            success: true
          });
        } catch (err: any) {
          results.push({
            step: step.name || step.url,
            error: err.message,
            duration: Date.now() - startTime,
            success: false
          });
          break; // Stop flow on error
        }
      }
      
      res.json({ success: true, results });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Fuzzing Engine
  app.post('/api/scans', async (req, res) => {
    const { targetUrl, payloadSetId, method, headers, body } = req.body;
    const scanId = uuidv4();
    
    db.prepare('INSERT INTO scans (id, target_url, payload_set_id, status) VALUES (?, ?, ?, ?)').run(scanId, targetUrl, payloadSetId, 'running');
    
    res.json({ id: scanId, status: 'started' });

    // Run async worker
    setTimeout(async () => {
      try {
        const payloadSet = db.prepare('SELECT content FROM payloads WHERE id = ?').get(payloadSetId) as any;
        if (!payloadSet) throw new Error('Payload set not found');
        
        const payloads = payloadSet.content.split('\n').filter((p: string) => p.trim());
        
        // Baseline request
        const baselineUrl = targetUrl.replace('§FUZZ§', 'baseline_test_123');
        const baselineBody = typeof body === 'string' ? body.replace('§FUZZ§', 'baseline_test_123') : body;
        
        const baselineRes = await axios({ method, url: baselineUrl, headers, data: baselineBody, validateStatus: () => true, timeout: 5000 }).catch(() => null);
        
        const baselineStatus = baselineRes ? baselineRes.status : 0;
        const baselineLength = baselineRes ? JSON.stringify(baselineRes.data).length : 0;
        
        db.prepare('UPDATE scans SET baseline_status = ?, baseline_length = ? WHERE id = ?').run(baselineStatus, baselineLength, scanId);
        
        for (const payload of payloads) {
          const pUrl = targetUrl.replace('§FUZZ§', encodeURIComponent(payload));
          const pBody = typeof body === 'string' ? body.replace('§FUZZ§', payload) : body;
          
          const pRes = await axios({ method, url: pUrl, headers, data: pBody, validateStatus: () => true, timeout: 5000 }).catch(() => null);
          
          const pStatus = pRes ? pRes.status : 0;
          const pLength = pRes ? JSON.stringify(pRes.data).length : 0;
          
          // Anomaly detection: status changed, or length differs by > 10%
          const lengthDiff = Math.abs(pLength - baselineLength);
          const isAnomaly = (pStatus !== baselineStatus && pStatus !== 0) || (baselineLength > 0 && (lengthDiff / baselineLength) > 0.1);
          
          const resId = uuidv4();
          if (pRes) {
            const reqId = uuidv4();
            db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)').run(reqId, method, pUrl, JSON.stringify(headers), typeof pBody === 'string' ? pBody : JSON.stringify(pBody));
            db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)').run(resId, reqId, pStatus, JSON.stringify(pRes.headers), typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data));
          }
          
          db.prepare('INSERT INTO scan_results (id, scan_id, payload, status, length, is_anomaly, response_id) VALUES (?, ?, ?, ?, ?, ?, ?)').run(uuidv4(), scanId, payload, pStatus, pLength, isAnomaly ? 1 : 0, pRes ? resId : null);
        }
        
        db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('completed', scanId);
      } catch (err) {
        console.error('Scan error:', err);
        db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('failed', scanId);
      }
    }, 0);
  });

  app.get('/api/scans', (req, res) => {
    const scans = db.prepare('SELECT * FROM scans ORDER BY created_at DESC').all();
    res.json(scans);
  });

  app.get('/api/scans/:id/results', (req, res) => {
    const results = db.prepare('SELECT * FROM scan_results WHERE scan_id = ? ORDER BY created_at DESC').all(req.params.id);
    res.json(results);
  });

  // Stack Gap Analyzer
  app.post('/api/stack-gap/analyze', async (req, res) => {
    const { url, method, headers } = req.body;
    try {
      const fingerprint = await StackGapAnalyzer.fingerprint(url);
      
      // Run analysis asynchronously
      setTimeout(async () => {
        try {
          await StackGapAnalyzer.analyze(url, method, headers);
        } catch (err) {
          console.error('Stack Gap Analysis error:', err);
        }
      }, 0);

      res.json({ fingerprint, status: 'analysis_started' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/stack-gap/findings', (req, res) => {
    const findings = db.prepare('SELECT * FROM stack_gap_findings ORDER BY created_at DESC').all();
    res.json(findings);
  });

  // Automation Engine
  app.post('/api/automation/start', async (req, res) => {
    const { targetUrl } = req.body;
    try {
      const jobId = await AutomationEngine.startJob(targetUrl);
      res.json({ id: jobId, status: 'running' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/automation/jobs', (req, res) => {
    const jobs = db.prepare('SELECT * FROM automation_jobs ORDER BY created_at DESC').all();
    res.json(jobs.map((j: any) => ({ ...j, findings: j.findings ? JSON.parse(j.findings) : [] })));
  });

  app.get('/api/automation/jobs/:id', (req, res) => {
    const job = db.prepare('SELECT * FROM automation_jobs WHERE id = ?').get(req.params.id) as any;
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ ...job, findings: job.findings ? JSON.parse(job.findings) : [] });
  });

  app.get('/api/automation/jobs/:id/logs', (req, res) => {
    const logs = db.prepare('SELECT * FROM automation_logs WHERE job_id = ? ORDER BY created_at ASC').all(req.params.id);
    res.json(logs.map((l: any) => ({ ...l, data: l.data ? JSON.parse(l.data) : null })));
  });

  // Tools Status
  app.get('/api/tools/status', async (req, res) => {
    try {
      const statuses = await ToolManager.getAllStatus();
      res.json(statuses);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // --- Static Files & Vite Middleware ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LevarG Server running on http://localhost:${PORT}`);
    // FIX: Removed hardcoded Figma startup scans — scans should only be triggered by user action
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});
--- END OF FILE LEVARG-main/server.ts ---

--- START OF FILE LEVARG-main/src/components/ScopeManager.tsx ---
import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Shield, AlertCircle } from 'lucide-react';

export default function ScopeManager() {
  const [scopes, setScopes] = useState<{ id: string, domain: string }[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [error, setError] = useState('');

  const fetchScopes = async () => {
    try {
      const res = await fetch('/api/scopes');
      if (res.ok) {
        const data = await res.json();
        setScopes(data);
      }
    } catch (err) {
      console.error('Failed to fetch scopes', err);
    }
  };

  useEffect(() => {
    fetchScopes();
    const interval = setInterval(fetchScopes, 5000);
    return () => clearInterval(interval);
  }, []);

  const addScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain) return;
    
    try {
      const res = await fetch('/api/scopes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: newDomain })
      });

      if (res.ok) {
        setNewDomain('');
        setError('');
        fetchScopes();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Failed to add domain. It might already exist.');
      }
    } catch (err: any) {
      setError('Network error: Failed to reach server');
    }
  };

  const deleteScope = async (id: string) => {
    try {
      await fetch(`/api/scopes/${id}`, { method: 'DELETE' });
      fetchScopes();
    } catch (err) {
      console.error('Failed to delete scope', err);
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto w-full h-full overflow-y-auto scrollbar-hide relative">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-12 relative">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Shield className="w-8 h-8 text-emerald-400" />
          Scope Control
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Define and manage approved research boundaries</p>
      </header>

      <div className="cyber-card p-8 mb-8">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <form onSubmit={addScope} className="flex gap-4 relative z-10">
          <div className="flex-1 relative">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="e.g. example.com"
              className="cyber-input w-full"
            />
          </div>
          <button
            type="submit"
            className="cyber-button"
          >
            <Plus className="w-4 h-4" />
            Add Domain
          </button>
        </form>
        {error && (
          <div className="mt-4 flex items-center gap-2 text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/30 p-3 rounded-md shadow-[0_0_10px_rgba(239,68,68,0.2)] relative z-10">
            <AlertCircle className="w-4 h-4" />
            {error}
          </div>
        )}
      </div>

      <div className="space-y-4">
        <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-emerald-500/70 mb-4 flex items-center gap-2">
          <Shield className="w-3 h-3" /> Approved Domains
        </h3>
        {scopes.length === 0 ? (
          <div className="p-12 border border-dashed border-emerald-900/30 bg-black/30 rounded-lg flex flex-col items-center justify-center opacity-50">
            <Shield className="w-8 h-8 mb-2 text-emerald-500/30 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
            <span className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">No domains in scope</span>
          </div>
        ) : (
          scopes.map((scope) => (
            <div key={scope.id} className="cyber-card p-4 flex items-center justify-between group hover:border-emerald-500/50 hover:bg-emerald-950/20 transition-all duration-300">
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-4 relative z-10">
                <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/30 rounded-md flex items-center justify-center group-hover:bg-emerald-500/20 group-hover:shadow-[0_0_10px_rgba(16,185,129,0.3)] transition-all">
                  <Shield className="w-5 h-5 text-emerald-400 drop-shadow-[0_0_5px_currentColor]" />
                </div>
                <div>
                  <div className="text-sm font-bold font-mono text-emerald-100 group-hover:text-emerald-50 transition-colors">{scope.domain}</div>
                  <div className="text-[10px] text-emerald-500/50 font-mono uppercase tracking-tighter mt-1">ID: {scope.id.split('-')[0]}</div>
                </div>
              </div>
              <button
                onClick={() => deleteScope(scope.id)}
                className="p-2 opacity-0 group-hover:opacity-100 text-emerald-500/50 hover:text-red-400 hover:bg-red-500/10 hover:shadow-[0_0_10px_rgba(239,68,68,0.2)] rounded-md transition-all relative z-10"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
--- END OF FILE LEVARG-main/src/components/ScopeManager.tsx ---


import 'dotenv/config';
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
import { OllamaClient } from './ollama_client.js';
import { OllamaManager } from './ollama_manager.js';
import { SessionVault, SessionScopeError, type SessionCookie, type SessionStorage } from './session_vault.js';
import { BrowserManager } from './browser_manager.js';

async function startServer() {
  // Auto-install, start, and pull model for Ollama (runs in background)
  const ollamaReady = OllamaManager.bootstrap().catch(err => {
    console.warn('[Ollama] Bootstrap error (AI features may be unavailable):', err.message);
  });

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
    const { method, url, headers, body, sessionId } = req.body as {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
      sessionId?: string;
    };

    // Scope Check (allowlist of domains; if empty, no restriction).
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
      // Optional auth-session overlay: cookies + static headers from a saved
      // Session, but only if the session's bound scope covers the target host.
      let finalHeaders: Record<string, string> = { ...(headers ?? {}) };
      if (sessionId) {
        try {
          const overlay = SessionVault.buildRequestOverlay(sessionId, url);
          finalHeaders = SessionVault.mergeHeaders(headers, {
            headers: overlay.headers,
            cookieHeader: overlay.cookieHeader,
            userAgent: overlay.userAgent,
          });
        } catch (err) {
          if (err instanceof SessionScopeError) {
            return res.status(err.status).json({ error: err.message });
          }
          throw err;
        }
      }

      const startTime = Date.now();
      const response = await axios({
        method,
        url,
        headers: finalHeaders,
        data: body,
        validateStatus: () => true,
        timeout: 10000
      });
      const duration = Date.now() - startTime;

      const requestId = uuidv4();
      const responseId = uuidv4();

      // Save request/response for history/diff
      db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(requestId, method, url, JSON.stringify(finalHeaders), typeof body === 'string' ? body : JSON.stringify(body));
      
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
      
      const { sessionId } = (req.body ?? {}) as { sessionId?: string };
      const steps: { method: string; url: string; headers?: Record<string, string>; body?: unknown; name?: string }[] = JSON.parse(flow.steps);

      // Pre-flight: every step's URL must be in scope when scopes are configured.
      // Failing fast prevents a multi-step flow from leaking traffic to an
      // out-of-scope step halfway through.
      const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
      if (scopes.length > 0) {
        for (const step of steps) {
          let host: string;
          try { host = new URL(step.url).hostname; }
          catch { return res.status(400).json({ error: `Invalid URL in flow step: ${step.url}` }); }
          const ok = scopes.some(s => host === s.domain || host.endsWith(`.${s.domain}`));
          if (!ok) return res.status(403).json({ error: `Flow step out of scope: ${step.url}` });
        }
      }

      const results = [];
      
      // Pre-flight: every session overlay must succeed before we send any
      // step. This avoids a flow halfway-running before discovering an
      // out-of-scope step.
      if (sessionId) {
        for (const step of steps) {
          try {
            SessionVault.buildRequestOverlay(sessionId, step.url);
          } catch (err) {
            if (err instanceof SessionScopeError) {
              return res.status(err.status).json({ error: err.message });
            }
            throw err;
          }
        }
      }

      for (const step of steps) {
        const startTime = Date.now();
        try {
          let stepHeaders: Record<string, string> = { ...(step.headers ?? {}) };
          if (sessionId) {
            const overlay = SessionVault.buildRequestOverlay(sessionId, step.url);
            stepHeaders = SessionVault.mergeHeaders(step.headers, {
              headers: overlay.headers,
              cookieHeader: overlay.cookieHeader,
              userAgent: overlay.userAgent,
            });
          }
          const stepRes = await axios({
            method: step.method,
            url: step.url,
            headers: stepHeaders,
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

  // --- Authenticated Sessions ---
  // A Session is a named cookie/header bundle bound to a Scope. The built-in
  // browser populates it; Request Lab and Flow Runner consume it.

  app.get('/api/sessions', (req, res) => {
    try {
      const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
      res.json(SessionVault.list(scopeId));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/sessions/:id', (req, res) => {
    const session = SessionVault.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json(session);
  });

  app.post('/api/sessions', (req, res) => {
    try {
      const { scopeId, name, cookies, headers, storage, userAgent, notes } = req.body as {
        scopeId: string;
        name: string;
        cookies?: SessionCookie[];
        headers?: Record<string, string>;
        storage?: SessionStorage;
        userAgent?: string | null;
        notes?: string | null;
      };
      if (!scopeId || !name) {
        return res.status(400).json({ error: 'scopeId and name are required' });
      }
      const created = SessionVault.create({ scopeId, name, cookies, headers, storage, userAgent, notes });
      res.json(created);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.patch('/api/sessions/:id', (req, res) => {
    try {
      const { name, cookies, headers, storage, userAgent, notes } = req.body as {
        name?: string;
        cookies?: SessionCookie[];
        headers?: Record<string, string>;
        storage?: SessionStorage;
        userAgent?: string | null;
        notes?: string | null;
      };
      const updated = SessionVault.update(req.params.id, { name, cookies, headers, storage, userAgent, notes });
      res.json(updated);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/sessions/:id', (req, res) => {
    const ok = SessionVault.delete(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Session not found' });
    res.json({ success: true });
  });

  // --- Built-in Browser ---
  // Drives a real Chromium under puppeteer-stealth so testers can complete
  // SSO/MFA login flows the headless scanner can't. All captured traffic
  // is scope-gated: requests to hosts not in the active scope are dropped,
  // never persisted.

  app.get('/api/browser/status', async (_req, res) => {
    try {
      res.json(await BrowserManager.status());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/browser/launch', async (req, res) => {
    try {
      const { scopeId, headless } = req.body as { scopeId: string; headless?: boolean };
      if (!scopeId) return res.status(400).json({ error: 'scopeId is required' });
      const status = await BrowserManager.launch({ scopeId, headless });
      res.json(status);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post('/api/browser/close', async (_req, res) => {
    try {
      await BrowserManager.close();
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/browser/capture', (req, res) => {
    const { enabled } = req.body as { enabled: boolean };
    BrowserManager.setCapturing(Boolean(enabled));
    res.json({ success: true, capturing: Boolean(enabled) });
  });

  app.post('/api/browser/save-as-session', async (req, res) => {
    try {
      const { name, notes } = req.body as { name: string; notes?: string | null };
      if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
      const out = await BrowserManager.saveAsSession({ name: name.trim(), notes });
      res.json(out);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Fuzzing Engine
  app.post('/api/scans', async (req, res) => {
    const { targetUrl, payloadSetId, method, headers, body, sessionId } = req.body as {
      targetUrl: string;
      payloadSetId: string;
      method: string;
      headers?: Record<string, string>;
      body?: unknown;
      sessionId?: string;
    };

    // Pre-flight scope check on the baseline URL. Subsequent payload-fuzzed
    // URLs share the same hostname so this gate is sufficient.
    try {
      const targetHost = new URL(targetUrl.replace('§FUZZ§', 'baseline_test_123')).hostname;
      const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
      if (scopes.length > 0) {
        const ok = scopes.some(s => targetHost === s.domain || targetHost.endsWith(`.${s.domain}`));
        if (!ok) return res.status(403).json({ error: 'Target domain not in scope' });
      }
    } catch {
      return res.status(400).json({ error: 'Invalid targetUrl' });
    }

    // Pre-flight session check: validate the overlay is applicable before we
    // accept the scan. Avoids spinning up an async job that immediately fails.
    if (sessionId) {
      try {
        SessionVault.buildRequestOverlay(sessionId, targetUrl.replace('§FUZZ§', 'baseline_test_123'));
      } catch (err: any) {
        if (err instanceof SessionScopeError) return res.status(err.status).json({ error: err.message });
        // Any other failure (e.g., DB error inside SessionVault) becomes a 500
        // rather than an unhandled rejection that would crash Express.
        return res.status(500).json({ error: err.message ?? 'Session lookup failed' });
      }
    }

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
        const baselineHeaders = SessionVault.applyToHeaders(sessionId, baselineUrl, headers);

        const baselineRes = await axios({ method, url: baselineUrl, headers: baselineHeaders, data: baselineBody, validateStatus: () => true, timeout: 5000 }).catch(() => null);

        const baselineStatus = baselineRes ? baselineRes.status : 0;
        const baselineLength = baselineRes ? JSON.stringify(baselineRes.data).length : 0;

        db.prepare('UPDATE scans SET baseline_status = ?, baseline_length = ? WHERE id = ?').run(baselineStatus, baselineLength, scanId);

        for (const payload of payloads) {
          const pUrl = targetUrl.replace('§FUZZ§', encodeURIComponent(payload));
          const pBody = typeof body === 'string' ? body.replace('§FUZZ§', payload) : body;
          const pHeaders = SessionVault.applyToHeaders(sessionId, pUrl, headers);

          const pRes = await axios({ method, url: pUrl, headers: pHeaders, data: pBody, validateStatus: () => true, timeout: 5000 }).catch(() => null);

          const pStatus = pRes ? pRes.status : 0;
          const pLength = pRes ? JSON.stringify(pRes.data).length : 0;

          // Anomaly detection: status changed, or length differs by > 10%
          const lengthDiff = Math.abs(pLength - baselineLength);
          const isAnomaly = (pStatus !== baselineStatus && pStatus !== 0) || (baselineLength > 0 && (lengthDiff / baselineLength) > 0.1);

          const resId = uuidv4();
          if (pRes) {
            const reqId = uuidv4();
            db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)').run(reqId, method, pUrl, JSON.stringify(pHeaders), typeof pBody === 'string' ? pBody : JSON.stringify(pBody));
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
    const { url, method, headers, sessionId } = req.body as {
      url: string;
      method?: string;
      headers?: Record<string, string>;
      sessionId?: string;
    };
    try {
      // Pre-flight: validate session overlay applies to target before kicking
      // off the async job.
      if (sessionId) {
        try { SessionVault.buildRequestOverlay(sessionId, url); }
        catch (err) {
          if (err instanceof SessionScopeError) return res.status(err.status).json({ error: err.message });
          throw err;
        }
      }
      const fingerprint = await StackGapAnalyzer.fingerprint(url);

      // Run analysis asynchronously
      setTimeout(async () => {
        try {
          await StackGapAnalyzer.analyze(url, method ?? 'GET', headers ?? {}, sessionId);
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
    const { targetUrl, sessionId } = req.body as { targetUrl: string; sessionId?: string };
    try {
      // Pre-flight: validate session overlay applies to target before launch.
      if (sessionId) {
        try { SessionVault.buildRequestOverlay(sessionId, targetUrl); }
        catch (err) {
          if (err instanceof SessionScopeError) return res.status(err.status).json({ error: err.message });
          throw err;
        }
      }
      const jobId = await AutomationEngine.startJob(targetUrl, { sessionId });
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

  // --- AI Proxy Endpoints (Ollama — local, free, no API key) ---
  app.post('/api/ai/generate-payloads', async (req, res) => {
    const { name, type } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const ollama = new OllamaClient();
    const prompt = `Generate a list of 20 highly effective security testing payloads for the following scenario: ${name}.\nThe payload type is: ${type || 'fuzzing'}.\nReturn ONLY the payloads, one per line. Do not include markdown formatting, numbers, or explanations.`;
    const content = await ollama.generate(prompt);
    if (content) {
      res.json({ content });
    } else {
      res.status(500).json({ error: 'Ollama is not reachable. Make sure Ollama is running (ollama serve).' });
    }
  });

  app.post('/api/ai/analyze-response', async (req, res) => {
    const { status, headers, body } = req.body;
    try {
      const ollama = new OllamaClient();
      const bodyStr = typeof body === 'string' ? body.substring(0, 5000) : JSON.stringify(body ?? '').substring(0, 5000);
      const prompt = `Analyze this HTTP response for potential security vulnerabilities.\nFocus on:\n1. Missing security headers\n2. Information disclosure\n3. Reflected input or XSS vectors\n4. Server errors indicating SQLi/RCE\nReturn a concise, bulleted technical summary formatted in Markdown.\n\nStatus: ${status}\nHeaders: ${JSON.stringify(headers)}\nBody: ${bodyStr}`;
      const analysis = await ollama.generate(prompt);
      if (analysis) {
        res.json({ analysis });
      } else {
        res.status(500).json({ error: 'Ollama is not reachable. Make sure Ollama is running (ollama serve).' });
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- Tools & Resources API ---
  app.get('/api/tools/status', async (req, res) => {
    try {
      const statuses = await ToolManager.getAllStatus();
      res.json(statuses);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/tools/install', async (req, res) => {
    const { toolName, methodIndex } = req.body;
    if (!toolName || methodIndex === undefined) return res.status(400).json({ error: 'toolName and methodIndex required' });
    const result = await ToolManager.installTool(toolName, methodIndex);
    ToolManager.clearCache();
    res.json(result);
  });

  app.post('/api/tools/pdtm-install-all', async (_req, res) => {
    const result = await ToolManager.pdtmInstallAll();
    res.json(result);
  });

  app.get('/api/resources/status', async (_req, res) => {
    try {
      const statuses = await ToolManager.getResourceStatus();
      res.json(statuses);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/resources/install', async (req, res) => {
    const { resourceName, methodIndex } = req.body;
    if (!resourceName || methodIndex === undefined) return res.status(400).json({ error: 'resourceName and methodIndex required' });
    const result = await ToolManager.installResource(resourceName, methodIndex);
    res.json(result);
  });

  app.get('/api/resources/browse', async (req, res) => {
    const { name, subpath } = req.query;
    if (!name) return res.status(400).json({ error: 'name query param required' });
    const contents = await ToolManager.getResourceContents(name as string, subpath as string | undefined);
    res.json({ path: subpath || '/', entries: contents });
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

  app.listen(PORT, '0.0.0.0', async () => {
    console.log(`LevarG Server running on http://localhost:${PORT}`);
    // Wait for Ollama bootstrap to finish (model download may take a while)
    await ollamaReady;
  });

  // Clean shutdown
  const shutdown = () => {
    OllamaManager.shutdown();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});

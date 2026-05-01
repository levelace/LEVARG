/**
 * LevarG Mobile Server — stripped-down Express backend for Android.
 *
 * Runs inside the embedded Node.js runtime provided by capacitor-nodejs.
 * Key differences from the desktop server.ts:
 *   - Always production mode (no Vite dev server)
 *   - No Puppeteer (unavailable on Android) — browser endpoints return 501
 *   - Listens on 127.0.0.1 only (Capacitor WebView connects via localhost)
 *   - LEVARG_DATA_DIR used for DB and writable data
 */

import 'dotenv/config';
import express from 'express';
import path from 'path';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import db from './db.js';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import { AutomationEngine } from './automation_engine.js';

import { ToolManager } from './tool_manager.js';
import { OllamaClient } from './ollama_client.js';
import { SessionVault, SessionScopeError, type SessionCookie, type SessionStorage } from './session_vault.js';
import { CredentialVault } from './credential_vault.js';
import { AuthFlowVault, type AuthFlowStep, type TriggerMode } from './auth_flow_vault.js';
import { ExtensionTokenVault } from './extension_token_vault.js';
import { detectLoginForm } from './form_detector.js';
import { USER_AGENTS, getUserAgent, pickRandomBrowserUA } from './user_agents.js';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // Logging middleware
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });

  // Health endpoint
  app.get('/health', (_req, res) => {
    res.send('OK');
  });

  // Platform info endpoint for the mobile UI
  app.get('/api/platform', (_req, res) => {
    res.json({
      platform: 'android',
      puppeteer: false,
      ollama: false,
      dataDir: process.env.LEVARG_DATA_DIR || process.cwd(),
    });
  });

  // ───── SCOPES ─────
  app.get('/api/scopes', (_req, res) => {
    const scopes = db.prepare('SELECT * FROM scopes ORDER BY created_at DESC').all();
    res.json(scopes);
  });

  app.post('/api/scopes', (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    const cleaned = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    const id = uuidv4();
    try {
      db.prepare('INSERT INTO scopes (id, domain) VALUES (?, ?)').run(id, cleaned);
      res.json({ id, domain: cleaned });
    } catch (err: any) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'scope exists' });
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/scopes/:id', (req, res) => {
    db.prepare('DELETE FROM scopes WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  });

  // ───── ENDPOINTS ─────
  app.get('/api/endpoints', (_req, res) => {
    const endpoints = db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC').all();
    res.json(endpoints);
  });

  app.post('/api/endpoints', (req, res) => {
    const { url, method, source } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO endpoints (id, url, method, source) VALUES (?, ?, ?, ?)').run(id, url, method || 'GET', source || 'manual');
    res.json({ id, url, method: method || 'GET', source: source || 'manual' });
  });

  app.delete('/api/endpoints/:id', (req, res) => {
    db.prepare('DELETE FROM endpoints WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  });

  // ───── HISTORY (requests + responses) ─────
  app.get('/api/history', (_req, res) => {
    const rows = db.prepare(`
      SELECT r.id, r.name, r.method, r.url, r.headers, r.body, r.created_at,
             resp.status AS response_status, resp.headers AS response_headers,
             resp.body AS response_body
      FROM requests r
      LEFT JOIN responses resp ON resp.request_id = r.id
      ORDER BY r.created_at DESC
      LIMIT 200
    `).all();
    res.json(rows);
  });

  // ───── REQUEST LAB ─────
  app.post('/api/lab/send', async (req, res) => {
    const { method, url, headers, body: reqBody, name, scope_id, session_id } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    try {
      const axiosHeaders: Record<string, string> = {};
      if (headers) {
        if (typeof headers === 'string') {
          for (const line of headers.split('\n')) {
            const idx = line.indexOf(':');
            if (idx > 0) axiosHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
          }
        } else {
          Object.assign(axiosHeaders, headers);
        }
      }

      if (session_id && scope_id) {
        try {
          const overlay = SessionVault.buildRequestOverlay(session_id, url);
          Object.assign(axiosHeaders, overlay.headers);
          if (overlay.cookieHeader) axiosHeaders['Cookie'] = overlay.cookieHeader;
        } catch {}
      }

      if (!axiosHeaders['User-Agent']) axiosHeaders['User-Agent'] = pickRandomBrowserUA();

      const response = await axios({
        method: (method || 'GET').toLowerCase() as any,
        url,
        headers: axiosHeaders,
        data: reqBody || undefined,
        timeout: 30000,
        maxRedirects: 5,
        validateStatus: () => true,
      });

      const requestId = uuidv4();
      const responseId = uuidv4();
      db.prepare('INSERT INTO requests (id, name, method, url, headers, body) VALUES (?, ?, ?, ?, ?, ?)')
        .run(requestId, name || null, method || 'GET', url, JSON.stringify(axiosHeaders), reqBody || null);
      db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(responseId, requestId, response.status, JSON.stringify(response.headers),
          typeof response.data === 'string' ? response.data : JSON.stringify(response.data));

      res.json({
        requestId,
        status: response.status,
        headers: response.headers,
        body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
      });
    } catch (err: any) {
      res.status(502).json({ error: err.message });
    }
  });

  // ───── LAB PROXY ─────
  app.all('/api/lab/proxy', async (req, res) => {
    const targetUrl = req.query.url as string || req.body?.url;
    if (!targetUrl) return res.status(400).json({ error: 'url query param required' });
    try {
      const response = await axios({
        method: req.method.toLowerCase() as any,
        url: targetUrl,
        headers: { 'User-Agent': pickRandomBrowserUA() },
        data: req.body?.data || undefined,
        timeout: 30000,
        validateStatus: () => true,
      });
      res.status(response.status).json({
        status: response.status,
        headers: response.headers,
        body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
      });
    } catch (err: any) {
      res.status(502).json({ error: err.message });
    }
  });

  // ───── PAYLOADS ─────
  app.get('/api/payloads', (_req, res) => {
    const payloads = db.prepare('SELECT * FROM payloads ORDER BY created_at DESC').all();
    res.json(payloads);
  });

  app.post('/api/payloads', (req, res) => {
    const { name, content, type } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO payloads (id, name, content, type) VALUES (?, ?, ?, ?)').run(id, name, content, type || 'custom');
    res.json({ id, name, content, type: type || 'custom' });
  });

  app.delete('/api/payloads/:id', (req, res) => {
    db.prepare('DELETE FROM payloads WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  });

  // ───── FLOWS ─────
  app.get('/api/flows', (_req, res) => {
    const flows = db.prepare('SELECT * FROM flows ORDER BY created_at DESC').all();
    res.json(flows.map((f: any) => ({ ...f, steps: JSON.parse(f.steps || '[]') })));
  });

  app.post('/api/flows', (req, res) => {
    const { name, steps } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO flows (id, name, steps) VALUES (?, ?, ?)').run(id, name, JSON.stringify(steps || []));
    res.json({ id, name, steps: steps || [] });
  });

  app.delete('/api/flows/:id', (req, res) => {
    db.prepare('DELETE FROM flows WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  });

  // ───── SESSIONS ─────
  app.get('/api/sessions', (req, res) => {
    const scopeId = req.query.scope_id as string;
    const rows = scopeId
      ? db.prepare('SELECT * FROM sessions WHERE scope_id = ? ORDER BY updated_at DESC').all(scopeId)
      : db.prepare('SELECT * FROM sessions ORDER BY updated_at DESC').all();
    res.json(rows.map((r: any) => ({
      ...r,
      cookies: JSON.parse(r.cookies || '[]'),
      headers: JSON.parse(r.headers || '{}'),
      storage: JSON.parse(r.storage || '{}'),
    })));
  });

  app.post('/api/sessions', (req, res) => {
    const { scope_id, name, cookies, headers, storage, user_agent, notes } = req.body;
    if (!scope_id || !name) return res.status(400).json({ error: 'scope_id and name required' });
    const id = uuidv4();
    try {
      db.prepare(`INSERT INTO sessions (id, scope_id, name, cookies, headers, storage, user_agent, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, scope_id, name, JSON.stringify(cookies || []), JSON.stringify(headers || {}), JSON.stringify(storage || {}), user_agent || null, notes || null);
      res.json({ id, scope_id, name });
    } catch (err: any) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'session name exists for this scope' });
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/sessions/:id', (req, res) => {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  });

  // ───── CREDENTIALS ─────
  app.get('/api/credentials', (req, res) => {
    const scopeId = req.query.scope_id as string;
    const rows = scopeId
      ? CredentialVault.list(scopeId)
      : CredentialVault.list();
    res.json(rows);
  });

  app.post('/api/credentials', (req, res) => {
    try {
      const cred = CredentialVault.create(req.body);
      res.json(cred);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/credentials/:id', (req, res) => {
    CredentialVault.delete(req.params.id);
    res.json({ ok: true });
  });

  // ───── AUTH FLOWS ─────
  app.get('/api/auth-flows', (req, res) => {
    const scopeId = req.query.scope_id as string;
    const rows = scopeId
      ? AuthFlowVault.list(scopeId)
      : AuthFlowVault.list();
    res.json(rows);
  });

  app.post('/api/auth-flows', (req, res) => {
    try {
      const flow = AuthFlowVault.create(req.body);
      res.json(flow);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/auth-flows/:id', (req, res) => {
    AuthFlowVault.delete(req.params.id);
    res.json({ ok: true });
  });

  // ───── BROWSER (unavailable on Android) ─────
  app.post('/api/browser/launch', (_req, res) => {
    res.status(501).json({ error: 'Built-in browser is not available on Android. Use the mobile browser for authenticated testing.' });
  });
  app.post('/api/browser/close', (_req, res) => {
    res.status(501).json({ error: 'Built-in browser not available on Android' });
  });
  app.post('/api/browser/capture', (_req, res) => {
    res.status(501).json({ error: 'Built-in browser not available on Android' });
  });

  // ───── AUTOMATION ─────
  app.get('/api/automation/jobs', (_req, res) => {
    const jobs = db.prepare('SELECT * FROM automation_jobs ORDER BY created_at DESC').all();
    res.json(jobs.map((j: any) => ({ ...j, findings: JSON.parse(j.findings || '[]') })));
  });

  app.get('/api/automation/jobs/:id', (req, res) => {
    const job = db.prepare('SELECT * FROM automation_jobs WHERE id = ?').get(req.params.id) as any;
    if (!job) return res.status(404).json({ error: 'not found' });
    res.json({ ...job, findings: JSON.parse(job.findings || '[]') });
  });

  app.get('/api/automation/jobs/:id/logs', (req, res) => {
    const logs = db.prepare('SELECT * FROM automation_logs WHERE job_id = ? ORDER BY created_at ASC').all(req.params.id);
    res.json(logs.map((l: any) => ({ ...l, data: JSON.parse(l.data || '{}') })));
  });

  app.post('/api/automation/start', async (req, res) => {
    const { target_url, session_id, auth_flow_id } = req.body;
    if (!target_url) return res.status(400).json({ error: 'target_url required' });

    // startJob creates the DB row and returns the job ID
    AutomationEngine.startJob(target_url, { sessionId: session_id, authFlowId: auth_flow_id })
      .then(jobId => console.log(`[Automation] Job ${jobId} started`))
      .catch(err => console.error(`[Automation] Job failed:`, err.message));

    res.json({ status: 'started' });
  });

  app.post('/api/automation/stop/:id', (req, res) => {
    db.prepare("UPDATE automation_jobs SET status = 'failed' WHERE id = ? AND status IN ('pending','running')")
      .run(req.params.id);
    res.json({ ok: true });
  });

  // ───── TOOLS ─────
  app.get('/api/tools', async (_req, res) => {
    const statuses = await ToolManager.getAllStatus();
    res.json(statuses);
  });

  app.get('/api/tools/:name/status', async (req, res) => {
    const status = await ToolManager.getToolStatus(req.params.name);
    res.json(status);
  });

  // ───── STACK GAP ─────
  app.post('/api/stack-gap/analyze', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    try {
      const result = await StackGapAnalyzer.analyze(url);
      res.json(result);
    } catch (err: any) {
      res.status(502).json({ error: err.message });
    }
  });

  // ───── AI PROXY (Ollama — if available remotely) ─────
  const ollamaBase = process.env.OLLAMA_HOST || 'http://localhost:11434';
  app.post('/api/ai/generate', async (req, res) => {
    try {
      const response = await axios.post(`${ollamaBase}/api/generate`, req.body, { timeout: 60000 });
      res.json(response.data);
    } catch (err: any) {
      res.status(503).json({ error: 'AI not available. Configure OLLAMA_HOST to connect to a remote Ollama instance.' });
    }
  });

  app.post('/api/ai/analyze', async (req, res) => {
    try {
      const response = await axios.post(`${ollamaBase}/api/generate`, req.body, { timeout: 60000 });
      res.json(response.data);
    } catch (err: any) {
      res.status(503).json({ error: 'AI not available. Configure OLLAMA_HOST to connect to a remote Ollama instance.' });
    }
  });

  // ───── SCAN RESULTS ─────
  app.get('/api/scans', (_req, res) => {
    const scans = db.prepare('SELECT * FROM scans ORDER BY created_at DESC').all();
    res.json(scans);
  });

  app.get('/api/scans/:id/results', (req, res) => {
    const results = db.prepare('SELECT * FROM scan_results WHERE scan_id = ? ORDER BY created_at ASC').all(req.params.id);
    res.json(results);
  });

  // ───── STATIC FILES ─────
  // In the Android app, the Capacitor WebView serves the frontend directly.
  // This Express server only needs to handle API routes.
  // But we still serve dist/ as a fallback for any non-API routes.
  const distPath = path.join(process.cwd(), 'dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ error: 'not found' });
    }
    res.sendFile(path.join(distPath, 'index.html'));
  });

  app.listen(PORT, '127.0.0.1', () => {
    console.log(`LevarG Mobile Server running on http://127.0.0.1:${PORT}`);
  });

  // Clean shutdown
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

startServer().catch(err => {
  console.error('Failed to start mobile server:', err);
});

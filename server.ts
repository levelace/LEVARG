
import 'dotenv/config';
import express from 'express';
import path from 'path';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { createServer as createViteServer } from 'vite';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import db from './db.js';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import { AutomationEngine } from './automation_engine.js';

import { ToolManager } from './tool_manager.js';
import { OllamaClient } from './ollama_client.js';
import { OllamaManager } from './ollama_manager.js';
import { SessionVault, SessionScopeError, type SessionCookie, type SessionStorage } from './session_vault.js';
import { BrowserManager } from './browser_manager.js';
import { CredentialVault } from './credential_vault.js';
import { AuthFlowVault, type AuthFlowStep, type TriggerMode } from './auth_flow_vault.js';
import { ExtensionTokenVault } from './extension_token_vault.js';
import { detectLoginForm } from './form_detector.js';
import { USER_AGENTS, getUserAgent, pickRandomBrowserUA } from './user_agents.js';
import { WafBypassEngine } from './waf_bypass_engine.js';
import { OriginIpDetector } from './origin_ip_detector.js';
import { EndpointHeaders } from './endpoint_headers.js';
import { MatchReplace } from './match_replace.js';

async function startServer() {
  // Auto-install, start, and pull model for Ollama (runs in background)
  const ollamaReady = OllamaManager.bootstrap().catch(err => {
    console.warn('[Ollama] Bootstrap error (AI features may be unavailable):', err.message);
  });

  const app = express();
  const PORT = parseInt(process.env.LEVARG_PORT || '3000', 10);
  const BIND_HOST = process.env.LEVARG_BIND || '127.0.0.1';
  const API_KEY = process.env.LEVARG_API_KEY || '';

  // CORS: restrict to same-origin by default; allow explicit origins via env
  const allowedOrigins = process.env.LEVARG_CORS_ORIGINS
    ? process.env.LEVARG_CORS_ORIGINS.split(',')
    : [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];
  app.use(cors({
    origin: (origin, cb) => {
      // Allow requests with no origin (curl, server-to-server, same-origin)
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error('CORS: origin not allowed'));
    },
  }));
  app.use(express.json({ limit: '2mb' }));

  // Optional API-key gate for non-localhost access
  if (API_KEY) {
    app.use('/api', (req, res, next) => {
      const provided = req.headers['x-api-key'] || req.query.apiKey;
      if (provided === API_KEY) return next();
      // Always allow localhost without key
      const ip = req.ip || req.socket.remoteAddress || '';
      if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return next();
      res.status(401).json({ error: 'Invalid or missing API key' });
    });
  }

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
      domain = domain.trim().toLowerCase();
      if (domain.startsWith('http://') || domain.startsWith('https://')) {
        try {
          domain = new URL(domain).hostname;
        } catch (e) {}
      } else {
        domain = domain.split('/')[0].split(':')[0];
      }
      // Strip trailing dots (DNS root)
      domain = domain.replace(/\.+$/, '');
      // Strip leading wildcard prefix
      domain = domain.replace(/^\*\./, '');
      // Guard against TLD-only or single-label scopes
      if (!domain || !domain.includes('.')) {
        return res.status(400).json({ error: 'Domain must have at least two labels (e.g. example.com)' });
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
    const limit = Math.min(parseInt(String(req.query.limit || '500'), 10) || 500, 5000);
    const offset = parseInt(String(req.query.offset || '0'), 10) || 0;
    const endpoints = db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
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
    const { endpoints } = req.body;
    if (!Array.isArray(endpoints)) {
      return res.status(400).json({ error: 'endpoints must be an array' });
    }
    const valid = endpoints.filter(
      (e: unknown) => e && typeof e === 'object' && typeof (e as Record<string, unknown>).url === 'string',
    );
    if (valid.length === 0) {
      return res.status(400).json({ error: 'No valid endpoints provided (each must have a url string)' });
    }
    const insert = db.prepare('INSERT OR IGNORE INTO endpoints (id, url, method, source) VALUES (?, ?, ?, ?)');
    const transaction = db.transaction((items: { url: string; method?: string; source?: string }[]) => {
      for (const item of items) {
        insert.run(uuidv4(), item.url, item.method || 'GET', item.source || 'manual');
      }
    });
    transaction(valid);
    res.json({ success: true, count: valid.length });
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
      // Layer per-endpoint custom headers (won't overwrite explicit headers)
      finalHeaders = EndpointHeaders.mergeHeaders(url, finalHeaders);

      // --- Match & Replace: request phase ---
      const mrReq = MatchReplace.applyToRequest(
        { url, method, headers: finalHeaders, body: typeof body === 'string' ? body : JSON.stringify(body ?? '') },
      );
      const finalUrl = mrReq.url;
      const finalMethod = mrReq.method;
      finalHeaders = mrReq.headers;
      const finalBody = mrReq.body || body;

      const startTime = Date.now();
      const response = await axios({
        method: finalMethod,
        url: finalUrl,
        headers: finalHeaders,
        data: finalBody,
        validateStatus: () => true,
        timeout: 10000
      });
      const duration = Date.now() - startTime;

      // --- Match & Replace: response phase ---
      const mrRes = MatchReplace.applyToResponse(
        { url: finalUrl, method: finalMethod, headers: finalHeaders, body: typeof finalBody === 'string' ? finalBody : JSON.stringify(finalBody ?? '') },
        {
          status: response.status,
          headers: response.headers as Record<string, string>,
          body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
        },
      );

      const requestId = uuidv4();
      const responseId = uuidv4();

      // Save request/response for history/diff
      db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(requestId, finalMethod, finalUrl, JSON.stringify(finalHeaders), typeof finalBody === 'string' ? finalBody : JSON.stringify(finalBody));
      
      db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(responseId, requestId, mrRes.status, JSON.stringify(mrRes.headers), typeof mrRes.body === 'string' ? mrRes.body : JSON.stringify(mrRes.body));

      res.json({
        id: responseId,
        status: mrRes.status,
        headers: mrRes.headers,
        body: mrRes.body,
        duration
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Payloads
  app.get('/api/payloads', (req, res) => {
    const limit = Math.min(parseInt(String(req.query.limit || '500'), 10) || 500, 5000);
    const offset = parseInt(String(req.query.offset || '0'), 10) || 0;
    const payloads = db.prepare('SELECT * FROM payloads ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
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
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'content is required' });
    if (!type || typeof type !== 'string') return res.status(400).json({ error: 'type is required' });
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
    const limit = Math.min(parseInt(String(req.query.limit || '500'), 10) || 500, 5000);
    const offset = parseInt(String(req.query.offset || '0'), 10) || 0;
    const flows = db.prepare('SELECT * FROM flows ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
    res.json(flows.map((f: any) => ({ ...f, steps: JSON.parse(f.steps) })));
  });

  app.post('/api/flows', (req, res) => {
    const { name, steps } = req.body;
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
    if (!Array.isArray(steps)) return res.status(400).json({ error: 'steps must be an array' });
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

  // --- Stored credentials (scope-bound) ---
  // The operator-input side of authenticated testing: stores the username +
  // password pair an auth-flow will type into the in-scope login form. Bound
  // 1:1 to a Scope so credentials for scope A can never be replayed against
  // scope B. Plaintext at rest by design (matches Burp/ZAP project files);
  // the password is redacted in list/get responses unless the caller is the
  // auth-flow runner.

  app.get('/api/credentials', (req, res) => {
    try {
      const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
      const rows = CredentialVault.list(scopeId).map((r) => CredentialVault.toPublic(r, false));
      res.json(rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/credentials/:id', (req, res) => {
    const row = CredentialVault.get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Credential not found' });
    res.json(CredentialVault.toPublic(row, false));
  });

  app.post('/api/credentials', (req, res) => {
    try {
      const { scopeId, label, username, password, notes } = req.body as {
        scopeId: string;
        label: string;
        username: string;
        password: string;
        notes?: string | null;
      };
      if (!scopeId) return res.status(400).json({ error: 'scopeId is required' });
      const created = CredentialVault.create({ scopeId, label, username, password, notes });
      res.json(CredentialVault.toPublic(created, false));
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.patch('/api/credentials/:id', (req, res) => {
    try {
      const { label, username, password, notes } = req.body as {
        label?: string;
        username?: string;
        password?: string;
        notes?: string | null;
      };
      const updated = CredentialVault.update(req.params.id, { label, username, password, notes });
      res.json(CredentialVault.toPublic(updated, false));
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/credentials/:id', (req, res) => {
    const ok = CredentialVault.delete(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Credential not found' });
    res.json({ success: true });
  });

  // --- Auth flows (scope-bound login macros) ---
  // Replayable login sequences played against the built-in browser; the
  // resulting cookie jar is captured into a SessionVault session bound to
  // the same scope. See auth_flow_vault.ts for the per-step scope guards.

  app.get('/api/auth-flows', (req, res) => {
    try {
      const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
      res.json(AuthFlowVault.list(scopeId));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/auth-flows/:id', (req, res) => {
    const flow = AuthFlowVault.get(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Auth flow not found' });
    res.json(flow);
  });

  app.post('/api/auth-flows', (req, res) => {
    try {
      const { scopeId, name, steps, credentialId, triggerMode, isDefault } = req.body as {
        scopeId: string;
        name: string;
        steps: AuthFlowStep[];
        credentialId?: string | null;
        triggerMode?: TriggerMode;
        isDefault?: boolean;
      };
      if (!scopeId) return res.status(400).json({ error: 'scopeId is required' });
      const created = AuthFlowVault.create({
        scopeId,
        name,
        steps,
        credentialId,
        triggerMode,
        isDefault,
      });
      res.json(created);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.patch('/api/auth-flows/:id', (req, res) => {
    try {
      const { name, steps, credentialId, triggerMode, isDefault } = req.body as {
        name?: string;
        steps?: AuthFlowStep[];
        credentialId?: string | null;
        triggerMode?: TriggerMode;
        isDefault?: boolean;
      };
      const updated = AuthFlowVault.update(req.params.id, {
        name,
        steps,
        credentialId,
        triggerMode,
        isDefault,
      });
      res.json(updated);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/auth-flows/:id', (req, res) => {
    const ok = AuthFlowVault.delete(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Auth flow not found' });
    res.json({ success: true });
  });

  app.post('/api/auth-flows/:id/run', async (req, res) => {
    try {
      const result = await AuthFlowVault.run(req.params.id, {
        sessionLabel: typeof req.body?.sessionLabel === 'string' ? req.body.sessionLabel : undefined,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- Login form auto-detect (heuristic) ---
  // Fetches the given URL through the same scope gate that protects /api/lab/proxy,
  // runs the heuristic detector, and returns the inferred selectors. The UI uses
  // this to pre-populate auth-flow steps so the operator doesn't have to write
  // selectors by hand for the common case.
  app.post('/api/auth-flows/detect', async (req, res) => {
    try {
      const { url } = req.body as { url: string };
      if (!url) return res.status(400).json({ error: 'url is required' });
      const targetHost = new URL(url).hostname;
      const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
      const inScope = scopes.some(
        (s) => targetHost === s.domain || targetHost.endsWith(`.${s.domain}`),
      );
      if (!inScope) {
        return res.status(403).json({ error: 'Target is not in any registered scope' });
      }
      const userAgentId = typeof req.body?.userAgentId === 'string' ? req.body.userAgentId : undefined;
      const response = await axios.get(url, {
        validateStatus: () => true,
        timeout: 10000,
        headers: { 'User-Agent': getUserAgent(userAgentId) ?? pickRandomBrowserUA() },
      });
      const html = typeof response.data === 'string' ? response.data : '';
      const detected = detectLoginForm(html, url);
      if (!detected) {
        return res.json({ detected: null, message: 'No login form detected on this page' });
      }
      // Pre-populate steps the operator can save as a flow.
      const steps: AuthFlowStep[] = [{ type: 'goto', url, waitFor: 'networkidle2' }];
      if (detected.usernameSelector) {
        steps.push({ type: 'fill', selector: detected.usernameSelector, value: '${USERNAME}' });
      }
      if (!detected.hasMultiStep) {
        steps.push({
          type: 'fill',
          selector: detected.passwordSelector,
          value: '${PASSWORD}',
          secret: true,
        });
      }
      if (detected.submitSelector) {
        steps.push({ type: 'click', selector: detected.submitSelector });
      } else {
        steps.push({ type: 'press', key: 'Enter' });
      }
      res.json({ detected, suggestedSteps: steps });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- User-Agent catalog ---
  // Real, curated UA strings (browsers across Windows/macOS/Linux/Android/iOS,
  // plus enterprise security tools). Used by the auth-flow editor's UA picker
  // and by Request Lab / Scanner when the operator wants to override the
  // default UA (e.g. announce as Burp on a sanctioned engagement).
  app.get('/api/user-agents', (_req, res) => {
    res.json(USER_AGENTS);
  });

  // --- OS-browser bridge (extension / bookmarklet / manual paste) ---
  // The bridge lets the operator complete login in their PRIMARY browser
  // (where their password manager / biometric auth / saved sessions live)
  // instead of inside the headless puppeteer Chromium. Cookies flow back
  // into LEVARG via /api/extension/cookies, gated by a per-scope token so
  // the bridge can never leak cookies into the wrong scope.

  app.get('/api/extension/tokens', (req, res) => {
    try {
      const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
      res.json(ExtensionTokenVault.list(scopeId));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/extension/tokens', (req, res) => {
    try {
      const { scopeId, label } = req.body as { scopeId: string; label?: string | null };
      if (!scopeId) return res.status(400).json({ error: 'scopeId is required' });
      const created = ExtensionTokenVault.create({ scopeId, label });
      res.json(created);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.delete('/api/extension/tokens/:id', (req, res) => {
    const ok = ExtensionTokenVault.delete(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Token not found' });
    res.json({ success: true });
  });

  // Cookie ingest — called by the extension, the bookmarklet, or the manual-
  // paste UI. Any cookie whose host is outside the token's bound scope is
  // silently dropped (logged but not stored), so a cookie jar containing
  // accounts.google.com / appleid.apple.com cookies can't smuggle creds
  // into a session bound to a different scope.
  app.post('/api/extension/cookies', (req, res) => {
    try {
      const { token, sessionName, cookies, storage, userAgent } = req.body as {
        token: string;
        sessionName?: string;
        cookies: SessionCookie[];
        storage?: SessionStorage;
        userAgent?: string | null;
      };
      if (!token) return res.status(400).json({ error: 'token is required' });
      if (!Array.isArray(cookies)) return res.status(400).json({ error: 'cookies must be an array' });
      const tokenRow = ExtensionTokenVault.getByToken(token);
      if (!tokenRow) return res.status(401).json({ error: 'Unknown extension token' });
      if (!tokenRow.scope_domain) {
        return res.status(409).json({ error: 'Token references a scope that no longer exists' });
      }
      const scopeDomain = tokenRow.scope_domain;
      const accepted: SessionCookie[] = [];
      const droppedHosts = new Set<string>();
      for (const c of cookies) {
        const d = (c.domain ?? '').replace(/^\./, '');
        if (!d) {
          // Host-only cookie with no domain field — accept; ingest path infers domain at replay.
          accepted.push(c);
          continue;
        }
        if (d === scopeDomain || d.endsWith(`.${scopeDomain}`)) {
          accepted.push(c);
        } else {
          droppedHosts.add(d);
        }
      }
      const created = SessionVault.create({
        scopeId: tokenRow.scope_id,
        name:
          (sessionName?.trim() && sessionName.trim()) ||
          `os-browser:${new Date().toISOString().replace(/[:.]/g, '-')}`,
        cookies: accepted,
        headers: {},
        storage: storage ?? {},
        userAgent: userAgent ?? null,
        notes: `Captured via OS-browser bridge (token ${tokenRow.id}). Dropped ${droppedHosts.size} out-of-scope host(s).`,
      });
      ExtensionTokenVault.recordUse(token);
      res.json({
        sessionId: created.id,
        accepted: accepted.length,
        droppedOutOfScope: droppedHosts.size,
        droppedHosts: Array.from(droppedHosts),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Streams the contents of `extension/` as a tar.gz so the operator can
  // grab the OS-browser bridge from any LEVARG instance without needing the
  // full repo. Tar (not zip) keeps the dependency footprint to nothing —
  // Node has built-in tar support via child_process.
  app.get('/api/extension/download', (_req, res) => {
    const dir = path.join(process.cwd(), 'extension');
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="levarg-bridge.tar.gz"');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { spawn } = require('child_process') as typeof import('child_process');
    const tar = spawn('tar', ['-czf', '-', '-C', dir, '.']);
    tar.stdout.pipe(res);
    tar.on('error', (e: Error) => {
      res.destroy(e);
    });
  });

  // Bookmarklet generator: returns a `javascript:` URL the operator can drag
  // to their bookmarks bar. Clicking it on any page POSTs that page's
  // document.cookie + localStorage back to LEVARG. HttpOnly cookies are NOT
  // captured (browser limit, not LEVARG's) — this is the mobile fallback;
  // the extension is the strong path.
  app.get('/api/extension/bookmarklet', (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const ingestUrl = typeof req.query.ingestUrl === 'string' ? req.query.ingestUrl : '';
    if (!token || !ingestUrl) {
      return res.status(400).json({ error: 'token and ingestUrl are required' });
    }
    // Validate ingestUrl points to a known self-origin to prevent exfiltration
    try {
      const parsed = new URL(ingestUrl);
      const selfOrigins = [
        `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`,
        `http://${BIND_HOST}:${PORT}`,
        ...(process.env.APP_URL ? [process.env.APP_URL] : []),
      ];
      const ingestOrigin = parsed.origin;
      if (!selfOrigins.some(o => ingestOrigin === o || ingestOrigin === new URL(o).origin)) {
        return res.status(400).json({ error: 'ingestUrl must point to this LEVARG instance' });
      }
    } catch {
      return res.status(400).json({ error: 'ingestUrl is not a valid URL' });
    }
    const ingestUrlJson = JSON.stringify(ingestUrl);
    const tokenJson = JSON.stringify(token);
    // Built as a single-line javascript: URL. fetch() the ingest endpoint
    // with the page's accessible cookies. Body is read by the inner script
    // so the operator can see any error inline.
    const script = `(function(){var c=document.cookie.split(';').map(function(p){var i=p.indexOf('=');var n=p.slice(0,i).trim();var v=p.slice(i+1);return{name:n,value:v,domain:location.hostname,path:'/'}}).filter(function(c){return c.name});var ls={};try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);ls[k]=localStorage.getItem(k)}}catch(e){}fetch(${ingestUrlJson},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:${tokenJson},sessionName:'bookmarklet:'+location.hostname,cookies:c,storage:{localStorage:ls},userAgent:navigator.userAgent})}).then(function(r){return r.json()}).then(function(j){alert('LEVARG: captured '+j.accepted+' cookies, dropped '+(j.droppedOutOfScope||0)+' out of scope. session='+j.sessionId)}).catch(function(e){alert('LEVARG ingest failed: '+e.message)})})();`;
    const url = `javascript:${encodeURI(script)}`;
    res.json({ bookmarklet: url });
  });

  // Pairing landing page — the operator opens this on their primary device
  // (phone or desktop). Walks them through extension install, bookmarklet
  // drag, or manual paste, with the token pre-filled. Pure HTML, no React,
  // so it works even on mobile browsers that can't run the SPA.
  app.get('/pair/:token', (req, res) => {
    const token = req.params.token;
    const row = ExtensionTokenVault.getByToken(token);
    if (!row) {
      res.status(404).type('html').send('<h1>Unknown pairing token</h1>');
      return;
    }
    const scopeDomain = row.scope_domain ?? '(scope deleted)';
    const ingestUrl = `${req.protocol}://${req.get('host')}/api/extension/cookies`;
    const bookmarkletUrl = `${req.protocol}://${req.get('host')}/api/extension/bookmarklet?token=${encodeURIComponent(token)}&ingestUrl=${encodeURIComponent(ingestUrl)}`;
    const downloadUrl = `${req.protocol}://${req.get('host')}/api/extension/download`;
    // Every dynamic value rendered into this page is escaped because the scope
    // domain (operator-supplied), the token (URL param), and the Host header
    // (used to derive ingestUrl/bookmarkletUrl/downloadUrl) are all attacker-
    // influenceable. Without escaping a domain like
    // `example.com<img src=x onerror=...>` would execute in the operator's
    // browser when they open the pairing page.
    const esc = (s: string) =>
      s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    const dom = esc(scopeDomain);
    const tok = esc(token);
    const ingest = esc(ingestUrl);
    const bookmarklet = esc(bookmarkletUrl);
    const dl = esc(downloadUrl);
    res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LEVARG — pair OS browser</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;color:#111}h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem}code{background:#f3f3f3;padding:.1rem .35rem;border-radius:.25rem;word-break:break-all}.token{font-family:ui-monospace,monospace;font-size:.85rem;background:#fafafa;padding:.5rem;border:1px solid #ddd;border-radius:.4rem;word-break:break-all}.warn{color:#a40;font-size:.9rem}</style>
</head><body>
<h1>Pair your browser to LEVARG</h1>
<p>Bound scope: <code>${dom}</code></p>
<p>Token (copy this into the LEVARG extension's options page):</p>
<div class="token">${tok}</div>
<h2>Option A — install the extension (desktop)</h2>
<p>Recommended for HttpOnly cookies (auth cookies are usually HttpOnly).</p>
<ol><li>The extension lives in the LEVARG repo at <code>extension/</code>. If you have the repo locally, point Chrome at that folder; otherwise download a tarball: <code>curl -O ${dl}</code></li>
<li>Open <code>chrome://extensions</code>, enable Developer Mode, click Load Unpacked, select the <code>extension/</code> folder.</li>
<li>Open the extension's options page, paste the token above, set ingest URL to <code>${ingest}</code>, save.</li>
<li>Log in to <code>${dom}</code> in your normal tab. Click the extension icon → “Capture cookies”.</li></ol>
<h2>Option B — bookmarklet (mobile or no-install)</h2>
<p class="warn">Bookmarklets cannot read HttpOnly cookies (browser limit). Use the extension when possible.</p>
<ol><li>Open <a href="${bookmarklet}">this page</a> on the device where you'll log in, save the JSON's <code>bookmarklet</code> field as a bookmark.</li>
<li>Log in to <code>${dom}</code> in your normal tab.</li>
<li>Tap the bookmark on that page — LEVARG ingests whatever cookies the page can see.</li></ol>
<h2>Option C — manual paste</h2>
<p>Open DevTools → Application → Cookies, copy as JSON, paste into the LEVARG UI → Sessions → Import. The UI will POST to the same ingest endpoint with this token.</p>
<p>Ingest endpoint (for tooling): <code>${ingest}</code></p>
</body></html>`);
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

    // Run async worker with crash-safe status management
    const runScan = async () => {
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

        // Insert results in batched transactions for crash safety
        const insertResult = db.prepare('INSERT INTO scan_results (id, scan_id, payload, status, length, is_anomaly, response_id) VALUES (?, ?, ?, ?, ?, ?, ?)');
        const insertReq = db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)');
        const insertRes = db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)');

        const BATCH_SIZE = 25;
        for (let i = 0; i < payloads.length; i += BATCH_SIZE) {
          const batch = payloads.slice(i, i + BATCH_SIZE);
          const batchInserts: (() => void)[] = [];

          for (const payload of batch) {
            const pUrl = targetUrl.replace('§FUZZ§', encodeURIComponent(payload));
            const pBody = typeof body === 'string' ? body.replace('§FUZZ§', payload) : body;

            let pHeaders: Record<string, string>;
            try {
              pHeaders = SessionVault.applyToHeaders(sessionId, pUrl, headers);
            } catch (err) {
              if (err instanceof SessionScopeError) {
                pHeaders = { ...(headers ?? {}) };
              } else {
                throw err;
              }
            }

            const pRes = await axios({ method, url: pUrl, headers: pHeaders, data: pBody, validateStatus: () => true, timeout: 5000 }).catch(() => null);

            const pStatus = pRes ? pRes.status : 0;
            const pLength = pRes ? JSON.stringify(pRes.data).length : 0;
            const lengthDiff = Math.abs(pLength - baselineLength);
            const isAnomaly = (pStatus !== baselineStatus && pStatus !== 0) || (baselineLength > 0 && (lengthDiff / baselineLength) > 0.1);

            const resId = uuidv4();
            batchInserts.push(() => {
              if (pRes) {
                const reqId = uuidv4();
                // Truncate response body to 100KB to prevent DB bloat
                const resBody = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
                const truncatedBody = resBody.length > 102400 ? resBody.substring(0, 102400) + '\n[truncated]' : resBody;
                insertReq.run(reqId, method, pUrl, JSON.stringify(pHeaders), typeof pBody === 'string' ? pBody : JSON.stringify(pBody));
                insertRes.run(resId, reqId, pStatus, JSON.stringify(pRes.headers), truncatedBody);
              }
              insertResult.run(uuidv4(), scanId, payload, pStatus, pLength, isAnomaly ? 1 : 0, pRes ? resId : null);
            });
          }

          // Commit batch atomically
          db.transaction(() => { for (const fn of batchInserts) fn(); })();
        }

        db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('completed', scanId);
      } catch (err) {
        console.error('Scan error:', err);
        db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('failed', scanId);
      }
    };
    runScan().catch((err) => {
      console.error('Unhandled scan error:', err);
      try { db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('failed', scanId); } catch {}
    });
  });

  app.get('/api/scans', (req, res) => {
    const limit = Math.min(parseInt(String(req.query.limit || '500'), 10) || 500, 5000);
    const offset = parseInt(String(req.query.offset || '0'), 10) || 0;
    const scans = db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
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
    const { targetUrl, sessionId, authFlowId } = req.body as {
      targetUrl: string;
      sessionId?: string;
      authFlowId?: string;
    };
    try {
      // Pre-flight: validate session overlay applies to target before launch.
      if (sessionId) {
        try { SessionVault.buildRequestOverlay(sessionId, targetUrl); }
        catch (err) {
          if (err instanceof SessionScopeError) return res.status(err.status).json({ error: err.message });
          throw err;
        }
      }

      // Pre-flight auth-flow: if the operator picked an auth-flow (or one is
      // marked default for the target's scope and no explicit session was
      // passed), replay it now and bind the resulting session to the job.
      // This is the "start every hunt logged in" trigger.
      let resolvedSessionId = sessionId;
      let resolvedAuthFlowId = authFlowId;
      if (!resolvedAuthFlowId && !resolvedSessionId) {
        try {
          const targetHost = new URL(targetUrl).hostname;
          const scopes = db.prepare('SELECT id, domain FROM scopes').all() as {
            id: string;
            domain: string;
          }[];
          const matched = scopes.find(
            (s) => targetHost === s.domain || targetHost.endsWith(`.${s.domain}`),
          );
          if (matched) {
            const def = AuthFlowVault.getDefaultForScope(matched.id);
            if (def) resolvedAuthFlowId = def.id;
          }
        } catch {
          // invalid URL is caught later inside startJob; ignore here
        }
      }
      if (resolvedAuthFlowId) {
        const flow = AuthFlowVault.get(resolvedAuthFlowId);
        if (!flow) return res.status(404).json({ error: 'Auth flow not found' });
        // Validate the flow's scope covers the target before we burn time on a replay.
        try {
          const targetHost = new URL(targetUrl).hostname;
          if (!flow.scope_domain || !SessionVault.hostInScope(targetHost, flow.scope_domain)) {
            return res.status(403).json({
              error: `Auth flow is bound to scope '${flow.scope_domain}' and cannot pre-flight a hunt on '${targetHost}'`,
            });
          }
        } catch {
          return res.status(400).json({ error: 'Invalid targetUrl' });
        }
        const result = await AuthFlowVault.run(resolvedAuthFlowId);
        if (!result.ok || !result.sessionId) {
          return res
            .status(502)
            .json({ error: `Auth-flow pre-flight failed: ${result.error ?? 'unknown'}`, log: result.log });
        }
        resolvedSessionId = result.sessionId;
      }

      const jobId = await AutomationEngine.startJob(targetUrl, {
        sessionId: resolvedSessionId,
        authFlowId: resolvedAuthFlowId,
      });
      res.json({
        id: jobId,
        status: 'running',
        sessionId: resolvedSessionId ?? null,
        authFlowId: resolvedAuthFlowId ?? null,
      });
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

  // --- WAF Bypass Engine API ---
  app.post('/api/waf/fingerprint', async (req, res) => {
    const { targetUrl, customHeaders } = req.body as { targetUrl: string; customHeaders?: Record<string, string> };
    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({ error: 'targetUrl is required' });
    }
    try {
      const detections = await WafBypassEngine.fingerprint(targetUrl, { customHeaders });
      res.json({ target: targetUrl, detections });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/waf/bypass', async (req, res) => {
    const { targetUrl, maxBypasses, customHeaders } = req.body as {
      targetUrl: string; maxBypasses?: number; customHeaders?: Record<string, string>;
    };
    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({ error: 'targetUrl is required' });
    }
    try {
      const detections = await WafBypassEngine.fingerprint(targetUrl, { customHeaders });
      if (detections.length === 0) {
        return res.json({ target: targetUrl, wafDetected: false, bypasses: [] });
      }
      const bypasses = await WafBypassEngine.testBypasses(targetUrl, detections, { maxBypasses, customHeaders });
      res.json({ target: targetUrl, wafDetected: true, wafs: detections, bypasses });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/waf/techniques', (_req, res) => {
    res.json(WafBypassEngine.getTechniques());
  });

  app.get('/api/waf/signatures', (_req, res) => {
    res.json(WafBypassEngine.getSignatures());
  });

  // --- Origin IP Detection API ---
  app.post('/api/origin-ip/detect', async (req, res) => {
    const { domain, maxSubdomains } = req.body as { domain: string; maxSubdomains?: number };
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'domain is required' });
    }
    try {
      // Strip protocol if provided
      const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
      const report = await OriginIpDetector.detect(cleanDomain, { maxSubdomains });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- Per-Endpoint Custom Headers API ---
  app.get('/api/endpoint-headers', (req, res) => {
    const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
    res.json(EndpointHeaders.list(scopeId));
  });

  app.post('/api/endpoint-headers', (req, res) => {
    const { pattern, name, value, scopeId, description, priority } = req.body;
    if (!pattern || typeof pattern !== 'string') return res.status(400).json({ error: 'pattern is required' });
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'header name is required' });
    if (value === undefined || value === null) return res.status(400).json({ error: 'header value is required' });
    try {
      const header = EndpointHeaders.create({ pattern, name, value, scopeId, description, priority });
      res.json(header);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.patch('/api/endpoint-headers/:id', (req, res) => {
    try {
      const header = EndpointHeaders.update(req.params.id, req.body);
      res.json(header);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 400).json({ error: err.message });
    }
  });

  app.delete('/api/endpoint-headers/:id', (req, res) => {
    const deleted = EndpointHeaders.delete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Header rule not found' });
    res.json({ success: true });
  });

  app.post('/api/endpoint-headers/:id/toggle', (req, res) => {
    try {
      const header = EndpointHeaders.toggle(req.params.id);
      res.json(header);
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  });

  app.post('/api/endpoint-headers/match', (req, res) => {
    const { url, scopeId } = req.body as { url: string; scopeId?: string };
    if (!url) return res.status(400).json({ error: 'url is required' });
    const matched = EndpointHeaders.matchUrl(url, scopeId);
    res.json(matched);
  });

  // --- Match & Replace API ---
  app.get('/api/match-replace', (req, res) => {
    const scopeId = typeof req.query.scopeId === 'string' ? req.query.scopeId : undefined;
    res.json(MatchReplace.list(scopeId));
  });

  app.get('/api/match-replace/catalog', (_req, res) => {
    res.json({
      conditions: MatchReplace.getConditionCategories(),
      actions: MatchReplace.getActionCategories(),
    });
  });

  app.get('/api/match-replace/:id', (req, res) => {
    const rule = MatchReplace.get(req.params.id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    res.json(rule);
  });

  app.post('/api/match-replace', (req, res) => {
    const { name, phase, conditions, conditionLogic, actions, priority, scopeId, comment } = req.body;
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
    try {
      const rule = MatchReplace.create({ name, phase, conditions, conditionLogic, actions, priority, scopeId, comment });
      res.json(rule);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.patch('/api/match-replace/:id', (req, res) => {
    try {
      const rule = MatchReplace.update(req.params.id, req.body);
      res.json(rule);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 400).json({ error: err.message });
    }
  });

  app.delete('/api/match-replace/:id', (req, res) => {
    const deleted = MatchReplace.delete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Rule not found' });
    res.json({ success: true });
  });

  app.post('/api/match-replace/:id/toggle', (req, res) => {
    try {
      const rule = MatchReplace.toggle(req.params.id);
      res.json(rule);
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  });

  app.post('/api/match-replace/:id/duplicate', (req, res) => {
    try {
      const rule = MatchReplace.duplicate(req.params.id);
      res.json(rule);
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  });

  app.post('/api/match-replace/:id/reset-hits', (req, res) => {
    MatchReplace.resetHitCount(req.params.id);
    res.json({ success: true });
  });

  // --- Upgrade / About API ---
  const getLocalVersion = (): string => {
    try {
      const pkg = JSON.parse(readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8'));
      return pkg.version || '0.0.0';
    } catch {
      return '0.0.0';
    }
  };

  const getGitInfo = (): { branch: string; commit: string; commitDate: string } => {
    try {
      const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: process.cwd() }).toString().trim();
      const commit = execSync('git rev-parse --short HEAD', { cwd: process.cwd() }).toString().trim();
      const commitDate = execSync('git log -1 --format=%ci', { cwd: process.cwd() }).toString().trim();
      return { branch, commit, commitDate };
    } catch {
      return { branch: 'unknown', commit: 'unknown', commitDate: '' };
    }
  };

  app.get('/api/version', (_req, res) => {
    const version = getLocalVersion();
    const git = getGitInfo();
    const uptime = process.uptime();
    res.json({
      version,
      branch: git.branch,
      commit: git.commit,
      commitDate: git.commitDate,
      nodeVersion: process.version,
      platform: process.platform,
      uptime: Math.floor(uptime),
      pid: process.pid,
    });
  });

  app.get('/api/upgrade/check', async (_req, res) => {
    try {
      const localVersion = getLocalVersion();
      const git = getGitInfo();
      const localCommit = execSync('git rev-parse HEAD', { cwd: process.cwd() }).toString().trim();

      // Fetch latest from remote
      try {
        execSync('git fetch origin --quiet', { cwd: process.cwd(), timeout: 30_000 });
      } catch {
        return res.status(502).json({ error: 'Could not reach remote — check your network connection.' });
      }

      // Determine remote ref: try current branch, fall back to main/master
      let remoteBranch = git.branch;
      let remoteCommit: string;
      try {
        remoteCommit = execSync(`git rev-parse origin/${remoteBranch}`, { cwd: process.cwd() }).toString().trim();
      } catch {
        // Current branch has no remote tracking — try main, then master
        for (const fallback of ['main', 'master']) {
          try {
            remoteCommit = execSync(`git rev-parse origin/${fallback}`, { cwd: process.cwd() }).toString().trim();
            remoteBranch = fallback;
            break;
          } catch { /* continue */ }
        }
        if (!remoteCommit!) {
          return res.json({
            currentVersion: localVersion,
            latestVersion: localVersion,
            currentCommit: localCommit.slice(0, 7),
            latestCommit: localCommit.slice(0, 7),
            behind: 0,
            updateAvailable: false,
            branch: git.branch,
            changelog: [],
          });
        }
      }

      const behind = parseInt(
        execSync(`git rev-list --count HEAD..origin/${remoteBranch}`, { cwd: process.cwd() }).toString().trim(),
        10,
      );

      let remoteVersion = localVersion;
      if (behind > 0) {
        try {
          const remotePkg = execSync(`git show origin/${remoteBranch}:package.json`, { cwd: process.cwd() }).toString();
          remoteVersion = JSON.parse(remotePkg).version || localVersion;
        } catch { /* keep local */ }
      }

      const changelog: string[] = [];
      if (behind > 0) {
        const log = execSync(
          `git log --oneline HEAD..origin/${remoteBranch}`,
          { cwd: process.cwd() },
        ).toString().trim();
        if (log) changelog.push(...log.split('\n'));
      }

      res.json({
        currentVersion: localVersion,
        latestVersion: remoteVersion,
        currentCommit: localCommit.slice(0, 7),
        latestCommit: remoteCommit.slice(0, 7),
        behind,
        updateAvailable: behind > 0,
        branch: git.branch,
        changelog,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/upgrade/apply', async (_req, res) => {
    try {
      const git = getGitInfo();

      // Pull latest changes
      const pullOutput = execSync(`git pull origin ${git.branch}`, {
        cwd: process.cwd(),
        timeout: 60_000,
      }).toString().trim();

      // Install any new/changed dependencies
      const installOutput = execSync('npm install --production=false', {
        cwd: process.cwd(),
        timeout: 120_000,
      }).toString().trim();

      const newVersion = getLocalVersion();
      const newGit = getGitInfo();

      // Respond with success before restarting
      res.json({
        success: true,
        version: newVersion,
        commit: newGit.commit,
        pullOutput,
        installOutput: installOutput.slice(-500),
        restarting: true,
      });

      // Schedule restart after response is sent
      setTimeout(() => {
        console.log('[Upgrade] Restarting process...');
        process.exit(0);
      }, 1500);
    } catch (err: any) {
      res.status(500).json({ error: err.message, success: false });
    }
  });

  // --- Static Files & Vite Middleware ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, allowedHosts: true },
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

  app.listen(PORT, BIND_HOST, async () => {
    console.log(`LevarG Server running on http://${BIND_HOST}:${PORT}`);
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

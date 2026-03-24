import axios from 'axios';
import axiosRetry from 'axios-retry';
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import * as cheerio from 'cheerio';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { GoogleGenAI, HarmCategory, HarmBlockThreshold } from '@google/genai';
import { PayloadOven } from './payload_oven.js';
import { ToolManager } from './tool_manager.js';
import { MemoryManager } from './memory_manager.js';

// Configure stealth
puppeteer.use(StealthPlugin());

// Configure axios retry
axiosRetry(axios, { retries: 3, retryDelay: axiosRetry.exponentialDelay });

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export class AutomationEngine {
  private static wildcardBodies: Map<string, string> = new Map();

  private static wildcardTitles: Map<string, string> = new Map();

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

  private static async auditAuthenticationFlow(jobId: string, asset: string, tech: string[], ai: GoogleGenAI | null) {
    const hostname = new URL(asset).hostname;
    const memory = MemoryManager.getMemory(jobId, hostname);
    
    // Generic Auth Flow Audit: Triggered by any SSO/Auth signatures
    const authKeywords = ['auth', 'login', 'sso', 'saml', 'oauth', 'cognito', 'okta', 'auth0', 'firebase'];
    if (tech.some(t => authKeywords.some(kw => t.toLowerCase().includes(kw)))) {
      this.log(jobId, 'info', `Launching Autonomous Authentication Flow Auditor for ${asset}`);
      
      // 1. Generic OAuth/SSO State CSRF Check
      try {
        const res = await axios.get(asset, { maxRedirects: 5, validateStatus: () => true });
        const currentUrl = res.request?._redirectable?._currentUrl || '';
        const state = currentUrl.match(/(?:state|RelayState)=([^&]+)/);
        const clientId = currentUrl.match(/client_id=([^&]+)/);
        
        if (clientId) MemoryManager.addIdentifier(jobId, hostname, 'client_id', clientId[1]);
        
        if (state && ai) {
          const stateParam = currentUrl.includes('RelayState=') ? 'RelayState' : 'state';
          const callbackUrl = currentUrl.split('?')[0];
          const testUrl = `${callbackUrl}?code=test_code&${stateParam}=attack_state`;
          const csrfRes = await axios.get(testUrl, { validateStatus: () => true });
          
          const analysisPrompt = `As an autonomous security agent (argila), analyze this Authentication Flow interaction.
          Target URL: ${testUrl}
          Original Redirect URL: ${currentUrl}
          Response Status: ${csrfRes.status}
          Response Body (truncated): ${typeof csrfRes.data === 'string' ? csrfRes.data.substring(0, 1000) : JSON.stringify(csrfRes.data).substring(0, 1000)}
          
          Memory of Target Behavior:
          - Tech Stack: ${memory.tech.join(', ')}
          - Identifiers: ${JSON.stringify(memory.identifiers)}
          - Previous Findings: ${JSON.stringify(memory.findings)}
          
          Determine if the application is vulnerable to OAuth/SSO State CSRF (Pre-Auth Account Takeover).
          Chaining Logic: Can this finding be combined with previous identifiers or users to escalate impact?
          Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

          const analysisRes = await ai.models.generateContent({
            model: 'gemini-3.1-pro-preview',
            contents: analysisPrompt,
            config: { responseMimeType: 'application/json' }
          });

          if (analysisRes.text) {
            const analysis = JSON.parse(analysisRes.text);
            this.log(jobId, 'info', `Auth Flow Analysis for ${asset}: ${analysis.isVulnerable ? 'VULNERABLE' : 'NOT VULNERABLE'} (${analysis.confidence})`, { explanation: analysis.explanation });
            if (analysis.isVulnerable && analysis.confidence > 0.8) {
              this.log(jobId, 'vuln', `CONFIRMED AUTH CSRF: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
              MemoryManager.addFinding(jobId, hostname, { type: 'Auth CSRF', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
            }
          }
        }
      } catch (e) {}

      // 2. Generic User Enumeration via Auth Endpoints
      const knownUser = memory.discoveredUsers[0] || 'admin';
      const randomUser = `user-${Math.random().toString(36).substring(7)}@example.com`;
      
      const enumEndpoints = [
        { url: '/forgot-password', method: 'POST', body: { email: knownUser }, altBody: { email: randomUser } },
        { url: '/api/auth/reset', method: 'POST', body: { username: knownUser }, altBody: { username: randomUser } }
      ];
      for (const endpoint of enumEndpoints) {
        try {
          const res1 = await axios({
            method: endpoint.method,
            url: `${asset}${endpoint.url}`,
            data: endpoint.body,
            validateStatus: () => true
          });
          
          const res2 = await axios({
            method: endpoint.method,
            url: `${asset}${endpoint.url}`,
            data: endpoint.altBody,
            validateStatus: () => true
          });
          
          // Only analyze if there's a difference between the two responses
          const isStatusDiff = res1.status !== res2.status;
          const isBodyDiff = JSON.stringify(res1.data) !== JSON.stringify(res2.data);

          if ((isStatusDiff || isBodyDiff) && ai) {
            const analysisPrompt = `Analyze these authentication responses for User Enumeration.
            Endpoint: ${endpoint.url}
            Method: ${endpoint.method}
            
            Response 1 (User: ${JSON.stringify(endpoint.body)}):
            Status: ${res1.status}
            Body: ${typeof res1.data === 'string' ? res1.data.substring(0, 1000) : JSON.stringify(res1.data).substring(0, 1000)}
            
            Response 2 (User: ${JSON.stringify(endpoint.altBody)}):
            Status: ${res2.status}
            Body: ${typeof res2.data === 'string' ? res2.data.substring(0, 1000) : JSON.stringify(res2.data).substring(0, 1000)}
            
            Memory of Target Behavior:
            - Tech Stack: ${memory.tech.join(', ')}
            - Identifiers: ${JSON.stringify(memory.identifiers)}
            - Previous Findings: ${JSON.stringify(memory.findings)}
            
            Determine if the difference between these responses reveals the existence of a user account.
            Chaining Logic: Can this finding be combined with previous identifiers or users to escalate impact?
            Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "discovered_user": string | null, "chain_potential": string | null }`;

            const analysisRes = await ai.models.generateContent({
              model: 'gemini-3.1-pro-preview',
              contents: analysisPrompt,
              config: { responseMimeType: 'application/json' }
            });

            if (analysisRes.text) {
              const analysis = JSON.parse(analysisRes.text);
              if (analysis.isVulnerable && analysis.confidence > 0.8) {
                this.log(jobId, 'vuln', `CONFIRMED USER ENUMERATION: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
                MemoryManager.addFinding(jobId, hostname, { type: 'User Enumeration', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
                if (analysis.discovered_user) MemoryManager.addDiscoveredUser(jobId, hostname, analysis.discovered_user);
              }
            }
          }
        } catch (e) {}
      }
    }
  }

  private static async auditBusinessLogic(jobId: string, asset: string, tech: string[], ai: GoogleGenAI | null) {
    const hostname = new URL(asset).hostname;
    const memory = MemoryManager.getMemory(jobId, hostname);
    
    // Generic Business Logic Audit: Triggered by E-commerce or Financial signatures
    const bizKeywords = ['shop', 'store', 'cart', 'checkout', 'price', 'shopify', 'magento', 'stripe'];
    if (tech.some(t => bizKeywords.some(kw => t.toLowerCase().includes(kw)))) {
      this.log(jobId, 'info', `Launching Autonomous Business Logic Auditor for ${asset}`);
      
      // 1. Price/Logic Integrity Check
      const logicEndpoints = ['/products.json', '/api/v1/products', '/cart.js'];
      for (const ep of logicEndpoints) {
        try {
          const res = await axios.get(`${asset}${ep}`, { validateStatus: () => true });
          // Only analyze if it actually returns JSON or product-like data
          const isJson = res.headers['content-type']?.includes('application/json');
          const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
          const hasProductMarkers = bodyStr.includes('price') || bodyStr.includes('variant') || bodyStr.includes('sku');

          if (isJson && hasProductMarkers && ai) {
            const analysisPrompt = `Analyze this e-commerce product data for Business Logic flaws.
            Endpoint: ${ep}
            Response Body (truncated): ${typeof res.data === 'string' ? res.data.substring(0, 2000) : JSON.stringify(res.data).substring(0, 2000)}
            
            Memory of Target Behavior:
            - Tech Stack: ${memory.tech.join(', ')}
            - Previous Findings: ${JSON.stringify(memory.findings)}
            - Identifiers: ${JSON.stringify(memory.identifiers)}
            
            Look for price manipulation, hidden discount codes, or logic bypasses.
            Chaining Logic: Can this finding be combined with previous identifiers or users to escalate impact?
            Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

            const analysisRes = await ai.models.generateContent({
              model: 'gemini-3.1-pro-preview',
              contents: analysisPrompt,
              config: { responseMimeType: 'application/json' }
            });

            if (analysisRes.text) {
              const analysis = JSON.parse(analysisRes.text);
              if (analysis.isVulnerable && analysis.confidence > 0.8) {
                this.log(jobId, 'vuln', `CONFIRMED BUSINESS LOGIC FLAW: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
                MemoryManager.addFinding(jobId, hostname, { type: 'Business Logic Flaw', asset, gap: analysis.gap_identified, chain: analysis.chain_potential });
              }
            }
          }
        } catch (e) {}
      }
    }
  }

  static async startJob(targetUrl: string) {
    const jobId = uuidv4();
    const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
    const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;
    
    // Check Scope
    const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
    const isAllowed = scopes.some(s => targetUrl.includes(s.domain));
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
          const subResult = await ToolManager.execute('subfinder', `-d ${hostname} -silent`, jobId, 
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
          const nmapResult = await ToolManager.execute('nmap', `-F ${hostname}`, jobId,
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
            const httpxResult = await ToolManager.execute('httpx', asset, jobId,
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
          args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled'
          ] 
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
                      
                      const secretRes = await ai.models.generateContent({
                        model: 'gemini-3.1-pro-preview',
                        contents: secretPrompt,
                        config: { responseMimeType: 'application/json' }
                      });
                      
                      if (secretRes.text) {
                        const analysis = JSON.parse(secretRes.text);
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

        // --- PHASE 4: EXPLOITATION & PoC (VULNERABILITY VERIFICATION) ---
        this.updateJob(jobId, 'running', 'Phase 4: Exploitation');
        this.log(jobId, 'info', 'Starting Phase 4: Autonomous AI-Driven Vulnerability Verification');

        // 1. Specialized Auditors (Auth, Business Logic, Sensitive Files)
        for (const stack of techStacks) {
          const tech = stack.results?.tech || [];
          await this.auditAuthenticationFlow(jobId, stack.asset, tech, ai);
          await this.auditBusinessLogic(jobId, stack.asset, tech, ai);
        }

        // 2. Sensitive File Disclosure Auditor (Crucial for high-impact leaks)
        const sensitiveFiles = endpoints.filter(e => 
          e.url.match(/\.(env|git|config|phpinfo|metrics|debug|internal|dashboard|v1|v2|graphql)$/) ||
          e.url.includes('phpinfo') || e.url.includes('.env') || e.url.includes('metrics') || e.url.includes('debug')
        );

        for (const sf of sensitiveFiles) {
          try {
            const hostname = new URL(sf.url).hostname;
            const res = await axios.get(sf.url, { timeout: 5000, validateStatus: () => true });
            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            
            // Filter out wildcard 200s
            if (this.isWildcardResponse(hostname, bodyStr)) continue;

            // Heuristic check for sensitive content
            const hasSensitiveContent = 
              bodyStr.includes('DB_') || bodyStr.includes('AWS_') || bodyStr.includes('SECRET') || 
              bodyStr.includes('PHP Version') || bodyStr.includes('System Info') || 
              bodyStr.includes('metrics_') || bodyStr.includes('debug_mode');

            if (res.status === 200 && hasSensitiveContent && ai) {
              const analysisPrompt = `As an autonomous security agent (argila), verify if this is a SENSITIVE FILE DISCLOSURE.
              URL: ${sf.url}
              Status: ${res.status}
              Body Snippet: ${bodyStr.substring(0, 3000)}
              
              Determine if this file contains REAL sensitive information (credentials, internal paths, system config) or if it's a false positive (e.g., a generic landing page or a public documentation page).
              
              Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

              const analysisRes = await ai.models.generateContent({
                model: 'gemini-3.1-pro-preview',
                contents: analysisPrompt,
                config: { responseMimeType: 'application/json' }
              });

              if (analysisRes.text) {
                const analysis = JSON.parse(analysisRes.text);
                if (analysis.isVulnerable && analysis.confidence > 0.8) {
                  this.log(jobId, 'vuln', `CONFIRMED Sensitive File Disclosure: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
                  MemoryManager.addFinding(jobId, hostname, { type: 'Sensitive File Disclosure', endpoint: sf.url, gap: analysis.gap_identified, chain_potential: analysis.chain_potential });
                }
              }
            }
          } catch (e) {}
        }

        // 3. SSRF to Cloud Metadata Auditor (AWS/GCP/Azure)
        const ssrfEndpoints = endpoints.filter(e => e.url.includes('=http') || e.url.includes('url=') || e.url.includes('dest=') || e.url.includes('redirect='));
        for (const se of ssrfEndpoints) {
          const cloudPayloads = [
            'http://169.254.169.254/latest/meta-data/', // AWS
            'http://metadata.google.internal/computeMetadata/v1/', // GCP
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01' // Azure
          ];

          for (const cp of cloudPayloads) {
            try {
              const testUrl = se.url.replace(/(url|dest|redirect|uri|path)=([^&]+)/, `$1=${encodeURIComponent(cp)}`);
              const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true, headers: { 'Metadata-Flavor': 'Google' } });
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

              if (res.status === 200 && (bodyStr.includes('ami-id') || bodyStr.includes('instance-id') || bodyStr.includes('computeMetadata'))) {
                this.log(jobId, 'vuln', `CONFIRMED SSRF to Cloud Metadata: ${se.url}`, { payload: cp });
                MemoryManager.addFinding(jobId, hostname, { type: 'SSRF', endpoint: se.url, gap: 'Cloud Metadata Leak', chain_potential: 'Full AWS/GCP takeover via metadata tokens' });
              }
            } catch (e) {}
          }
        }

        // 4. Generic Vulnerability Fuzzing (SQLi, XSS, etc.)
        const vulnerabilities: any[] = [];
        
        // --- STACK GAP ANALYSIS (Adversary Simulation) ---
        this.log(jobId, 'info', 'Strategy 3: Stack Gap Analysis (WAF/Proxy Smuggling)');
        for (const asset of discoveredAssets.slice(0, 3)) {
          try {
            const gaps = await StackGapAnalyzer.analyze(asset);
            if (gaps.length > 0) {
              this.log(jobId, 'vuln', `STACK GAP IDENTIFIED on ${asset}`, { gaps });
              allFindings.push({ phase: 'Phase 4', type: 'Stack Gap Findings', asset, data: gaps });
            }
          } catch (e) {}
        }

        const highValueEndpoints = endpoints.filter(e => 
          e.url.includes('api') || e.url.includes('admin') || e.url.includes('auth') || e.url.includes('?') || e.url.includes('login')
        ).slice(0, 50); // Increased depth

        for (const ep of highValueEndpoints) {
          // IDOR Detection Logic
          const idMatch = ep.url.match(/\/(\d+)(?:\/|$|\?)/);
          if (idMatch) {
            const originalId = idMatch[1];
            const testIds = [parseInt(originalId) + 1, parseInt(originalId) - 1, 1, 123456];
            for (const testId of testIds) {
              try {
                const testUrl = ep.url.replace(`/${originalId}`, `/${testId}`);
                const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
                const baselineRes = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true }).catch(() => null);
                
                if (res.status === 200 && baselineRes && res.status === baselineRes.status && JSON.stringify(res.data) !== JSON.stringify(baselineRes.data)) {
                  if (ai) {
                    const analysisPrompt = `Analyze these two responses for IDOR (Insecure Direct Object Reference).
                    Original URL: ${ep.url}
                    Test URL: ${testUrl}
                    Response 1 Body: ${JSON.stringify(baselineRes.data).substring(0, 1000)}
                    Response 2 Body: ${JSON.stringify(res.data).substring(0, 1000)}
                    
                    Determine if changing the ID in the URL allowed access to another user's or object's data.
                    Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                    const analysisRes = await ai.models.generateContent({
                      model: 'gemini-3.1-pro-preview',
                      contents: analysisPrompt,
                      config: { responseMimeType: 'application/json' }
                    });

                    if (analysisRes.text) {
                      const analysis = JSON.parse(analysisRes.text);
                      if (analysis.isVulnerable && analysis.confidence > 0.8) {
                        this.log(jobId, 'vuln', `CONFIRMED IDOR: ${analysis.gap_identified}`, { explanation: analysis.explanation });
                        vulnerabilities.push({ endpoint: ep.url, type: 'IDOR', gap: analysis.gap_identified, evidence: analysis.explanation });
                      }
                    }
                  }
                }
              } catch (e) {}
            }
          }

          const vulnTypes = ['SQLi', 'XSS', 'Path Traversal', 'SSRF', 'RCE', 'SSTI'];
          const memory = MemoryManager.getMemory(jobId, hostname);
          
          for (const type of vulnTypes) {
            try {
              const customPayload = await PayloadOven.generateCustomPayload(ai, type, `Endpoint: ${ep.url}, Method: ${ep.method}, Tech: ${memory.tech.join(', ')}, Identifiers: ${JSON.stringify(memory.identifiers)}`);
              
              // Smart parameter replacement
              let testUrl = ep.url;
              if (ep.url.includes('=')) {
                // Replace values of existing parameters
                testUrl = ep.url.replace(/=([^&]+)/g, `=${encodeURIComponent(customPayload)}`);
              } else {
                // Append new parameter
                testUrl = ep.url.includes('?') ? `${ep.url}&test=${encodeURIComponent(customPayload)}` : `${ep.url}?test=${encodeURIComponent(customPayload)}`;
              }
              
              const startTime = Date.now();
              const res = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
              const latency = Date.now() - startTime;
              
              // 1. Initial Baseline Comparison (Heuristic Trigger)
              const baselineRes = await axios.get(ep.url, { timeout: 5000, validateStatus: () => true }).catch(() => null);
              const isStatusDiff = baselineRes && res.status !== baselineRes.status;
              const isLatencySpike = type === 'SQLi' && latency > 3000; // Time-based SQLi trigger
              const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
              const hasErrorMarkers = bodyStr.includes('error') || bodyStr.includes('exception') || bodyStr.includes('syntax');

              // Agentic AI Verification (Only if there's a trigger)
              if (ai && (isStatusDiff || isLatencySpike || hasErrorMarkers)) {
                const analysisPrompt = `As an autonomous security agent (argila), analyze this HTTP interaction to find the exact security gap.
                Target URL: ${testUrl}
                Payload: ${customPayload}
                Vulnerability Type: ${type}
                Response Status: ${res.status}
                Response Latency: ${latency}ms
                Response Body (truncated): ${typeof res.data === 'string' ? res.data.substring(0, 2000) : JSON.stringify(res.data).substring(0, 2000)}
                
                Memory of Target Behavior:
                - Tech Stack: ${memory.tech.join(', ')}
                - Identifiers: ${JSON.stringify(memory.identifiers)}
                - Discovered Users: ${memory.discoveredUsers.join(', ')}
                - Previous Findings: ${JSON.stringify(memory.findings)}
                
                Determine if this is a REAL security vulnerability or just noise/false positive.
                Chaining Logic: Can this finding be combined with previous identifiers or users to escalate impact?
                
                Return JSON: { "isVulnerable": boolean, "confidence": number, "explanation": string, "gap_identified": string, "chain_potential": string | null }`;

                const analysisRes = await ai.models.generateContent({
                  model: 'gemini-3.1-pro-preview',
                  contents: analysisPrompt,
                  config: { responseMimeType: 'application/json' }
                });
                
                if (analysisRes.text) {
                  const analysis = JSON.parse(analysisRes.text);
                  if (analysis.isVulnerable && analysis.confidence > 0.8) {
                    this.log(jobId, 'vuln', `CONFIRMED ${type}: ${analysis.gap_identified}`, { explanation: analysis.explanation, chain: analysis.chain_potential });
                    const finding = { 
                      endpoint: ep.url, 
                      type: type, 
                      payload: customPayload, 
                      gap: analysis.gap_identified,
                      evidence: analysis.explanation,
                      chain: analysis.chain_potential
                    };
                    vulnerabilities.push(finding);
                    MemoryManager.addFinding(jobId, hostname, finding);
                  }
                }
              }
            } catch (e) {}
          }
        }

        if (ai && vulnerabilities.length > 0) {
          const pocPrompt = `Generate a detailed Proof of Concept (PoC) for these confirmed vulnerabilities: ${JSON.stringify(vulnerabilities)}. 
          Target: ${targetUrl}. 
          Include: 1. Description, 2. Steps to Reproduce, 3. Impact, 4. Remediation.
          Format: JSON { "pocs": [ { "title": string, "steps": string[], "impact": string, "remediation": string, "severity": string } ] }`;
          
          try {
            const pocRes = await ai.models.generateContent({
              model: 'gemini-3.1-pro-preview',
              contents: pocPrompt,
              config: { responseMimeType: 'application/json' }
            });
            if (pocRes.text) {
              const pocData = JSON.parse(pocRes.text);
              allFindings.push({ phase: 'Phase 4', type: 'AI PoC Reports', data: pocData.pocs });
            }
          } catch (e) {}
        }

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
      }
    }, 0);

    return jobId;
  }
}

/**
 * BrowserManager — built-in Puppeteer browser for authenticated testing.
 *
 * Goals:
 *   1. Let the tester drive a real Chromium so they can complete login flows
 *      that the headless scanner can't (SSO, captcha, MFA, OAuth consent).
 *   2. Persist profile state (cookies, localStorage, IndexedDB) per scope so
 *      logging in once survives across server restarts.
 *   3. Capture every in-scope request/response into the existing requests /
 *      responses tables so the tester can replay them in Request Lab without
 *      copy-pasting curl.
 *   4. Export the live cookie jar as a Session in SessionVault so other parts
 *      of the app (Request Lab, Flow Runner) can replay authenticated.
 *
 * Hard constraints:
 *   - The browser is bound to exactly one scope at a time. Switching scopes
 *     closes the current browser and opens a fresh profile.
 *   - Capture is gated on the scope: requests to hosts NOT in the active
 *     scope are NEVER persisted. The browser is allowed to navigate to
 *     identity-provider domains (Google, Okta, etc.) so login can complete,
 *     but their traffic is dropped on the floor for capture purposes.
 */

import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import type { Browser, Page, HTTPRequest, HTTPResponse } from 'puppeteer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import db from './db.js';
import { SessionVault, type SessionCookie, type SessionStorage } from './session_vault.js';

puppeteer.use(StealthPlugin());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROFILE_ROOT = path.join(process.env.LEVARG_DATA_DIR || __dirname, '.browser_profiles');

interface ScopeRow {
  id: string;
  domain: string;
}

export interface BrowserStatus {
  running: boolean;
  scopeId: string | null;
  scopeDomain: string | null;
  headless: boolean;
  capturing: boolean;
  capturedRequests: number;
  outOfScopeDropped: number;
  pages: { url: string; title: string }[];
}

export interface LaunchOptions {
  scopeId: string;
  headless?: boolean;
}

interface PendingRequest {
  startTime: number;
  requestId: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

function ensureDir(p: string): void {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function log(level: 'info' | 'warn' | 'error', message: string, data?: unknown): void {
  const ts = new Date().toISOString();
  const payload = data === undefined ? '' : ` ${JSON.stringify(data)}`;
  // eslint-disable-next-line no-console
  console.log(`[${ts}] [Browser] [${level.toUpperCase()}] ${message}${payload}`);
}

export class BrowserManager {
  private static browser: Browser | null = null;
  private static currentScope: ScopeRow | null = null;
  private static headless = false;
  private static capturing = true;
  private static capturedRequests = 0;
  private static outOfScopeDropped = 0;
  private static pendingByPuppeteerId: Map<string, PendingRequest> = new Map();

  static async launch(opts: LaunchOptions): Promise<BrowserStatus> {
    if (this.browser) {
      // Already running. If same scope, just report status. If different,
      // refuse — caller must close first to avoid silently re-binding state.
      if (this.currentScope && this.currentScope.id === opts.scopeId) {
        return this.status();
      }
      throw new Error(
        `Browser already running for scope '${this.currentScope?.domain ?? 'unknown'}'. Close it before switching scopes.`,
      );
    }

    const scope = db
      .prepare('SELECT id, domain FROM scopes WHERE id = ?')
      .get(opts.scopeId) as ScopeRow | undefined;
    if (!scope) throw new Error(`Scope ${opts.scopeId} does not exist`);

    ensureDir(PROFILE_ROOT);
    const userDataDir = path.join(PROFILE_ROOT, scope.id);
    ensureDir(userDataDir);

    this.headless = opts.headless ?? false;

    const launchArgs = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled',
      '--disable-dev-shm-usage',
    ];

    log('info', 'Launching browser', {
      scope: scope.domain,
      headless: this.headless,
      userDataDir,
    });

    const browser = await puppeteer
      .launch({
        headless: this.headless,
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome',
        userDataDir,
        args: launchArgs,
        defaultViewport: null,
      })
      .catch(async (err: Error) => {
        log('warn', `Primary launch failed (${err.message}), falling back to bundled Chromium`);
        return puppeteer.launch({
          headless: this.headless,
          userDataDir,
          args: launchArgs,
          defaultViewport: null,
        });
      });

    this.browser = browser;
    this.currentScope = scope;
    this.capturedRequests = 0;
    this.outOfScopeDropped = 0;
    this.pendingByPuppeteerId.clear();

    browser.on('disconnected', () => {
      log('info', 'Browser disconnected');
      this.browser = null;
      this.currentScope = null;
      this.pendingByPuppeteerId.clear();
    });

    // Attach capture to existing pages and any future ones.
    const pages = await browser.pages();
    for (const p of pages) await this.attachCaptureToPage(p);
    browser.on('targetcreated', async (target) => {
      if (target.type() !== 'page') return;
      const page = await target.page();
      if (page) await this.attachCaptureToPage(page);
    });

    return this.status();
  }

  /**
   * Ensure the built-in browser is running for `scopeId`. If a browser is
   * already running for the same scope, it's reused. If a browser is running
   * for a *different* scope, an error is thrown — switching scopes requires
   * an explicit close() so cookie/storage state from one scope can't bleed
   * into another mid-flow.
   *
   * Used by AuthFlowVault to lazily bring up a headless browser for a flow
   * replay; the `headless` flag defaults to true here (no GUI needed for
   * automated flow replays) but takes effect only on a fresh launch.
   */
  static async ensureRunning(scopeId: string, opts: { headless?: boolean } = {}): Promise<BrowserStatus> {
    if (this.browser && this.currentScope) {
      if (this.currentScope.id !== scopeId) {
        throw new Error(
          `Browser is bound to scope '${this.currentScope.domain}'. Close it before running an auth-flow for a different scope.`,
        );
      }
      return this.status();
    }
    return this.launch({ scopeId, headless: opts.headless ?? true });
  }

  /**
   * Open a fresh tab in the current browser. Capture is automatically
   * attached because the browser-level `targetcreated` listener wired up in
   * launch() catches every new page. Throws if the browser isn't running.
   */
  static async newPage(): Promise<Page> {
    if (!this.browser) throw new Error('Browser is not running');
    const page = await this.browser.newPage();
    return page;
  }

  /**
   * Convenience: the puppeteer Browser instance for callers that need to
   * inspect cookies / pages directly (e.g. AuthFlowVault). Throws if not
   * running so callers don't accidentally check `null`.
   */
  static getBrowserOrThrow(): Browser {
    if (!this.browser) throw new Error('Browser is not running');
    return this.browser;
  }

  /** Read-only accessor for the active scope; null when the browser is down. */
  static getCurrentScope(): ScopeRow | null {
    return this.currentScope;
  }

  static async close(): Promise<void> {
    if (!this.browser) return;
    try {
      await this.browser.close();
    } catch (err) {
      log('warn', `Error closing browser: ${(err as Error).message}`);
    }
    this.browser = null;
    this.currentScope = null;
    this.pendingByPuppeteerId.clear();
  }

  static async status(): Promise<BrowserStatus> {
    const base: BrowserStatus = {
      running: this.browser !== null,
      scopeId: this.currentScope?.id ?? null,
      scopeDomain: this.currentScope?.domain ?? null,
      headless: this.headless,
      capturing: this.capturing,
      capturedRequests: this.capturedRequests,
      outOfScopeDropped: this.outOfScopeDropped,
      pages: [],
    };
    if (!this.browser) return base;
    try {
      const pages = await this.browser.pages();
      base.pages = await Promise.all(
        pages.map(async (p) => ({
          url: p.url(),
          title: await p.title().catch(() => ''),
        })),
      );
    } catch {
      // browser may have just disconnected; return what we have
    }
    return base;
  }

  static setCapturing(enabled: boolean): void {
    this.capturing = enabled;
    log('info', `Capture ${enabled ? 'enabled' : 'paused'}`);
  }

  /**
   * Snapshot the live browser state — cookies + localStorage/sessionStorage
   * for all in-scope pages — into a new SessionVault entry.
   */
  static async saveAsSession(input: { name: string; notes?: string | null }): Promise<{ sessionId: string }> {
    if (!this.browser || !this.currentScope) {
      throw new Error('Browser is not running');
    }
    const scope = this.currentScope;

    // puppeteer's BrowserContext.cookies() returns cookies for all URLs in the
    // browser. Filter to in-scope ones only, so we never bleed an IdP cookie
    // into a Session bound to scope A.
    const allCookies = await this.browser.cookies();
    const scopedCookies: SessionCookie[] = allCookies
      .filter((c) => {
        const d = (c.domain ?? '').replace(/^\./, '');
        return d === scope.domain || d.endsWith(`.${scope.domain}`);
      })
      .map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        expires: c.expires,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: (c.sameSite ?? 'Unspecified') as SessionCookie['sameSite'],
      }));

    // Pull localStorage / sessionStorage from any open in-scope page.
    const storage: SessionStorage = { localStorage: {}, sessionStorage: {} };
    let userAgent: string | null = null;
    const pages = await this.browser.pages();
    for (const page of pages) {
      let host: string;
      try {
        host = new URL(page.url()).hostname;
      } catch {
        continue;
      }
      if (!SessionVault.hostInScope(host, scope.domain)) continue;
      try {
        const local = await page.evaluate(() => {
          const o: Record<string, string> = {};
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k !== null) o[k] = localStorage.getItem(k) ?? '';
          }
          return o;
        });
        Object.assign(storage.localStorage ?? {}, local);
        const session = await page.evaluate(() => {
          const o: Record<string, string> = {};
          for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            if (k !== null) o[k] = sessionStorage.getItem(k) ?? '';
          }
          return o;
        });
        Object.assign(storage.sessionStorage ?? {}, session);
      } catch {
        // ignore — the page might be in mid-navigation
      }
      if (!userAgent) {
        try {
          userAgent = await page.evaluate(() => navigator.userAgent);
        } catch {
          // ignore
        }
      }
    }

    const created = SessionVault.create({
      scopeId: scope.id,
      name: input.name,
      cookies: scopedCookies,
      headers: {},
      storage,
      userAgent,
      notes: input.notes ?? null,
    });

    log('info', 'Saved browser state as session', {
      sessionId: created.id,
      cookies: scopedCookies.length,
    });
    return { sessionId: created.id };
  }

  // --- Internal: per-page capture wiring -------------------------------------

  private static async attachCaptureToPage(page: Page): Promise<void> {
    page.on('request', (req: HTTPRequest) => this.onRequest(req));
    page.on('response', (res: HTTPResponse) => {
      void this.onResponse(res);
    });
    // Intentionally not registering 'requestfailed' — failed requests don't
    // produce a useful response body and would just clutter history.
  }

  private static onRequest(req: HTTPRequest): void {
    if (!this.capturing || !this.currentScope) return;

    let host: string;
    try {
      host = new URL(req.url()).hostname;
    } catch {
      return;
    }

    if (!SessionVault.hostInScope(host, this.currentScope.domain)) {
      this.outOfScopeDropped++;
      return;
    }

    // Skip non-HTTP traffic and obvious noise — data: URIs, blob:, ws/wss
    // upgrades, sub-resources we don't want flooding History.
    const resourceType = req.resourceType();
    if (resourceType === 'image' || resourceType === 'font' || resourceType === 'media') return;

    const requestId = uuidv4();
    const headers = req.headers();
    const body = req.postData();

    this.pendingByPuppeteerId.set(this.requestKey(req), {
      startTime: Date.now(),
      requestId,
      method: req.method(),
      url: req.url(),
      headers,
      body,
    });

    db.prepare(
      'INSERT INTO requests (id, method, url, headers, body) VALUES (?, ?, ?, ?, ?)',
    ).run(requestId, req.method(), req.url(), JSON.stringify(headers), body ?? null);
  }

  private static async onResponse(res: HTTPResponse): Promise<void> {
    if (!this.capturing || !this.currentScope) return;
    const req = res.request();
    const pending = this.pendingByPuppeteerId.get(this.requestKey(req));
    if (!pending) return;
    this.pendingByPuppeteerId.delete(this.requestKey(req));

    let bodyText = '';
    try {
      // Some response types (preflight, redirects without body) error here.
      const buf = await res.buffer();
      bodyText = buf.toString('utf8');
    } catch {
      bodyText = '';
    }

    const responseId = uuidv4();
    db.prepare(
      'INSERT INTO responses (id, request_id, status, headers, body) VALUES (?, ?, ?, ?, ?)',
    ).run(
      responseId,
      pending.requestId,
      res.status(),
      JSON.stringify(res.headers()),
      bodyText.slice(0, 200000), // 200 KB cap to avoid SQLite bloat on big assets
    );
    this.capturedRequests++;
  }

  private static requestKey(req: HTTPRequest): string {
    // puppeteer doesn't expose a stable internal id across versions; the
    // (method,url,resource,redirect-chain-len) tuple is unique enough for
    // pairing within a single page lifetime.
    return `${req.method()}|${req.url()}|${req.resourceType()}|${req.redirectChain().length}`;
  }
}

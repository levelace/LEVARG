/**
 * AuthFlowVault — replayable login macros bound to a scope.
 *
 * Each flow is an ordered list of `AuthFlowStep`s — goto, fill, click, press,
 * waitForSelector, waitForUrl, sleep — that puppeteer plays back inside the
 * scope-bound built-in browser. Once the playback lands on a successful
 * post-login state, the resulting cookies are snapshotted into a new
 * `Session` in `SessionVault` and bound to the same scope.
 *
 * Trust boundary, enforced on every step that touches a URL:
 *   - The *current* page URL is checked against the bound scope before any
 *     `fill` / `click` / `press` step runs. If the auth flow has navigated
 *     to a third-party domain (e.g. `accounts.google.com`, `appleid.apple.com`),
 *     the step is REJECTED — credentials are never typed into a host outside
 *     the scope. The operator can complete provider-side login manually in the
 *     built-in browser; the resulting session is still captured.
 *   - The `goto` step's URL is checked too, so a flow can't be hand-edited to
 *     drive the browser onto an unrelated domain.
 *   - The `${USERNAME}` / `${PASSWORD}` template tokens are resolved from the
 *     bound credential at fill-time only — they're never persisted in the
 *     `steps` JSON.
 */
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';
import type { Page } from 'puppeteer';
import { BrowserManager } from './browser_manager.js';
import { CredentialVault } from './credential_vault.js';
import { SessionVault } from './session_vault.js';

export type TriggerMode = 'preflight' | 'on_401' | 'discovery' | 'all' | 'manual';

export type AuthFlowStep =
  | { type: 'goto'; url: string; waitFor?: 'load' | 'domcontentloaded' | 'networkidle0' | 'networkidle2' }
  | { type: 'fill'; selector: string; value: string; secret?: boolean }
  | { type: 'click'; selector: string }
  | { type: 'press'; key: 'Enter' | 'Tab' | 'Escape' }
  | { type: 'waitForSelector'; selector: string; timeout?: number }
  | { type: 'waitForUrl'; urlContains: string; timeout?: number }
  | { type: 'sleep'; ms: number };

export interface AuthFlowRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  credential_id: string | null;
  name: string;
  steps: AuthFlowStep[];
  trigger_mode: TriggerMode;
  is_default: boolean;
  last_run_at: string | null;
  last_status: 'ok' | 'error' | null;
  last_error: string | null;
  success_count: number;
  fail_count: number;
  created_at: string;
  updated_at: string;
}

interface RawAuthFlowRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  credential_id: string | null;
  name: string;
  steps: string;
  trigger_mode: string;
  is_default: number;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  success_count: number;
  fail_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateAuthFlowInput {
  scopeId: string;
  name: string;
  steps: AuthFlowStep[];
  credentialId?: string | null;
  triggerMode?: TriggerMode;
  isDefault?: boolean;
}

export interface UpdateAuthFlowInput {
  name?: string;
  steps?: AuthFlowStep[];
  credentialId?: string | null;
  triggerMode?: TriggerMode;
  isDefault?: boolean;
}

export interface AuthFlowRunResult {
  ok: boolean;
  flowId: string;
  sessionId: string | null;
  error: string | null;
  log: { ts: string; level: 'info' | 'warn' | 'error'; message: string }[];
}

const TRIGGER_MODES: TriggerMode[] = ['preflight', 'on_401', 'discovery', 'all', 'manual'];

function hydrate(raw: RawAuthFlowRow): AuthFlowRow {
  let steps: AuthFlowStep[] = [];
  try {
    steps = JSON.parse(raw.steps) as AuthFlowStep[];
  } catch {
    steps = [];
  }
  const trigger = (TRIGGER_MODES as string[]).includes(raw.trigger_mode)
    ? (raw.trigger_mode as TriggerMode)
    : 'manual';
  const status = raw.last_status === 'ok' || raw.last_status === 'error' ? raw.last_status : null;
  return {
    id: raw.id,
    scope_id: raw.scope_id,
    scope_domain: raw.scope_domain,
    credential_id: raw.credential_id,
    name: raw.name,
    steps,
    trigger_mode: trigger,
    is_default: !!raw.is_default,
    last_run_at: raw.last_run_at,
    last_status: status,
    last_error: raw.last_error,
    success_count: raw.success_count,
    fail_count: raw.fail_count,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

function validateSteps(steps: unknown): AuthFlowStep[] {
  if (!Array.isArray(steps)) throw new Error('steps must be an array');
  const out: AuthFlowStep[] = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i] as Record<string, unknown> | null;
    if (!s || typeof s !== 'object') throw new Error(`steps[${i}] must be an object`);
    const t = s.type;
    switch (t) {
      case 'goto':
        if (typeof s.url !== 'string' || !s.url) throw new Error(`steps[${i}].url is required`);
        out.push({ type: 'goto', url: s.url, waitFor: (s.waitFor as 'load') ?? 'load' });
        break;
      case 'fill':
        if (typeof s.selector !== 'string' || !s.selector)
          throw new Error(`steps[${i}].selector is required`);
        if (typeof s.value !== 'string') throw new Error(`steps[${i}].value must be a string`);
        out.push({ type: 'fill', selector: s.selector, value: s.value, secret: !!s.secret });
        break;
      case 'click':
        if (typeof s.selector !== 'string' || !s.selector)
          throw new Error(`steps[${i}].selector is required`);
        out.push({ type: 'click', selector: s.selector });
        break;
      case 'press':
        if (s.key !== 'Enter' && s.key !== 'Tab' && s.key !== 'Escape')
          throw new Error(`steps[${i}].key must be Enter|Tab|Escape`);
        out.push({ type: 'press', key: s.key });
        break;
      case 'waitForSelector':
        if (typeof s.selector !== 'string' || !s.selector)
          throw new Error(`steps[${i}].selector is required`);
        out.push({
          type: 'waitForSelector',
          selector: s.selector,
          timeout: typeof s.timeout === 'number' ? s.timeout : 15000,
        });
        break;
      case 'waitForUrl':
        if (typeof s.urlContains !== 'string' || !s.urlContains)
          throw new Error(`steps[${i}].urlContains is required`);
        out.push({
          type: 'waitForUrl',
          urlContains: s.urlContains,
          timeout: typeof s.timeout === 'number' ? s.timeout : 15000,
        });
        break;
      case 'sleep':
        if (typeof s.ms !== 'number' || s.ms < 0) throw new Error(`steps[${i}].ms must be >= 0`);
        out.push({ type: 'sleep', ms: Math.min(s.ms, 30000) });
        break;
      default:
        throw new Error(`steps[${i}].type '${String(t)}' is not a valid step type`);
    }
  }
  return out;
}

interface ScopeRow {
  id: string;
  domain: string;
}

export class AuthFlowVault {
  static list(scopeId?: string): AuthFlowRow[] {
    const sql = scopeId
      ? `SELECT f.*, sc.domain AS scope_domain
           FROM auth_flows f
           LEFT JOIN scopes sc ON sc.id = f.scope_id
          WHERE f.scope_id = ?
          ORDER BY f.updated_at DESC`
      : `SELECT f.*, sc.domain AS scope_domain
           FROM auth_flows f
           LEFT JOIN scopes sc ON sc.id = f.scope_id
          ORDER BY f.updated_at DESC`;
    const rows = (
      scopeId ? db.prepare(sql).all(scopeId) : db.prepare(sql).all()
    ) as RawAuthFlowRow[];
    return rows.map(hydrate);
  }

  static get(id: string): AuthFlowRow | null {
    const row = db
      .prepare(
        `SELECT f.*, sc.domain AS scope_domain
           FROM auth_flows f
           LEFT JOIN scopes sc ON sc.id = f.scope_id
          WHERE f.id = ?`,
      )
      .get(id) as RawAuthFlowRow | undefined;
    return row ? hydrate(row) : null;
  }

  static getDefaultForScope(scopeId: string): AuthFlowRow | null {
    const row = db
      .prepare(
        `SELECT f.*, sc.domain AS scope_domain
           FROM auth_flows f
           LEFT JOIN scopes sc ON sc.id = f.scope_id
          WHERE f.scope_id = ? AND f.is_default = 1
          LIMIT 1`,
      )
      .get(scopeId) as RawAuthFlowRow | undefined;
    return row ? hydrate(row) : null;
  }

  static create(input: CreateAuthFlowInput): AuthFlowRow {
    if (!input.name || !input.name.trim()) throw new Error('Auth flow name is required');
    const scope = db
      .prepare('SELECT id, domain FROM scopes WHERE id = ?')
      .get(input.scopeId) as ScopeRow | undefined;
    if (!scope) throw new Error(`Scope ${input.scopeId} does not exist`);

    if (input.credentialId) {
      const cred = CredentialVault.get(input.credentialId);
      if (!cred) throw new Error(`Credential ${input.credentialId} does not exist`);
      if (cred.scope_id !== input.scopeId) {
        throw new Error('Credential is bound to a different scope and cannot be linked here');
      }
    }

    const steps = validateSteps(input.steps);
    const triggerMode: TriggerMode = input.triggerMode ?? 'preflight';
    if (!TRIGGER_MODES.includes(triggerMode)) {
      throw new Error(`triggerMode must be one of ${TRIGGER_MODES.join(', ')}`);
    }
    const isDefault = !!input.isDefault;

    const id = uuidv4();
    const tx = db.transaction(() => {
      if (isDefault) {
        db.prepare('UPDATE auth_flows SET is_default = 0 WHERE scope_id = ?').run(input.scopeId);
      }
      db.prepare(
        `INSERT INTO auth_flows
           (id, scope_id, credential_id, name, steps, trigger_mode, is_default)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id,
        input.scopeId,
        input.credentialId ?? null,
        input.name.trim(),
        JSON.stringify(steps),
        triggerMode,
        isDefault ? 1 : 0,
      );
    });
    tx();
    const created = this.get(id);
    if (!created) throw new Error('Auth flow creation failed');
    return created;
  }

  static update(id: string, patch: UpdateAuthFlowInput): AuthFlowRow {
    const existing = this.get(id);
    if (!existing) throw new Error(`Auth flow ${id} not found`);

    if (patch.name !== undefined && (!patch.name || !patch.name.trim())) {
      throw new Error('Auth flow name is required');
    }

    let nextSteps: AuthFlowStep[] | undefined;
    if (patch.steps !== undefined) nextSteps = validateSteps(patch.steps);

    let nextTrigger: TriggerMode | undefined;
    if (patch.triggerMode !== undefined) {
      if (!TRIGGER_MODES.includes(patch.triggerMode)) {
        throw new Error(`triggerMode must be one of ${TRIGGER_MODES.join(', ')}`);
      }
      nextTrigger = patch.triggerMode;
    }

    if (patch.credentialId !== undefined && patch.credentialId !== null) {
      const cred = CredentialVault.get(patch.credentialId);
      if (!cred) throw new Error(`Credential ${patch.credentialId} does not exist`);
      if (cred.scope_id !== existing.scope_id) {
        throw new Error('Credential is bound to a different scope and cannot be linked here');
      }
    }

    const tx = db.transaction(() => {
      if (patch.isDefault) {
        db.prepare('UPDATE auth_flows SET is_default = 0 WHERE scope_id = ? AND id != ?').run(
          existing.scope_id,
          id,
        );
      }
      db.prepare(
        `UPDATE auth_flows
            SET name = COALESCE(?, name),
                steps = COALESCE(?, steps),
                credential_id = CASE WHEN ? = 1 THEN ? ELSE credential_id END,
                trigger_mode = COALESCE(?, trigger_mode),
                is_default = COALESCE(?, is_default),
                updated_at = CURRENT_TIMESTAMP
          WHERE id = ?`,
      ).run(
        patch.name?.trim() ?? null,
        nextSteps ? JSON.stringify(nextSteps) : null,
        patch.credentialId !== undefined ? 1 : 0,
        patch.credentialId ?? null,
        nextTrigger ?? null,
        patch.isDefault === undefined ? null : patch.isDefault ? 1 : 0,
        id,
      );
    });
    tx();

    const after = this.get(id);
    if (!after) throw new Error('Auth flow update failed');
    return after;
  }

  static delete(id: string): boolean {
    const result = db.prepare('DELETE FROM auth_flows WHERE id = ?').run(id);
    return result.changes > 0;
  }

  static recordRun(id: string, ok: boolean, error: string | null): void {
    if (ok) {
      db.prepare(
        `UPDATE auth_flows
            SET last_run_at = CURRENT_TIMESTAMP,
                last_status = 'ok',
                last_error = NULL,
                success_count = success_count + 1
          WHERE id = ?`,
      ).run(id);
    } else {
      db.prepare(
        `UPDATE auth_flows
            SET last_run_at = CURRENT_TIMESTAMP,
                last_status = 'error',
                last_error = ?,
                fail_count = fail_count + 1
          WHERE id = ?`,
      ).run(error?.slice(0, 2000) ?? 'Unknown error', id);
    }
  }

  // --- Replay engine -------------------------------------------------------

  /**
   * Replay an auth flow against the bound scope. Lazily brings up the
   * built-in browser if it isn't already running. On success, captures the
   * resulting cookies into a new `Session` named after the flow and returns
   * its id. On failure, leaves the browser running so the operator can
   * inspect what went wrong (e.g. a captcha challenge that requires manual
   * intervention).
   */
  static async run(
    flowId: string,
    opts: { sessionLabel?: string } = {},
  ): Promise<AuthFlowRunResult> {
    const log: AuthFlowRunResult['log'] = [];
    const tlog = (level: 'info' | 'warn' | 'error', message: string) =>
      log.push({ ts: new Date().toISOString(), level, message });

    const flow = this.get(flowId);
    if (!flow) {
      return { ok: false, flowId, sessionId: null, error: `Auth flow ${flowId} not found`, log };
    }
    if (!flow.scope_domain) {
      return {
        ok: false,
        flowId,
        sessionId: null,
        error: `Auth flow ${flowId} has no resolvable scope`,
        log,
      };
    }

    let credentialUsername: string | null = null;
    let credentialPassword: string | null = null;
    if (flow.credential_id) {
      const cred = CredentialVault.get(flow.credential_id);
      if (!cred) {
        const err = `Linked credential ${flow.credential_id} no longer exists`;
        tlog('error', err);
        this.recordRun(flowId, false, err);
        return { ok: false, flowId, sessionId: null, error: err, log };
      }
      if (cred.scope_id !== flow.scope_id) {
        const err = 'Linked credential is bound to a different scope; refusing to run';
        tlog('error', err);
        this.recordRun(flowId, false, err);
        return { ok: false, flowId, sessionId: null, error: err, log };
      }
      credentialUsername = cred.username;
      credentialPassword = cred.password;
    }

    try {
      tlog('info', `Ensuring browser is running for scope '${flow.scope_domain}'`);
      await BrowserManager.ensureRunning(flow.scope_id, { headless: true });
    } catch (err) {
      const msg = (err as Error).message;
      tlog('error', `Browser launch failed: ${msg}`);
      this.recordRun(flowId, false, msg);
      return { ok: false, flowId, sessionId: null, error: msg, log };
    }

    let page: Page;
    try {
      page = await BrowserManager.newPage();
    } catch (err) {
      const msg = (err as Error).message;
      tlog('error', `newPage failed: ${msg}`);
      this.recordRun(flowId, false, msg);
      return { ok: false, flowId, sessionId: null, error: msg, log };
    }

    const scopeDomain = flow.scope_domain;

    const assertCurrentInScope = (verb: string): void => {
      const url = page.url();
      if (!url || url === 'about:blank') return;
      let host: string;
      try {
        host = new URL(url).hostname;
      } catch {
        throw new Error(`Cannot ${verb}: page URL '${url}' is invalid`);
      }
      if (!SessionVault.hostInScope(host, scopeDomain)) {
        throw new Error(
          `Refusing to ${verb} on out-of-scope host '${host}' (bound scope '${scopeDomain}'). ` +
            `Provider OAuth pages must be completed manually in the built-in browser.`,
        );
      }
    };

    const expandTemplate = (raw: string): string =>
      raw
        .replaceAll('${USERNAME}', credentialUsername ?? '')
        .replaceAll('${PASSWORD}', credentialPassword ?? '');

    try {
      for (let i = 0; i < flow.steps.length; i++) {
        const step = flow.steps[i];
        switch (step.type) {
          case 'goto': {
            let host: string;
            try {
              host = new URL(step.url).hostname;
            } catch {
              throw new Error(`steps[${i}].url '${step.url}' is not a valid URL`);
            }
            if (!SessionVault.hostInScope(host, scopeDomain)) {
              throw new Error(
                `Refusing to navigate to out-of-scope host '${host}' (bound scope '${scopeDomain}')`,
              );
            }
            tlog('info', `goto ${step.url}`);
            await page.goto(step.url, { waitUntil: step.waitFor ?? 'load', timeout: 30000 });
            break;
          }
          case 'fill': {
            assertCurrentInScope('fill credentials');
            const value = expandTemplate(step.value);
            const display = step.secret || /\$\{PASSWORD\}/.test(step.value) ? '<redacted>' : value;
            tlog('info', `fill ${step.selector} = ${display}`);
            await page.waitForSelector(step.selector, { timeout: 15000 });
            await page.click(step.selector, { clickCount: 3 }).catch(() => undefined);
            await page.type(step.selector, value, { delay: 30 });
            break;
          }
          case 'click': {
            assertCurrentInScope('click');
            tlog('info', `click ${step.selector}`);
            await page.waitForSelector(step.selector, { timeout: 15000 });
            await page.click(step.selector);
            break;
          }
          case 'press': {
            assertCurrentInScope('press key');
            tlog('info', `press ${step.key}`);
            await page.keyboard.press(step.key);
            break;
          }
          case 'waitForSelector': {
            tlog('info', `waitForSelector ${step.selector}`);
            await page.waitForSelector(step.selector, { timeout: step.timeout ?? 15000 });
            break;
          }
          case 'waitForUrl': {
            tlog('info', `waitForUrl contains '${step.urlContains}'`);
            const deadline = Date.now() + (step.timeout ?? 15000);
            // Polling beats waitForFunction for cross-origin pages where
            // page.evaluate() throws on isolated contexts.
            while (Date.now() < deadline) {
              if (page.url().includes(step.urlContains)) break;
              await new Promise((r) => setTimeout(r, 200));
            }
            if (!page.url().includes(step.urlContains)) {
              throw new Error(
                `Timed out waiting for URL containing '${step.urlContains}' (current: ${page.url()})`,
              );
            }
            break;
          }
          case 'sleep': {
            tlog('info', `sleep ${step.ms}ms`);
            await new Promise((r) => setTimeout(r, step.ms));
            break;
          }
        }
      }

      // After the last step, snapshot the in-scope cookie jar into a Session.
      const sessionLabel =
        opts.sessionLabel ??
        `auth-flow:${flow.name}@${new Date().toISOString().replace(/[:.]/g, '-')}`;
      tlog('info', `Capturing session as '${sessionLabel}'`);
      const { sessionId } = await BrowserManager.saveAsSession({
        name: sessionLabel,
        notes: `Captured by auth-flow '${flow.name}' (${flow.id})`,
      });
      tlog('info', `Session ${sessionId} captured`);
      this.recordRun(flowId, true, null);
      // Close just the page used for replay; leave the browser up for reuse.
      await page.close().catch(() => undefined);
      return { ok: true, flowId, sessionId, error: null, log };
    } catch (err) {
      const msg = (err as Error).message ?? String(err);
      tlog('error', msg);
      this.recordRun(flowId, false, msg);
      // Leave the page open: the operator can inspect what went wrong (most
      // common cause: a captcha or device-trust challenge that needs manual
      // attention before the flow can succeed).
      return { ok: false, flowId, sessionId: null, error: msg, log };
    }
  }
}

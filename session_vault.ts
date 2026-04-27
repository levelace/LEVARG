/**
 * SessionVault — named cookie/header bundles bound to a scope, used to inject
 * authenticated state into Request Lab and Flow Runner.
 *
 * A Session is the persistence model for "I logged in as user X in the built-in
 * browser, save that auth material so my replays / fuzzing / flows can reuse
 * it". Each Session belongs to exactly one Scope; a Session for scope A is
 * refused against any host that isn't in scope A. This is the second layer of
 * scope enforcement on top of the existing /api/scopes domain allowlist.
 */
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';

export interface SessionCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None' | 'Unspecified';
}

export interface SessionStorage {
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
}

export interface SessionRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  name: string;
  cookies: SessionCookie[];
  headers: Record<string, string>;
  storage: SessionStorage;
  user_agent: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface RawSessionRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  name: string;
  cookies: string | null;
  headers: string | null;
  storage: string | null;
  user_agent: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface ScopeRow {
  id: string;
  domain: string;
}

export interface CreateSessionInput {
  scopeId: string;
  name: string;
  cookies?: SessionCookie[];
  headers?: Record<string, string>;
  storage?: SessionStorage;
  userAgent?: string | null;
  notes?: string | null;
}

export interface UpdateSessionInput {
  name?: string;
  cookies?: SessionCookie[];
  headers?: Record<string, string>;
  storage?: SessionStorage;
  userAgent?: string | null;
  notes?: string | null;
}

/**
 * Thrown when a Session can't be applied to a target URL. The HTTP `status`
 * (403 or 404) is meant to be propagated directly onto the API response.
 */
export class SessionScopeError extends Error {
  status: 403 | 404;
  constructor(message: string, status: 403 | 404) {
    super(message);
    this.name = 'SessionScopeError';
    this.status = status;
  }
}

function safeParseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function hydrate(raw: RawSessionRow): SessionRow {
  return {
    id: raw.id,
    scope_domain: raw.scope_domain ?? null,
    scope_id: raw.scope_id,
    name: raw.name,
    cookies: safeParseJson<SessionCookie[]>(raw.cookies, []),
    headers: safeParseJson<Record<string, string>>(raw.headers, {}),
    storage: safeParseJson<SessionStorage>(raw.storage, {}),
    user_agent: raw.user_agent,
    notes: raw.notes,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

export class SessionVault {
  /** Look up a scope by ID. Returns null if not found. */
  static getScope(scopeId: string): ScopeRow | null {
    const row = db.prepare('SELECT id, domain FROM scopes WHERE id = ?').get(scopeId) as
      | ScopeRow
      | undefined;
    return row ?? null;
  }

  /**
   * True iff `targetHost` is the scope domain or any subdomain of it.
   * Same matching rule as the existing /api/scopes gate.
   */
  static hostInScope(targetHost: string, scopeDomain: string): boolean {
    return targetHost === scopeDomain || targetHost.endsWith(`.${scopeDomain}`);
  }

  static list(scopeId?: string): SessionRow[] {
    const rows = scopeId
      ? (db
          .prepare(
            `SELECT s.*, sc.domain AS scope_domain FROM sessions s
               LEFT JOIN scopes sc ON sc.id = s.scope_id
               WHERE s.scope_id = ? ORDER BY s.updated_at DESC`,
          )
          .all(scopeId) as RawSessionRow[])
      : (db
          .prepare(
            `SELECT s.*, sc.domain AS scope_domain FROM sessions s
               LEFT JOIN scopes sc ON sc.id = s.scope_id
               ORDER BY s.updated_at DESC`,
          )
          .all() as RawSessionRow[]);
    return rows.map(hydrate);
  }

  static get(id: string): SessionRow | null {
    const row = db
      .prepare(
        `SELECT s.*, sc.domain AS scope_domain FROM sessions s
           LEFT JOIN scopes sc ON sc.id = s.scope_id
           WHERE s.id = ?`,
      )
      .get(id) as RawSessionRow | undefined;
    return row ? hydrate(row) : null;
  }

  static create(input: CreateSessionInput): SessionRow {
    const scope = this.getScope(input.scopeId);
    if (!scope) throw new Error(`Scope ${input.scopeId} does not exist`);
    if (!input.name || !input.name.trim()) throw new Error('Session name is required');

    const id = uuidv4();
    db.prepare(
      `INSERT INTO sessions (id, scope_id, name, cookies, headers, storage, user_agent, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.scopeId,
      input.name.trim(),
      JSON.stringify(input.cookies ?? []),
      JSON.stringify(input.headers ?? {}),
      JSON.stringify(input.storage ?? {}),
      input.userAgent ?? null,
      input.notes ?? null,
    );
    const created = this.get(id);
    if (!created) throw new Error('Session creation failed');
    return created;
  }

  static update(id: string, patch: UpdateSessionInput): SessionRow {
    const existing = this.get(id);
    if (!existing) throw new Error(`Session ${id} not found`);

    // Match the validation in create(): an explicit empty / whitespace-only
    // / null name is a 400, not a silent overwrite. `??` alone wouldn't catch
    // these because "" is a defined non-nullish value, and a JSON `null` from
    // the client survives destructuring as a real `null`.
    if (patch.name !== undefined && (!patch.name || !patch.name.trim())) {
      throw new Error('Session name is required');
    }

    const next: SessionRow = {
      ...existing,
      name: patch.name?.trim() ?? existing.name,
      cookies: patch.cookies ?? existing.cookies,
      headers: patch.headers ?? existing.headers,
      storage: patch.storage ?? existing.storage,
      user_agent: patch.userAgent !== undefined ? patch.userAgent : existing.user_agent,
      notes: patch.notes !== undefined ? patch.notes : existing.notes,
      updated_at: new Date().toISOString(),
    };

    db.prepare(
      `UPDATE sessions SET
         name = ?, cookies = ?, headers = ?, storage = ?,
         user_agent = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
    ).run(
      next.name,
      JSON.stringify(next.cookies),
      JSON.stringify(next.headers),
      JSON.stringify(next.storage),
      next.user_agent,
      next.notes,
      id,
    );

    const after = this.get(id);
    if (!after) throw new Error('Session update failed');
    return after;
  }

  static delete(id: string): boolean {
    const result = db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    return result.changes > 0;
  }

  /**
   * Build the headers to send for a request inside `targetUrl` using the
   * given session. Throws SessionScopeError if the session can't be applied
   * (missing session, missing scope, or out-of-scope target). The caller
   * should map the thrown `.status` directly onto the HTTP response.
   *
   * User-supplied headers always win over session headers and cookies —
   * this lets a tester explicitly override auth in a single request without
   * editing the session.
   *
   * Cookie matching is intentionally permissive: a cookie is included
   * if it has no domain set OR if its domain matches the target host.
   */
  static buildRequestOverlay(
    sessionId: string,
    targetUrl: string,
  ): {
    headers: Record<string, string>;
    cookieHeader: string;
    userAgent: string | null;
    scope: ScopeRow;
  } {
    const session = this.get(sessionId);
    if (!session) {
      throw new SessionScopeError(`Session ${sessionId} not found`, 404);
    }
    const scope = this.getScope(session.scope_id);
    if (!scope) {
      throw new SessionScopeError(
        `Session ${sessionId} references missing scope`,
        404,
      );
    }

    let targetHost: string;
    try {
      targetHost = new URL(targetUrl).hostname;
    } catch {
      throw new SessionScopeError('Invalid target URL', 403);
    }

    if (!this.hostInScope(targetHost, scope.domain)) {
      throw new SessionScopeError(
        `Session is bound to scope '${scope.domain}' and cannot be used against '${targetHost}'`,
        403,
      );
    }

    const matchingCookies = session.cookies.filter((c) => {
      if (!c.domain) return true;
      const d = c.domain.startsWith('.') ? c.domain.slice(1) : c.domain;
      return targetHost === d || targetHost.endsWith(`.${d}`);
    });
    const cookieHeader = matchingCookies
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');

    return {
      headers: { ...session.headers },
      cookieHeader,
      userAgent: session.user_agent,
      scope,
    };
  }

  /**
   * One-shot helper: returns the headers to send for a request to `targetUrl`
   * with `sessionId` applied. Returns `baseHeaders` unchanged when
   * `sessionId` is empty/null. Throws `SessionScopeError` if the session
   * exists but can't legally be used against the target.
   *
   * Use this everywhere outbound requests are made (lab proxy, flow runner,
   * scanner, stack-gap analyzer, auto-hunter) so all of them pick up the
   * authed session uniformly.
   */
  static applyToHeaders(
    sessionId: string | null | undefined,
    targetUrl: string,
    baseHeaders?: Record<string, string>,
  ): Record<string, string> {
    if (!sessionId) return { ...(baseHeaders ?? {}) };
    const overlay = this.buildRequestOverlay(sessionId, targetUrl);
    return this.mergeHeaders(baseHeaders, {
      headers: overlay.headers,
      cookieHeader: overlay.cookieHeader,
      userAgent: overlay.userAgent,
    });
  }

  /**
   * Apply a session overlay to an existing axios-style header object.
   * User-supplied headers (`baseHeaders`) take precedence over session
   * headers; the only exception is that we add the session's Cookie header
   * if and only if the user did not already provide one.
   */
  static mergeHeaders(
    baseHeaders: Record<string, string> | undefined,
    overlay: { headers: Record<string, string>; cookieHeader: string; userAgent: string | null },
  ): Record<string, string> {
    const out: Record<string, string> = { ...overlay.headers, ...(baseHeaders ?? {}) };
    const userHasCookie = Object.keys(out).some((k) => k.toLowerCase() === 'cookie');
    if (overlay.cookieHeader && !userHasCookie) {
      out['Cookie'] = overlay.cookieHeader;
    }
    if (overlay.userAgent) {
      const userHasUa = Object.keys(out).some((k) => k.toLowerCase() === 'user-agent');
      if (!userHasUa) out['User-Agent'] = overlay.userAgent;
    }
    return out;
  }
}

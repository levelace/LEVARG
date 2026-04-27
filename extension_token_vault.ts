/**
 * ExtensionTokenVault — pairing tokens for the OS-browser bridge.
 *
 * The bridge has three concrete transports, all gated by the same token:
 *
 *   1. **Browser extension** — operator installs the LEVARG extension, pastes
 *      the token in the options page; the extension reads cookies via
 *      `chrome.cookies.getAll()` (which can read HttpOnly cookies, unlike
 *      page-level JS) and POSTs them to /api/extension/cookies.
 *   2. **Bookmarklet** — a `javascript:` URL fetched from
 *      /api/extension/bookmarklet?token=... that captures `document.cookie` +
 *      `localStorage` and POSTs them to /api/extension/cookies. Mobile-
 *      friendly fallback; HttpOnly cookies are *not* captured (browser limit).
 *   3. **Manual paste** — operator opens DevTools → Application → Cookies,
 *      copies as JSON, pastes into the LEVARG UI which calls the same
 *      ingest endpoint with the token.
 *
 * Tokens are scope-bound. A token issued for scope A can only create
 * sessions inside scope A; cookies for hosts outside the bound scope are
 * silently dropped at ingest time. This is the same defensive boundary
 * SessionVault enforces for replays.
 */
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

export interface ExtensionTokenRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  token: string;
  label: string | null;
  last_used_at: string | null;
  use_count: number;
  created_at: string;
}

interface RawTokenRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  token: string;
  label: string | null;
  last_used_at: string | null;
  use_count: number;
  created_at: string;
}

export class ExtensionTokenVault {
  static list(scopeId?: string): ExtensionTokenRow[] {
    const sql = scopeId
      ? `SELECT t.*, sc.domain AS scope_domain
           FROM extension_tokens t
           LEFT JOIN scopes sc ON sc.id = t.scope_id
          WHERE t.scope_id = ?
          ORDER BY t.created_at DESC`
      : `SELECT t.*, sc.domain AS scope_domain
           FROM extension_tokens t
           LEFT JOIN scopes sc ON sc.id = t.scope_id
          ORDER BY t.created_at DESC`;
    const rows = (
      scopeId ? db.prepare(sql).all(scopeId) : db.prepare(sql).all()
    ) as RawTokenRow[];
    return rows;
  }

  static getByToken(token: string): ExtensionTokenRow | null {
    const row = db
      .prepare(
        `SELECT t.*, sc.domain AS scope_domain
           FROM extension_tokens t
           LEFT JOIN scopes sc ON sc.id = t.scope_id
          WHERE t.token = ?`,
      )
      .get(token) as RawTokenRow | undefined;
    return row ?? null;
  }

  static create(input: { scopeId: string; label?: string | null }): ExtensionTokenRow {
    const scope = db.prepare('SELECT id FROM scopes WHERE id = ?').get(input.scopeId) as
      | { id: string }
      | undefined;
    if (!scope) throw new Error(`Scope ${input.scopeId} does not exist`);

    const id = uuidv4();
    // 32-byte URL-safe token; long enough that brute-force isn't a real
    // concern even without rate-limiting the ingest endpoint.
    const token = crypto.randomBytes(32).toString('base64url');
    db.prepare(
      `INSERT INTO extension_tokens (id, scope_id, token, label) VALUES (?, ?, ?, ?)`,
    ).run(id, input.scopeId, token, input.label ?? null);
    const created = db
      .prepare(
        `SELECT t.*, sc.domain AS scope_domain
           FROM extension_tokens t
           LEFT JOIN scopes sc ON sc.id = t.scope_id
          WHERE t.id = ?`,
      )
      .get(id) as RawTokenRow | undefined;
    if (!created) throw new Error('Token creation failed');
    return created;
  }

  static delete(id: string): boolean {
    const result = db.prepare('DELETE FROM extension_tokens WHERE id = ?').run(id);
    return result.changes > 0;
  }

  static recordUse(token: string): void {
    db.prepare(
      `UPDATE extension_tokens
          SET last_used_at = CURRENT_TIMESTAMP,
              use_count = use_count + 1
        WHERE token = ?`,
    ).run(token);
  }
}

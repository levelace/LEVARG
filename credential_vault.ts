/**
 * CredentialVault — stored login credentials bound to a scope.
 *
 * Operators register a username/password (or any single-shot credential pair)
 * for a scope; auth-flow macros read those values when they replay a login.
 * The "label" is the human-readable name (e.g. "admin", "tester-A") so a scope
 * can have multiple identities for role-based testing.
 *
 * Scope binding is enforced 1:1: a credential created for scope A is rejected
 * by any auth-flow / hunt bound to scope B. This sits next to SessionVault's
 * scope check and is the operator-input side of the same trust boundary —
 * SessionVault holds the result of a login (cookies); CredentialVault holds
 * the input (username/password) used to acquire that session.
 *
 * Plaintext-at-rest by design: matches the project-file conventions of Burp
 * Suite and OWASP ZAP; the `pocforge.db` SQLite file inherits whatever fs
 * permissions the operator already trusts for their toolchain. If a higher
 * bar is needed, an AES-GCM master-passphrase mode can be layered on later
 * without changing the schema.
 */
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';

export interface CredentialRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  label: string;
  username: string;
  password: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface RawCredentialRow {
  id: string;
  scope_id: string;
  scope_domain: string | null;
  label: string;
  username: string;
  password: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateCredentialInput {
  scopeId: string;
  label: string;
  username: string;
  password: string;
  notes?: string | null;
}

export interface UpdateCredentialInput {
  label?: string;
  username?: string;
  password?: string;
  notes?: string | null;
}

export class CredentialVault {
  static list(scopeId?: string): CredentialRow[] {
    const sql = scopeId
      ? `SELECT c.*, sc.domain AS scope_domain
           FROM credentials c
           LEFT JOIN scopes sc ON sc.id = c.scope_id
          WHERE c.scope_id = ?
          ORDER BY c.updated_at DESC`
      : `SELECT c.*, sc.domain AS scope_domain
           FROM credentials c
           LEFT JOIN scopes sc ON sc.id = c.scope_id
          ORDER BY c.updated_at DESC`;
    const rows = (
      scopeId
        ? db.prepare(sql).all(scopeId)
        : db.prepare(sql).all()
    ) as RawCredentialRow[];
    return rows;
  }

  static get(id: string): CredentialRow | null {
    const row = db
      .prepare(
        `SELECT c.*, sc.domain AS scope_domain
           FROM credentials c
           LEFT JOIN scopes sc ON sc.id = c.scope_id
          WHERE c.id = ?`,
      )
      .get(id) as RawCredentialRow | undefined;
    return row ?? null;
  }

  static create(input: CreateCredentialInput): CredentialRow {
    if (!input.label || !input.label.trim()) {
      throw new Error('Credential label is required');
    }
    if (!input.username) {
      throw new Error('Credential username is required');
    }
    if (input.password === undefined || input.password === null) {
      throw new Error('Credential password is required');
    }
    const scope = db.prepare('SELECT id FROM scopes WHERE id = ?').get(input.scopeId) as
      | { id: string }
      | undefined;
    if (!scope) throw new Error(`Scope ${input.scopeId} does not exist`);

    const id = uuidv4();
    db.prepare(
      `INSERT INTO credentials (id, scope_id, label, username, password, notes)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.scopeId,
      input.label.trim(),
      input.username,
      input.password,
      input.notes ?? null,
    );
    const created = this.get(id);
    if (!created) throw new Error('Credential creation failed');
    return created;
  }

  static update(id: string, patch: UpdateCredentialInput): CredentialRow {
    const existing = this.get(id);
    if (!existing) throw new Error(`Credential ${id} not found`);

    if (patch.label !== undefined && (!patch.label || !patch.label.trim())) {
      throw new Error('Credential label is required');
    }
    if (patch.username !== undefined && !patch.username) {
      throw new Error('Credential username is required');
    }

    // Empty-string passwords keep the existing value: the UI's "leave blank to
    // keep current" contract has to hold for any direct API caller too,
    // otherwise PATCH {"password": ""} would silently wipe the stored secret.
    const next = {
      label: patch.label?.trim() ?? existing.label,
      username: patch.username ?? existing.username,
      password: patch.password ? patch.password : existing.password,
      notes: patch.notes !== undefined ? patch.notes : existing.notes,
    };

    db.prepare(
      `UPDATE credentials
          SET label = ?, username = ?, password = ?, notes = ?,
              updated_at = CURRENT_TIMESTAMP
        WHERE id = ?`,
    ).run(next.label, next.username, next.password, next.notes, id);

    const after = this.get(id);
    if (!after) throw new Error('Credential update failed');
    return after;
  }

  static delete(id: string): boolean {
    const result = db.prepare('DELETE FROM credentials WHERE id = ?').run(id);
    return result.changes > 0;
  }

  /**
   * Return the credential safely for embedding in API responses: keeps label,
   * username, and notes; redacts the password unless `includePassword` is
   * explicitly true. Auth-flow execution paths read with includePassword;
   * UI list/edit endpoints read without.
   */
  static toPublic(
    row: CredentialRow,
    includePassword = false,
  ): Omit<CredentialRow, 'password'> & { password: string | null; has_password: boolean } {
    return {
      ...row,
      password: includePassword ? row.password : null,
      has_password: !!row.password,
    };
  }
}

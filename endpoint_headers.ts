/**
 * endpoint_headers — Per-endpoint custom header management.
 *
 * Allows operators to define custom HTTP headers that are automatically
 * applied to requests matching a specific URL pattern or endpoint. This
 * is essential for:
 *   - API key injection on specific API endpoints
 *   - Custom Authorization headers per service
 *   - Target-specific fingerprint headers (X-Request-ID, X-Correlation-ID)
 *   - WAF bypass headers discovered during testing
 *   - Content negotiation overrides
 *
 * Headers are stored in SQLite and scoped to URL patterns. The merge
 * function is called from the lab proxy and automation engine before
 * every outbound request, layering endpoint-specific headers on top of
 * session overlay headers.
 *
 * Priority (highest wins):
 *   1. Explicit request headers from the operator
 *   2. Endpoint-matched custom headers (most specific pattern first)
 *   3. Session overlay headers
 *   4. Default HTTP identity headers
 */

import db from './db.js';
import { v4 as uuidv4 } from 'uuid';

// ---------------------------------------------------------------------------
// Schema migration — adds the endpoint_headers table if it doesn't exist
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS endpoint_headers (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    scope_id TEXT,
    description TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_endpoint_headers_pattern ON endpoint_headers(pattern);
  CREATE INDEX IF NOT EXISTS idx_endpoint_headers_scope ON endpoint_headers(scope_id);
`);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EndpointHeader {
  id: string;
  pattern: string;
  name: string;
  value: string;
  scope_id: string | null;
  description: string;
  enabled: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface EndpointHeaderInput {
  pattern: string;
  name: string;
  value: string;
  scopeId?: string | null;
  description?: string;
  priority?: number;
}

interface EndpointHeaderRow {
  id: string;
  pattern: string;
  name: string;
  value: string;
  scope_id: string | null;
  description: string;
  enabled: number;
  priority: number;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

function rowToHeader(row: EndpointHeaderRow): EndpointHeader {
  return {
    ...row,
    enabled: row.enabled === 1,
  };
}

export class EndpointHeaders {
  /**
   * Create a new endpoint header rule.
   */
  static create(input: EndpointHeaderInput): EndpointHeader {
    if (!input.pattern || typeof input.pattern !== 'string') {
      throw new Error('pattern is required');
    }
    if (!input.name || typeof input.name !== 'string') {
      throw new Error('header name is required');
    }
    if (input.value === undefined || input.value === null) {
      throw new Error('header value is required');
    }

    // Validate scope exists if provided
    if (input.scopeId) {
      const scope = db.prepare('SELECT id FROM scopes WHERE id = ?').get(input.scopeId);
      if (!scope) throw new Error(`Scope ${input.scopeId} not found`);
    }

    const id = uuidv4();
    db.prepare(
      `INSERT INTO endpoint_headers (id, pattern, name, value, scope_id, description, priority)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.pattern,
      input.name.toLowerCase(),
      input.value,
      input.scopeId ?? null,
      input.description ?? '',
      input.priority ?? 0,
    );

    return this.get(id)!;
  }

  /**
   * Get a single header rule by ID.
   */
  static get(id: string): EndpointHeader | null {
    const row = db.prepare('SELECT * FROM endpoint_headers WHERE id = ?').get(id) as EndpointHeaderRow | undefined;
    return row ? rowToHeader(row) : null;
  }

  /**
   * List all header rules, optionally filtered by scope.
   */
  static list(scopeId?: string): EndpointHeader[] {
    let rows: EndpointHeaderRow[];
    if (scopeId) {
      rows = db.prepare(
        'SELECT * FROM endpoint_headers WHERE scope_id = ? OR scope_id IS NULL ORDER BY priority DESC, created_at DESC',
      ).all(scopeId) as EndpointHeaderRow[];
    } else {
      rows = db.prepare(
        'SELECT * FROM endpoint_headers ORDER BY priority DESC, created_at DESC',
      ).all() as EndpointHeaderRow[];
    }
    return rows.map(rowToHeader);
  }

  /**
   * Update a header rule.
   */
  static update(
    id: string,
    patch: Partial<EndpointHeaderInput & { enabled: boolean }>,
  ): EndpointHeader {
    const existing = this.get(id);
    if (!existing) throw new Error(`Endpoint header ${id} not found`);

    db.prepare(
      `UPDATE endpoint_headers
          SET pattern = COALESCE(?, pattern),
              name = COALESCE(?, name),
              value = COALESCE(?, value),
              scope_id = CASE WHEN ? = 1 THEN ? ELSE scope_id END,
              description = COALESCE(?, description),
              priority = COALESCE(?, priority),
              enabled = COALESCE(?, enabled),
              updated_at = CURRENT_TIMESTAMP
        WHERE id = ?`,
    ).run(
      patch.pattern ?? null,
      patch.name?.toLowerCase() ?? null,
      patch.value ?? null,
      patch.scopeId !== undefined ? 1 : 0,
      patch.scopeId ?? null,
      patch.description ?? null,
      patch.priority ?? null,
      patch.enabled !== undefined ? (patch.enabled ? 1 : 0) : null,
      id,
    );

    return this.get(id)!;
  }

  /**
   * Delete a header rule.
   */
  static delete(id: string): boolean {
    return db.prepare('DELETE FROM endpoint_headers WHERE id = ?').run(id).changes > 0;
  }

  /**
   * Toggle a header rule on/off.
   */
  static toggle(id: string): EndpointHeader {
    const existing = this.get(id);
    if (!existing) throw new Error(`Endpoint header ${id} not found`);
    db.prepare('UPDATE endpoint_headers SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(existing.enabled ? 0 : 1, id);
    return this.get(id)!;
  }

  /**
   * Find all enabled header rules that match a given URL, sorted by
   * specificity (most specific pattern first, then by priority).
   */
  static matchUrl(url: string, scopeId?: string): EndpointHeader[] {
    const allRules = this.list(scopeId).filter(h => h.enabled);
    const matched: Array<EndpointHeader & { specificity: number }> = [];

    for (const rule of allRules) {
      if (this.patternMatches(rule.pattern, url)) {
        matched.push({ ...rule, specificity: this.patternSpecificity(rule.pattern) });
      }
    }

    // Sort: most specific first, then highest priority
    matched.sort((a, b) => b.specificity - a.specificity || b.priority - a.priority);
    return matched;
  }

  /**
   * Merge endpoint-specific headers into a request's header map.
   * Endpoint headers do NOT overwrite explicitly-provided headers.
   */
  static mergeHeaders(
    url: string,
    existingHeaders: Record<string, string>,
    scopeId?: string,
  ): Record<string, string> {
    const matched = this.matchUrl(url, scopeId);
    const merged = { ...existingHeaders };

    for (const rule of matched) {
      const key = rule.name.toLowerCase();
      // Don't overwrite headers the operator explicitly set
      if (!(key in merged)) {
        merged[key] = rule.value;
      }
    }

    return merged;
  }

  /**
   * Check if a URL matches a pattern.
   * Patterns support:
   *   - Exact URL match: "https://api.example.com/v1/users"
   *   - Wildcard: "https://api.example.com/*" or "*example.com*"
   *   - Domain-only: "example.com" (matches any URL on that domain)
   *   - Path prefix: "/api/v1/*" (matches any URL with that path prefix)
   *   - Regex: "/pattern/flags" (if wrapped in forward slashes)
   */
  private static patternMatches(pattern: string, url: string): boolean {
    // Regex pattern
    if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
      const lastSlash = pattern.lastIndexOf('/');
      const regex = pattern.slice(1, lastSlash);
      const flags = pattern.slice(lastSlash + 1);
      try {
        return new RegExp(regex, flags).test(url);
      } catch {
        return false;
      }
    }

    // Path prefix pattern
    if (pattern.startsWith('/')) {
      try {
        const urlPath = new URL(url).pathname;
        const cleanPattern = pattern.replace(/\*$/, '');
        return urlPath.startsWith(cleanPattern);
      } catch {
        return false;
      }
    }

    // Domain-only pattern (no protocol, no path)
    if (!pattern.includes('/') && !pattern.includes('*')) {
      try {
        const hostname = new URL(url).hostname;
        return hostname === pattern || hostname.endsWith(`.${pattern}`);
      } catch {
        return url.includes(pattern);
      }
    }

    // Wildcard pattern — convert * to regex
    const escaped = pattern
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`, 'i').test(url);
  }

  /**
   * Calculate pattern specificity (higher = more specific).
   * Used to sort matched rules so most specific patterns win.
   */
  private static patternSpecificity(pattern: string): number {
    // Regex patterns are considered highly specific
    if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) return 100;
    // Exact URL (no wildcards)
    if (!pattern.includes('*') && pattern.includes('://')) return 90;
    // Path prefix with no wildcards
    if (!pattern.includes('*') && pattern.startsWith('/')) return 70;
    // Domain + path with wildcards
    if (pattern.includes('://') && pattern.includes('*')) return 50;
    // Domain-only
    if (!pattern.includes('/') && !pattern.includes('*')) return 30;
    // Pure wildcard
    return 10;
  }
}

import { v4 as uuidv4 } from 'uuid';
import db from './db.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Phase = 'request' | 'response';

export type MatchTarget =
  | 'url'
  | 'method'
  | 'req_header_name'
  | 'req_header_value'
  | 'req_body'
  | 'req_cookie'
  | 'res_header_name'
  | 'res_header_value'
  | 'res_body'
  | 'res_status'
  | 'content_type';

export type MatchOperator =
  | 'contains'
  | 'not_contains'
  | 'regex'
  | 'equals'
  | 'not_equals'
  | 'starts_with'
  | 'ends_with'
  | 'exists'
  | 'not_exists'
  | 'gt'
  | 'lt'
  | 'json_path'
  | 'always';

export type ActionType =
  // Core transforms
  | 'regex_replace'
  | 'literal_replace'
  | 'prepend'
  | 'append'
  | 'remove'
  // Encoding
  | 'base64_encode'
  | 'base64_decode'
  | 'url_encode'
  | 'url_decode'
  | 'double_url_encode'
  | 'html_entity_encode'
  | 'html_entity_decode'
  | 'unicode_escape'
  | 'hex_encode'
  // Header manipulation
  | 'add_header'
  | 'remove_header'
  | 'set_header'
  // Security testing
  | 'case_randomize'
  | 'null_byte_inject'
  | 'crlf_inject'
  | 'param_pollute'
  | 'chunk_body'
  // Token / Auth
  | 'jwt_decode_tamper'
  | 'rotate_value';

export type ActionTarget =
  | 'url'
  | 'req_header'
  | 'req_body'
  | 'res_header'
  | 'res_body';

export interface Condition {
  target: MatchTarget;
  operator: MatchOperator;
  value: string;
  headerName?: string;
}

export interface Action {
  type: ActionType;
  target: ActionTarget;
  pattern?: string;
  replacement?: string;
  headerName?: string;
  headerValue?: string;
  jwtClaims?: Record<string, unknown>;
  rotateValues?: string[];
}

export interface MatchReplaceRule {
  id: string;
  name: string;
  phase: Phase;
  enabled: boolean;
  priority: number;
  conditions: Condition[];
  conditionLogic: 'and' | 'or';
  actions: Action[];
  hitCount: number;
  scopeId?: string;
  comment?: string;
  createdAt: string;
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// Condition categories for frontend dropdown
// ---------------------------------------------------------------------------

export const CONDITION_CATEGORIES = [
  {
    category: 'Scope',
    conditions: [
      { target: 'url' as MatchTarget, operator: 'regex' as MatchOperator, label: 'URL matches regex' },
      { target: 'url' as MatchTarget, operator: 'contains' as MatchOperator, label: 'URL contains' },
      { target: 'url' as MatchTarget, operator: 'starts_with' as MatchOperator, label: 'URL starts with' },
      { target: 'method' as MatchTarget, operator: 'equals' as MatchOperator, label: 'Method equals' },
    ],
  },
  {
    category: 'Request',
    conditions: [
      { target: 'req_header_name' as MatchTarget, operator: 'exists' as MatchOperator, label: 'Request header exists' },
      { target: 'req_header_value' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Request header value contains' },
      { target: 'req_header_value' as MatchTarget, operator: 'regex' as MatchOperator, label: 'Request header value matches regex' },
      { target: 'req_body' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Request body contains' },
      { target: 'req_body' as MatchTarget, operator: 'regex' as MatchOperator, label: 'Request body matches regex' },
      { target: 'req_body' as MatchTarget, operator: 'json_path' as MatchOperator, label: 'Request body JSON path exists' },
      { target: 'req_cookie' as MatchTarget, operator: 'exists' as MatchOperator, label: 'Request cookie exists' },
      { target: 'req_cookie' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Request cookie value contains' },
      { target: 'content_type' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Content-Type contains' },
    ],
  },
  {
    category: 'Response',
    conditions: [
      { target: 'res_status' as MatchTarget, operator: 'equals' as MatchOperator, label: 'Status code equals' },
      { target: 'res_status' as MatchTarget, operator: 'gt' as MatchOperator, label: 'Status code greater than' },
      { target: 'res_status' as MatchTarget, operator: 'lt' as MatchOperator, label: 'Status code less than' },
      { target: 'res_header_name' as MatchTarget, operator: 'exists' as MatchOperator, label: 'Response header exists' },
      { target: 'res_header_value' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Response header value contains' },
      { target: 'res_body' as MatchTarget, operator: 'contains' as MatchOperator, label: 'Response body contains' },
      { target: 'res_body' as MatchTarget, operator: 'regex' as MatchOperator, label: 'Response body matches regex' },
    ],
  },
  {
    category: 'Universal',
    conditions: [
      { target: 'url' as MatchTarget, operator: 'always' as MatchOperator, label: 'Always (every request)' },
    ],
  },
];

export const ACTION_CATEGORIES = [
  {
    category: 'Transform',
    actions: [
      { type: 'regex_replace' as ActionType, label: 'Regex replace' },
      { type: 'literal_replace' as ActionType, label: 'Literal replace' },
      { type: 'prepend' as ActionType, label: 'Prepend text' },
      { type: 'append' as ActionType, label: 'Append text' },
      { type: 'remove' as ActionType, label: 'Remove matched text' },
    ],
  },
  {
    category: 'Encoding',
    actions: [
      { type: 'base64_encode' as ActionType, label: 'Base64 encode' },
      { type: 'base64_decode' as ActionType, label: 'Base64 decode' },
      { type: 'url_encode' as ActionType, label: 'URL encode' },
      { type: 'url_decode' as ActionType, label: 'URL decode' },
      { type: 'double_url_encode' as ActionType, label: 'Double URL encode' },
      { type: 'html_entity_encode' as ActionType, label: 'HTML entity encode' },
      { type: 'html_entity_decode' as ActionType, label: 'HTML entity decode' },
      { type: 'unicode_escape' as ActionType, label: 'Unicode escape' },
      { type: 'hex_encode' as ActionType, label: 'Hex encode' },
    ],
  },
  {
    category: 'Headers',
    actions: [
      { type: 'add_header' as ActionType, label: 'Add header' },
      { type: 'set_header' as ActionType, label: 'Set/overwrite header' },
      { type: 'remove_header' as ActionType, label: 'Remove header' },
    ],
  },
  {
    category: 'Security Testing',
    actions: [
      { type: 'case_randomize' as ActionType, label: 'Randomize case (WAF evasion)' },
      { type: 'null_byte_inject' as ActionType, label: 'Null byte inject' },
      { type: 'crlf_inject' as ActionType, label: 'CRLF inject' },
      { type: 'param_pollute' as ActionType, label: 'Parameter pollution' },
      { type: 'chunk_body' as ActionType, label: 'Chunk body (transfer-encoding evasion)' },
    ],
  },
  {
    category: 'Auth / Token',
    actions: [
      { type: 'jwt_decode_tamper' as ActionType, label: 'JWT decode & tamper claims' },
      { type: 'rotate_value' as ActionType, label: 'Rotate value (cycle through list)' },
    ],
  },
];

// ---------------------------------------------------------------------------
// DB init
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS match_replace_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'request',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    conditions TEXT NOT NULL DEFAULT '[]',
    condition_logic TEXT NOT NULL DEFAULT 'and',
    actions TEXT NOT NULL DEFAULT '[]',
    hit_count INTEGER NOT NULL DEFAULT 0,
    scope_id TEXT,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_mr_rules_phase ON match_replace_rules(phase);
  CREATE INDEX IF NOT EXISTS idx_mr_rules_enabled ON match_replace_rules(enabled);
`);

// ---------------------------------------------------------------------------
// Rotation state (in-memory per rule)
// ---------------------------------------------------------------------------
const rotationIndex: Record<string, number> = {};

// ---------------------------------------------------------------------------
// Evaluation helpers
// ---------------------------------------------------------------------------

function evalJsonPath(obj: unknown, path: string): unknown {
  const parts = path.replace(/^\$\.?/, '').split(/[.\[\]]+/).filter(Boolean);
  let cur: any = obj;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

function evalCondition(
  cond: Condition,
  ctx: {
    url: string;
    method: string;
    reqHeaders: Record<string, string>;
    reqBody: string;
    resStatus?: number;
    resHeaders?: Record<string, string>;
    resBody?: string;
  },
): boolean {
  const { target, operator, value, headerName } = cond;

  let subject = '';
  switch (target) {
    case 'url':
      subject = ctx.url;
      break;
    case 'method':
      subject = ctx.method;
      break;
    case 'req_header_name':
      return operator === 'exists'
        ? Object.keys(ctx.reqHeaders).some((k) => k.toLowerCase() === value.toLowerCase())
        : !Object.keys(ctx.reqHeaders).some((k) => k.toLowerCase() === value.toLowerCase());
    case 'req_header_value': {
      const hdr = headerName || value.split(':')[0];
      const hv = Object.entries(ctx.reqHeaders).find(([k]) => k.toLowerCase() === hdr.toLowerCase());
      subject = hv ? hv[1] : '';
      break;
    }
    case 'req_body':
      subject = ctx.reqBody || '';
      break;
    case 'req_cookie': {
      const cookieHeader = ctx.reqHeaders['cookie'] || ctx.reqHeaders['Cookie'] || '';
      if (operator === 'exists' || operator === 'not_exists') {
        const found = cookieHeader.split(';').some((c) => c.trim().startsWith(value + '='));
        return operator === 'exists' ? found : !found;
      }
      subject = cookieHeader;
      break;
    }
    case 'content_type':
      subject = ctx.reqHeaders['content-type'] || ctx.reqHeaders['Content-Type'] || '';
      break;
    case 'res_status':
      subject = String(ctx.resStatus ?? '');
      break;
    case 'res_header_name':
      if (!ctx.resHeaders) return false;
      return operator === 'exists'
        ? Object.keys(ctx.resHeaders).some((k) => k.toLowerCase() === value.toLowerCase())
        : !Object.keys(ctx.resHeaders).some((k) => k.toLowerCase() === value.toLowerCase());
    case 'res_header_value': {
      if (!ctx.resHeaders) return false;
      const hdr = headerName || value.split(':')[0];
      const hv = Object.entries(ctx.resHeaders).find(([k]) => k.toLowerCase() === hdr.toLowerCase());
      subject = hv ? hv[1] : '';
      break;
    }
    case 'res_body':
      subject = ctx.resBody || '';
      break;
    default:
      return false;
  }

  switch (operator) {
    case 'always':
      return true;
    case 'contains':
      return subject.includes(value);
    case 'not_contains':
      return !subject.includes(value);
    case 'equals':
      return subject === value;
    case 'not_equals':
      return subject !== value;
    case 'starts_with':
      return subject.startsWith(value);
    case 'ends_with':
      return subject.endsWith(value);
    case 'regex':
      try { return new RegExp(value, 'i').test(subject); } catch { return false; }
    case 'exists':
      return subject.length > 0;
    case 'not_exists':
      return subject.length === 0;
    case 'gt':
      return parseFloat(subject) > parseFloat(value);
    case 'lt':
      return parseFloat(subject) < parseFloat(value);
    case 'json_path':
      try {
        const parsed = JSON.parse(subject);
        return evalJsonPath(parsed, value) !== undefined;
      } catch {
        return false;
      }
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Action executors
// ---------------------------------------------------------------------------

function caseRandomize(str: string): string {
  return str.split('').map((c) => (Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase())).join('');
}

function hexEncode(str: string): string {
  return [...str].map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function unicodeEscape(str: string): string {
  return [...str].map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
}

function htmlEntityEncode(str: string): string {
  return str.replace(/[&<>"'\/]/g, (c) => `&#${c.charCodeAt(0)};`)
    .replace(/[^\x20-\x7E]/g, (c) => `&#${c.charCodeAt(0)};`);
}

function htmlEntityDecode(str: string): string {
  return str
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function jwtDecodeTamper(token: string, claims: Record<string, unknown>): string {
  const parts = token.split('.');
  if (parts.length !== 3) return token;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    Object.assign(payload, claims);
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    // Invalidate signature — forces the server to handle an unsigned JWT
    parts[2] = '';
    return parts.join('.');
  } catch {
    return token;
  }
}

function chunkBody(body: string, chunkSize = 5): string {
  const chunks: string[] = [];
  for (let i = 0; i < body.length; i += chunkSize) {
    const slice = body.slice(i, i + chunkSize);
    chunks.push(slice.length.toString(16) + '\r\n' + slice + '\r\n');
  }
  chunks.push('0\r\n\r\n');
  return chunks.join('');
}

function applyTextAction(
  action: Action,
  text: string,
  ruleId: string,
): string {
  const { type, pattern, replacement } = action;
  switch (type) {
    case 'regex_replace':
      try {
        return text.replace(new RegExp(pattern || '', 'g'), replacement || '');
      } catch {
        return text;
      }
    case 'literal_replace':
      return text.split(pattern || '').join(replacement || '');
    case 'prepend':
      return (replacement || '') + text;
    case 'append':
      return text + (replacement || '');
    case 'remove':
      return pattern ? text.split(pattern).join('') : text.replace(new RegExp(replacement || '', 'g'), '');
    case 'base64_encode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), (m) => Buffer.from(m).toString('base64'))
        : Buffer.from(text).toString('base64');
    case 'base64_decode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), (m) => Buffer.from(m, 'base64').toString())
        : Buffer.from(text, 'base64').toString();
    case 'url_encode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), encodeURIComponent)
        : encodeURIComponent(text);
    case 'url_decode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), decodeURIComponent)
        : decodeURIComponent(text);
    case 'double_url_encode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), (m) => encodeURIComponent(encodeURIComponent(m)))
        : encodeURIComponent(encodeURIComponent(text));
    case 'html_entity_encode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), htmlEntityEncode)
        : htmlEntityEncode(text);
    case 'html_entity_decode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), htmlEntityDecode)
        : htmlEntityDecode(text);
    case 'unicode_escape':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), unicodeEscape)
        : unicodeEscape(text);
    case 'hex_encode':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), hexEncode)
        : hexEncode(text);
    case 'case_randomize':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), caseRandomize)
        : caseRandomize(text);
    case 'null_byte_inject':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), (m) => m + '\x00')
        : text + '\x00';
    case 'crlf_inject':
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), (m) => m + '\r\n' + (replacement || ''))
        : text + '\r\n' + (replacement || '');
    case 'chunk_body':
      return chunkBody(text);
    case 'jwt_decode_tamper': {
      const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
      const claims = action.jwtClaims || (replacement ? JSON.parse(replacement) : {});
      return text.replace(jwtRegex, (m) => jwtDecodeTamper(m, claims));
    }
    case 'rotate_value': {
      const values = action.rotateValues || (replacement || '').split('|||');
      if (values.length === 0) return text;
      const idx = (rotationIndex[ruleId] || 0) % values.length;
      rotationIndex[ruleId] = idx + 1;
      return pattern
        ? text.replace(new RegExp(pattern, 'g'), values[idx])
        : values[idx];
    }
    case 'param_pollute': {
      if (!pattern || !replacement) return text;
      // For URLs: add duplicate param with different value
      const separator = text.includes('?') ? '&' : '?';
      return text + separator + pattern + '=' + replacement;
    }
    default:
      return text;
  }
}

// ---------------------------------------------------------------------------
// Main engine: apply rules to a request or response context
// ---------------------------------------------------------------------------

export interface RequestContext {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

export interface ResponseContext {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function rowToRule(row: any): MatchReplaceRule {
  return {
    id: row.id,
    name: row.name,
    phase: row.phase,
    enabled: !!row.enabled,
    priority: row.priority,
    conditions: JSON.parse(row.conditions || '[]'),
    conditionLogic: row.condition_logic || 'and',
    actions: JSON.parse(row.actions || '[]'),
    hitCount: row.hit_count || 0,
    scopeId: row.scope_id || undefined,
    comment: row.comment || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export const MatchReplace = {
  // -------------------------------------------------------------------------
  // CRUD
  // -------------------------------------------------------------------------

  list(scopeId?: string): MatchReplaceRule[] {
    const query = scopeId
      ? db.prepare('SELECT * FROM match_replace_rules WHERE scope_id = ? OR scope_id IS NULL ORDER BY priority DESC, created_at ASC')
      : db.prepare('SELECT * FROM match_replace_rules ORDER BY priority DESC, created_at ASC');
    const rows = scopeId ? query.all(scopeId) : query.all();
    return (rows as any[]).map(rowToRule);
  },

  get(id: string): MatchReplaceRule | null {
    const row = db.prepare('SELECT * FROM match_replace_rules WHERE id = ?').get(id);
    return row ? rowToRule(row) : null;
  },

  create(data: {
    name: string;
    phase?: Phase;
    conditions?: Condition[];
    conditionLogic?: 'and' | 'or';
    actions?: Action[];
    priority?: number;
    scopeId?: string;
    comment?: string;
  }): MatchReplaceRule {
    const id = uuidv4();
    db.prepare(
      `INSERT INTO match_replace_rules (id, name, phase, conditions, condition_logic, actions, priority, scope_id, comment)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      data.name,
      data.phase || 'request',
      JSON.stringify(data.conditions || []),
      data.conditionLogic || 'and',
      JSON.stringify(data.actions || []),
      data.priority ?? 0,
      data.scopeId || null,
      data.comment || null,
    );
    return this.get(id)!;
  },

  update(id: string, data: Partial<{
    name: string;
    phase: Phase;
    enabled: boolean;
    conditions: Condition[];
    conditionLogic: 'and' | 'or';
    actions: Action[];
    priority: number;
    scopeId: string | null;
    comment: string | null;
  }>): MatchReplaceRule {
    const existing = this.get(id);
    if (!existing) throw new Error('Rule not found');
    const updates: string[] = [];
    const values: any[] = [];
    if (data.name !== undefined) { updates.push('name = ?'); values.push(data.name); }
    if (data.phase !== undefined) { updates.push('phase = ?'); values.push(data.phase); }
    if (data.enabled !== undefined) { updates.push('enabled = ?'); values.push(data.enabled ? 1 : 0); }
    if (data.conditions !== undefined) { updates.push('conditions = ?'); values.push(JSON.stringify(data.conditions)); }
    if (data.conditionLogic !== undefined) { updates.push('condition_logic = ?'); values.push(data.conditionLogic); }
    if (data.actions !== undefined) { updates.push('actions = ?'); values.push(JSON.stringify(data.actions)); }
    if (data.priority !== undefined) { updates.push('priority = ?'); values.push(data.priority); }
    if (data.scopeId !== undefined) { updates.push('scope_id = ?'); values.push(data.scopeId); }
    if (data.comment !== undefined) { updates.push('comment = ?'); values.push(data.comment); }
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);
    db.prepare(`UPDATE match_replace_rules SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    return this.get(id)!;
  },

  delete(id: string): boolean {
    const result = db.prepare('DELETE FROM match_replace_rules WHERE id = ?').run(id);
    delete rotationIndex[id];
    return result.changes > 0;
  },

  toggle(id: string): MatchReplaceRule {
    const existing = this.get(id);
    if (!existing) throw new Error('Rule not found');
    db.prepare('UPDATE match_replace_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(existing.enabled ? 0 : 1, id);
    return this.get(id)!;
  },

  duplicate(id: string): MatchReplaceRule {
    const existing = this.get(id);
    if (!existing) throw new Error('Rule not found');
    return this.create({
      name: existing.name + ' (copy)',
      phase: existing.phase,
      conditions: existing.conditions,
      conditionLogic: existing.conditionLogic,
      actions: existing.actions,
      priority: existing.priority,
      scopeId: existing.scopeId,
      comment: existing.comment,
    });
  },

  // -------------------------------------------------------------------------
  // Engine
  // -------------------------------------------------------------------------

  applyToRequest(ctx: RequestContext, scopeId?: string): RequestContext {
    const rules = this.list(scopeId).filter((r) => r.enabled && r.phase === 'request');
    let { url, method, headers, body } = ctx;

    for (const rule of rules) {
      const matchCtx = { url, method, reqHeaders: headers, reqBody: body };
      const matches = rule.conditionLogic === 'and'
        ? rule.conditions.every((c) => evalCondition(c, matchCtx))
        : rule.conditions.some((c) => evalCondition(c, matchCtx));

      if (rule.conditions.length === 0 || matches) {
        for (const action of rule.actions) {
          switch (action.target) {
            case 'url':
              url = applyTextAction(action, url, rule.id);
              break;
            case 'req_header':
              if (action.type === 'add_header' || action.type === 'set_header') {
                if (action.headerName) headers[action.headerName] = action.headerValue || '';
              } else if (action.type === 'remove_header') {
                if (action.headerName) {
                  const key = Object.keys(headers).find((k) => k.toLowerCase() === action.headerName!.toLowerCase());
                  if (key) delete headers[key];
                }
              } else {
                // Apply text transforms to all header values
                for (const [k, v] of Object.entries(headers)) {
                  headers[k] = applyTextAction(action, v, rule.id);
                }
              }
              break;
            case 'req_body':
              body = applyTextAction(action, body, rule.id);
              break;
          }
        }
        db.prepare('UPDATE match_replace_rules SET hit_count = hit_count + 1 WHERE id = ?').run(rule.id);
      }
    }

    return { url, method, headers: { ...headers }, body };
  },

  applyToResponse(
    reqCtx: RequestContext,
    resCtx: ResponseContext,
    scopeId?: string,
  ): ResponseContext {
    const rules = this.list(scopeId).filter((r) => r.enabled && r.phase === 'response');
    let { status, headers, body } = resCtx;

    for (const rule of rules) {
      const matchCtx = {
        url: reqCtx.url,
        method: reqCtx.method,
        reqHeaders: reqCtx.headers,
        reqBody: reqCtx.body,
        resStatus: status,
        resHeaders: headers,
        resBody: typeof body === 'string' ? body : JSON.stringify(body),
      };
      const matches = rule.conditionLogic === 'and'
        ? rule.conditions.every((c) => evalCondition(c, matchCtx))
        : rule.conditions.some((c) => evalCondition(c, matchCtx));

      if (rule.conditions.length === 0 || matches) {
        for (const action of rule.actions) {
          const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
          switch (action.target) {
            case 'res_header':
              if (action.type === 'add_header' || action.type === 'set_header') {
                if (action.headerName) headers[action.headerName] = action.headerValue || '';
              } else if (action.type === 'remove_header') {
                if (action.headerName) {
                  const key = Object.keys(headers).find((k) => k.toLowerCase() === action.headerName!.toLowerCase());
                  if (key) delete headers[key];
                }
              } else {
                for (const [k, v] of Object.entries(headers)) {
                  headers[k] = applyTextAction(action, String(v), rule.id);
                }
              }
              break;
            case 'res_body':
              body = applyTextAction(action, bodyStr, rule.id);
              break;
          }
        }
        db.prepare('UPDATE match_replace_rules SET hit_count = hit_count + 1 WHERE id = ?').run(rule.id);
      }
    }

    return { status, headers: { ...headers }, body };
  },

  // Expose catalogs for the frontend
  getConditionCategories() { return CONDITION_CATEGORIES; },
  getActionCategories() { return ACTION_CATEGORIES; },

  resetHitCount(id: string): void {
    db.prepare('UPDATE match_replace_rules SET hit_count = 0 WHERE id = ?').run(id);
  },
};

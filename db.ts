import Database from 'better-sqlite3';
import path from 'path';

const dataDir = process.env.LEVARG_DATA_DIR || process.cwd();
const db = new Database(path.join(dataDir, 'pocforge.db'));

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    source TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    name TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    headers TEXT,
    body TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS responses (
    id TEXT PRIMARY KEY,
    request_id TEXT,
    status INTEGER,
    headers TEXT,
    body TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(request_id) REFERENCES requests(id)
  );

  CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    steps TEXT NOT NULL, -- JSON array of request IDs
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS payloads (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    payload_set_id TEXT NOT NULL,
    status TEXT NOT NULL,
    baseline_status INTEGER,
    baseline_length INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    status INTEGER,
    length INTEGER,
    is_anomaly BOOLEAN,
    response_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
  );

  CREATE TABLE IF NOT EXISTS stack_gap_findings (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    mutation_type TEXT NOT NULL,
    baseline_status INTEGER,
    mutated_status INTEGER,
    evidence TEXT,
    confidence TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS automation_jobs (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'running', 'completed', 'failed'
    phase TEXT, -- 'recon', 'crawling', 'fuzzing', 'exfiltration'
    findings TEXT, -- JSON array of findings
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS automation_logs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    level TEXT NOT NULL, -- 'info', 'warn', 'error', 'vuln'
    message TEXT NOT NULL,
    data TEXT, -- JSON additional data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(job_id) REFERENCES automation_jobs(id)
  );

  -- Authenticated-testing sessions: named cookie/header bundles bound to a scope.
  -- A session captured via the built-in browser (or hand-crafted) can be injected
  -- into Request Lab and Flow Runner so authenticated requests reuse the auth
  -- material. Bound to scope_id so a session for scope A can never be used
  -- against scope B.
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cookies TEXT,        -- JSON array of {name, value, domain, path, expires, httpOnly, secure, sameSite}
    headers TEXT,        -- JSON object of static headers (Authorization, X-CSRF-Token, ...)
    storage TEXT,        -- JSON {localStorage:{}, sessionStorage:{}}
    user_agent TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
    UNIQUE(scope_id, name)
  );

  -- Stored login credentials per scope. Used by auth-flow macros to fill
  -- login forms during a hunt without re-prompting the operator. Bound 1:1
  -- to a Scope so credentials for scope A can never be replayed against
  -- scope B. Plaintext-at-rest by design (matches Burp/ZAP project files);
  -- the pocforge.db file lives next to the project and inherits the same
  -- filesystem permissions the operator already grants their tooling.
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    label TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
    UNIQUE(scope_id, label)
  );

  -- Replayable login macros bound to a scope (and optionally a credential).
  -- A flow is an ordered list of steps {goto|fill|click|press|waitForSelector|
  -- waitForUrl|sleep}; runtime checks every navigated/typed URL against the
  -- bound scope's domain before executing — the operator's stored credentials
  -- are NEVER typed into a host outside the scope (third-party OAuth providers
  -- like accounts.google.com / facebook.com / appleid.apple.com are
  -- explicitly out of scope and require manual login via the built-in browser
  -- or the OS-browser extension).
  CREATE TABLE IF NOT EXISTS auth_flows (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    credential_id TEXT,
    name TEXT NOT NULL,
    steps TEXT NOT NULL,                    -- JSON array of AuthFlowStep
    trigger_mode TEXT NOT NULL DEFAULT 'preflight', -- 'preflight' | 'on_401' | 'discovery' | 'all' | 'manual'
    is_default INTEGER NOT NULL DEFAULT 0,  -- if 1, applied automatically when a hunt starts on this scope without explicit auth_flow_id
    last_run_at DATETIME,
    last_status TEXT,                       -- 'ok' | 'error'
    last_error TEXT,
    success_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
    FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE SET NULL,
    UNIQUE(scope_id, name)
  );

  -- Pairing tokens for the OS-browser extension. The operator generates a
  -- token in the LEVARG UI, pastes it into the extension's options page, and
  -- the extension can then POST captured cookies to /api/extension/cookies.
  -- Tokens are scope-bound so an extension paired for scope A can't smuggle
  -- cookies into a session bound to scope B. last_used_at and request count
  -- are recorded for audit.
  CREATE TABLE IF NOT EXISTS extension_tokens (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    label TEXT,
    last_used_at DATETIME,
    use_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE
  );
`);

// Migration: Add 'phase' column to 'automation_jobs' if it doesn't exist
const tableInfo = db.prepare("PRAGMA table_info(automation_jobs)").all() as any[];
const hasPhase = tableInfo.some(col => col.name === 'phase');
if (!hasPhase) {
  db.exec("ALTER TABLE automation_jobs ADD COLUMN phase TEXT");
}

// --- Performance indexes ---
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_responses_request_id ON responses(request_id);
  CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
  CREATE INDEX IF NOT EXISTS idx_automation_logs_job_id ON automation_logs(job_id);
  CREATE INDEX IF NOT EXISTS idx_endpoints_created ON endpoints(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_sessions_scope_id ON sessions(scope_id);
  CREATE INDEX IF NOT EXISTS idx_credentials_scope_id ON credentials(scope_id);
  CREATE INDEX IF NOT EXISTS idx_auth_flows_scope_id ON auth_flows(scope_id);
  CREATE INDEX IF NOT EXISTS idx_extension_tokens_scope_id ON extension_tokens(scope_id);
  CREATE INDEX IF NOT EXISTS idx_stack_gap_findings_created ON stack_gap_findings(created_at DESC);
`);

// --- Crash recovery: mark orphaned 'running' scans/jobs as 'failed' ---
db.prepare("UPDATE scans SET status = 'failed' WHERE status = 'running'").run();
db.prepare("UPDATE automation_jobs SET status = 'failed' WHERE status = 'running'").run();

export default db;

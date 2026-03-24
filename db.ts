import Database from 'better-sqlite3';
import path from 'path';

const db = new Database('pocforge.db');

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
`);

// Migration: Add 'phase' column to 'automation_jobs' if it doesn't exist
const tableInfo = db.prepare("PRAGMA table_info(automation_jobs)").all() as any[];
const hasPhase = tableInfo.some(col => col.name === 'phase');
if (!hasPhase) {
  db.exec("ALTER TABLE automation_jobs ADD COLUMN phase TEXT");
}

export default db;

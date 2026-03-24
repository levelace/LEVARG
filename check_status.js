import Database from 'better-sqlite3';
const db = new Database('pocforge.db');
const jobs = db.prepare('SELECT * FROM automation_jobs ORDER BY created_at DESC LIMIT 5').all();
console.log(JSON.stringify(jobs, null, 2));
const logs = db.prepare('SELECT * FROM automation_logs ORDER BY created_at DESC LIMIT 10').all();
console.log('--- LATEST LOGS ---');
console.log(JSON.stringify(logs, null, 2));

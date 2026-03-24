import Database from 'better-sqlite3';
const db = new Database('pocforge.db');

const jobs = db.prepare('SELECT * FROM automation_jobs ORDER BY created_at DESC LIMIT 5').all();
console.log('--- JOBS ---');
console.log(JSON.stringify(jobs, null, 2));

const logs = db.prepare('SELECT * FROM automation_logs WHERE job_id IN (?, ?) ORDER BY created_at DESC LIMIT 20')
  .all('4df60ab2-4d52-4ab8-b256-446d638e9d3c', 'f1557098-c818-44a3-9d3c-a4be313111f5');
console.log('--- LATEST LOGS ---');
console.log(JSON.stringify(logs, null, 2));

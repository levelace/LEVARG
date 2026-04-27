/**
 * Centralized SecLists wordlist loader.
 *
 * SecLists is installed during `setup.sh` to `$LEVARG_TOOLS_HOME/wordlists/SecLists`
 * (default `~/.levarg/wordlists/SecLists`). This module is the single read path
 * every detector / discovery phase uses, so the 2.5 GB tree is only resolved
 * once per process and missing files degrade gracefully to a small built-in
 * fallback rather than crashing the hunt.
 */

import fs from 'fs';
import path from 'path';

const TOOLS_HOME = process.env.LEVARG_TOOLS_HOME || path.join(process.env.HOME || '/root', '.levarg');
const SECLISTS_ROOT = path.join(TOOLS_HOME, 'wordlists', 'SecLists');

const cache = new Map<string, string[]>();

/**
 * Read a file under SECLISTS_ROOT, returning non-empty / non-comment lines.
 * Returns [] (not throw) if the file is missing — callers must always supply a
 * fallback list themselves so a partial SecLists install never wedges a hunt.
 */
function readLines(relPath: string, max?: number): string[] {
  const cacheKey = `${relPath}:${max ?? 'all'}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const abs = path.join(SECLISTS_ROOT, relPath);
  let lines: string[] = [];
  try {
    if (fs.existsSync(abs)) {
      const raw = fs.readFileSync(abs, 'utf8');
      lines = raw
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith('#'));
      if (max && lines.length > max) lines = lines.slice(0, max);
    }
  } catch {
    lines = [];
  }
  cache.set(cacheKey, lines);
  return lines;
}

function dedup(arr: string[]): string[] {
  return Array.from(new Set(arr));
}

export function isSecListsAvailable(): boolean {
  return fs.existsSync(path.join(SECLISTS_ROOT, 'Discovery'));
}

/** Top-N subdomain prefixes for DNS brute-forcing. Cap defaults to 500 (DNS-bound). */
export function getSubdomains(max = 500): string[] {
  const FALLBACK = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
    'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
    'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
    'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
    'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay',
    'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
    'exchange', 'ipv4',
  ];
  const lines = readLines('Discovery/DNS/subdomains-top1million-5000.txt', max);
  return lines.length > 0 ? lines : FALLBACK.slice(0, max);
}

/** Common HTTP path-enum entries. Cap defaults to 500 (HTTP-bound). */
export function getCommonPaths(max = 500): string[] {
  const FALLBACK = [
    'admin', 'api', 'v1', 'v2', 'graphql', 'config', 'login', 'dashboard',
    'debug', 'internal', 'metrics', '.env', 'phpinfo',
    'api/auth/login', 'api/auth/google', 'api/auth/session', 'api/users/me',
    'api/teams', 'api/projects', 'api/files',
    '.git/config', '.git/HEAD', '.vscode/sftp.json', '.well-known/security.txt',
    'sitemap.xml', 'robots.txt', 'crossdomain.xml', 'server-status',
    'phpmyadmin', 'wp-admin', 'wp-login.php', 'manager/html', 'console',
    'actuator', 'actuator/health', 'actuator/env',
  ];
  const lines = readLines('Discovery/Web-Content/common.txt', max);
  return lines.length > 0 ? lines : FALLBACK.slice(0, max);
}

/** Top usernames for credential-spray. Default = full shortlist (17 lines). */
export function getTopUsernames(max = 100): string[] {
  const FALLBACK = [
    'admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo',
    'support', 'service', 'sysadmin', 'webmaster', 'info', 'api', 'manager',
  ];
  const lines = readLines('Usernames/top-usernames-shortlist.txt', max);
  return lines.length > 0 ? lines : FALLBACK.slice(0, max);
}

/**
 * Top passwords for credential-spray. Defaults to top-100 from darkweb2017
 * because it's small enough to keep a spray bounded (≤17 × 100 = 1,700 reqs
 * per form at 1/sec = ~28 min, the practical upper bound for a single spray).
 */
export function getTopPasswords(max = 100): string[] {
  const FALLBACK = [
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
    '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football',
    'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321',
    'mustang', '1234567890', 'michael', '654321', 'pussy', 'superman', '1qaz2wsx',
    '7777777', 'fuckyou', '121212', '000000', 'qazwsx', '123qwe', 'killer',
    'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
    'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
  ];
  const lines = readLines('Passwords/Common-Credentials/darkweb2017_top-100.txt', max);
  return lines.length > 0 ? lines : FALLBACK.slice(0, max);
}

/** SQL-injection payloads, sized per tier. */
export function getSqliPayloads(tier: 'standard' | 'advanced' | 'elite' = 'standard'): string[] {
  const cap = tier === 'standard' ? 30 : tier === 'advanced' ? 150 : 800;
  const merged = dedup([
    ...readLines('Fuzzing/Databases/SQLi/quick-SQLi.txt'),
    ...readLines('Fuzzing/Databases/SQLi/Generic-SQLi.txt'),
    ...readLines('Fuzzing/Databases/SQLi/SQLi-Polyglots.txt'),
    ...(tier !== 'standard' ? readLines('Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt') : []),
    ...(tier === 'elite' ? readLines('Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt') : []),
  ]);
  return merged.slice(0, cap);
}

/** XSS payloads, sized per tier. Polyglots first (highest hit-rate per byte). */
export function getXssPayloads(tier: 'standard' | 'advanced' | 'elite' = 'standard'): string[] {
  const cap = tier === 'standard' ? 30 : tier === 'advanced' ? 150 : 800;
  const merged = dedup([
    ...readLines('Fuzzing/XSS/Polyglots/XSS-Polyglots.txt'),
    ...readLines('Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt'),
    ...(tier !== 'standard' ? readLines('Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt') : []),
    ...(tier === 'elite' ? readLines('Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt') : []),
  ]);
  return merged.slice(0, cap);
}

/** LFI / path-traversal payloads, sized per tier. */
export function getLfiPayloads(tier: 'standard' | 'advanced' | 'elite' = 'standard'): string[] {
  const cap = tier === 'standard' ? 30 : tier === 'advanced' ? 150 : 800;
  const merged = dedup([
    ...readLines('Fuzzing/LFI/LFI-Jhaddix.txt'),
    ...(tier !== 'standard' ? readLines('Fuzzing/LFI/LFI-LFISuite-pathtotest.txt') : []),
    ...(tier === 'elite' ? readLines('Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt') : []),
  ]);
  return merged.slice(0, cap);
}

export function getSecListsRoot(): string {
  return SECLISTS_ROOT;
}

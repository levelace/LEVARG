import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync } from 'fs';
import { readdir } from 'fs/promises';
import dns from 'dns/promises';
import path from 'path';
import portscanner from 'portscanner';
import axios from 'axios';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';
import { getSubdomains, getCommonPaths } from './seclists.js';

const execAsync = promisify(exec);

const spawnAsync = (
  command: string,
  args: string[],
  opts: { timeoutMs?: number; stdin?: string } = {}
): Promise<{ stdout: string; stderr: string; timedOut?: boolean }> => {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let stdout = '';
    let stderr = '';
    let killedByTimeout = false;
    const timer = opts.timeoutMs && opts.timeoutMs > 0
      ? setTimeout(() => {
          killedByTimeout = true;
          try { child.kill('SIGKILL'); } catch {}
        }, opts.timeoutMs)
      : null;

    child.stdout.on('data', (data) => { stdout += data.toString(); });
    child.stderr.on('data', (data) => { stderr += data.toString(); });

    if (opts.stdin) {
      try { child.stdin.write(opts.stdin); child.stdin.end(); } catch {}
    }

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (killedByTimeout) {
        resolve({ stdout, stderr: stderr + `\n[spawnAsync] killed after ${opts.timeoutMs}ms timeout`, timedOut: true });
      } else if (code === 0 || code === null) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`Command failed with exit code ${code}: ${stderr}`));
      }
    });

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
  });
};

// Per-tool default subprocess timeouts. Tools that hit slow / rate-limited
// targets must time out so a stuck Phase 2 fingerprint doesn't wedge the
// entire hunt.
const TOOL_TIMEOUTS_MS: Record<string, number> = {
  httpx: 30_000,
  subfinder: 120_000,
  naabu: 90_000,
  nmap: 90_000,
  katana: 90_000,
  nuclei: 180_000,
  pdtm: 60_000,
};

export type ToolCategory = 'Recon' | 'Fingerprinting' | 'Discovery' | 'Vulnerability' | 'Exploitation' | 'Utility';
export type ExecutionMethod = 'BINARY' | 'NPX' | 'POLYFILL' | 'UNAVAILABLE';

export interface InstallMethod {
  label: string;
  command: string;
}

interface ToolDefinition {
  name: string;
  category: ToolCategory;
  phase: number;
  binaryName: string;
  npxPackage?: string;
  description: string;
  versionFlag: string;
  installMethods: InstallMethod[];
}

export interface ResourceDefinition {
  name: string;
  type: 'wordlist' | 'templates';
  description: string;
  defaultPath: string;
  installMethods: InstallMethod[];
  verifyPath: string;
}

// --- Centralized paths ---
const TOOLS_HOME = process.env.LEVARG_TOOLS_HOME || path.join(process.env.HOME || '/root', '.levarg');
const WORDLISTS_DIR = path.join(TOOLS_HOME, 'wordlists');
const TEMPLATES_DIR = path.join(TOOLS_HOME, 'templates');

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  // --- Utility (pdtm first — it can install everything from ProjectDiscovery) ---
  {
    name: 'pdtm', category: 'Utility', phase: 0, binaryName: 'pdtm',
    description: 'ProjectDiscovery Tool Manager — installs & updates all PD tools',
    versionFlag: '-version',
    installMethods: [
      { label: 'go install (latest)', command: 'go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/pdtm/releases/latest/download/pdtm_linux_amd64.zip -o /tmp/pdtm.zip && unzip -o /tmp/pdtm.zip -d /usr/local/bin && rm /tmp/pdtm.zip' },
      { label: 'curl (Linux arm64)', command: 'curl -sL https://github.com/projectdiscovery/pdtm/releases/latest/download/pdtm_linux_arm64.zip -o /tmp/pdtm.zip && unzip -o /tmp/pdtm.zip -d /usr/local/bin && rm /tmp/pdtm.zip' },
      { label: 'curl (macOS amd64)', command: 'curl -sL https://github.com/projectdiscovery/pdtm/releases/latest/download/pdtm_macOS_amd64.zip -o /tmp/pdtm.zip && unzip -o /tmp/pdtm.zip -d /usr/local/bin && rm /tmp/pdtm.zip' },
      { label: 'curl (macOS arm64)', command: 'curl -sL https://github.com/projectdiscovery/pdtm/releases/latest/download/pdtm_macOS_arm64.zip -o /tmp/pdtm.zip && unzip -o /tmp/pdtm.zip -d /usr/local/bin && rm /tmp/pdtm.zip' },
    ]
  },
  // --- Recon ---
  {
    name: 'nmap', category: 'Recon', phase: 1, binaryName: 'nmap',
    description: 'Network exploration and port scanning',
    versionFlag: '--version',
    installMethods: [
      { label: 'apt (Debian/Ubuntu)', command: 'sudo apt-get install -y nmap' },
      { label: 'brew (macOS)', command: 'brew install nmap' },
      { label: 'pacman (Arch)', command: 'sudo pacman -S nmap' },
    ]
  },
  {
    name: 'subfinder', category: 'Recon', phase: 1, binaryName: 'subfinder',
    description: 'Passive subdomain discovery',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install subfinder' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip -o /tmp/subfinder.zip && unzip -o /tmp/subfinder.zip -d /usr/local/bin && rm /tmp/subfinder.zip' },
    ]
  },
  {
    name: 'amass', category: 'Recon', phase: 1, binaryName: 'amass',
    description: 'In-depth attack surface mapping',
    versionFlag: '-version',
    installMethods: [
      { label: 'go install', command: 'go install -v github.com/owasp-amass/amass/v4/...@master' },
      { label: 'apt (Kali/Ubuntu)', command: 'sudo apt-get install -y amass' },
      { label: 'brew (macOS)', command: 'brew install amass' },
      { label: 'snap', command: 'sudo snap install amass' },
    ]
  },
  {
    name: 'naabu', category: 'Recon', phase: 1, binaryName: 'naabu',
    description: 'Fast port scanner (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install naabu' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_linux_amd64.zip -o /tmp/naabu.zip && unzip -o /tmp/naabu.zip -d /usr/local/bin && rm /tmp/naabu.zip' },
    ]
  },
  {
    name: 'dnsx', category: 'Recon', phase: 1, binaryName: 'dnsx',
    description: 'Fast DNS toolkit (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install dnsx' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest' },
    ]
  },
  {
    name: 'uncover', category: 'Recon', phase: 1, binaryName: 'uncover',
    description: 'API-powered host discovery (Shodan, Censys, Fofa)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install uncover' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest' },
    ]
  },
  // --- Fingerprinting ---
  {
    name: 'httpx', category: 'Fingerprinting', phase: 2, binaryName: 'httpx',
    description: 'Fast multi-purpose HTTP toolkit (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install httpx' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip && unzip -o /tmp/httpx.zip -d /usr/local/bin && rm /tmp/httpx.zip' },
    ]
  },
  {
    name: 'whatweb', category: 'Fingerprinting', phase: 2, binaryName: 'whatweb',
    description: 'Web technology identifier',
    versionFlag: '--version',
    installMethods: [
      { label: 'apt (Debian/Ubuntu)', command: 'sudo apt-get install -y whatweb' },
      { label: 'brew (macOS)', command: 'brew install whatweb' },
      { label: 'gem', command: 'gem install whatweb' },
    ]
  },
  {
    name: 'tlsx', category: 'Fingerprinting', phase: 2, binaryName: 'tlsx',
    description: 'TLS data gatherer (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install tlsx' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest' },
    ]
  },
  // --- Discovery ---
  {
    name: 'ffuf', category: 'Discovery', phase: 3, binaryName: 'ffuf', npxPackage: 'ffuf',
    description: 'Fast web fuzzer',
    versionFlag: '-V',
    installMethods: [
      { label: 'go install', command: 'go install -v github.com/ffuf/ffuf/v2@latest' },
      { label: 'apt (Kali/Ubuntu)', command: 'sudo apt-get install -y ffuf' },
      { label: 'brew (macOS)', command: 'brew install ffuf' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz | tar xz -C /usr/local/bin' },
    ]
  },
  {
    name: 'dirb', category: 'Discovery', phase: 3, binaryName: 'dirb',
    description: 'Web content scanner',
    versionFlag: '-h',
    installMethods: [
      { label: 'apt (Debian/Ubuntu)', command: 'sudo apt-get install -y dirb' },
    ]
  },
  {
    name: 'katana', category: 'Discovery', phase: 3, binaryName: 'katana',
    description: 'Next-gen web crawler (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install katana' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_amd64.zip -o /tmp/katana.zip && unzip -o /tmp/katana.zip -d /usr/local/bin && rm /tmp/katana.zip' },
    ]
  },
  {
    name: 'gau', category: 'Discovery', phase: 3, binaryName: 'gau',
    description: 'Fetch known URLs from AlienVault, Wayback, Common Crawl',
    versionFlag: '-version',
    installMethods: [
      { label: 'go install', command: 'go install -v github.com/lc/gau/v2/cmd/gau@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz | tar xz -C /usr/local/bin' },
    ]
  },
  {
    name: 'gobuster', category: 'Discovery', phase: 3, binaryName: 'gobuster',
    description: 'Directory / DNS / vhost brute-forcer',
    versionFlag: 'version',
    installMethods: [
      { label: 'go install', command: 'go install -v github.com/OJ/gobuster/v3@latest' },
      { label: 'apt (Kali/Ubuntu)', command: 'sudo apt-get install -y gobuster' },
      { label: 'brew (macOS)', command: 'brew install gobuster' },
    ]
  },
  // --- Vulnerability ---
  {
    name: 'nuclei', category: 'Vulnerability', phase: 4, binaryName: 'nuclei',
    description: 'Template-based vulnerability scanner (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install nuclei' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
      { label: 'curl (Linux amd64)', command: 'curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip' },
      { label: 'brew (macOS)', command: 'brew install nuclei' },
    ]
  },
  {
    name: 'dalfox', category: 'Vulnerability', phase: 4, binaryName: 'dalfox',
    description: 'XSS scanner and parameter analysis',
    versionFlag: 'version',
    installMethods: [
      { label: 'go install', command: 'go install -v github.com/hahwul/dalfox/v2@latest' },
      { label: 'brew (macOS)', command: 'brew install dalfox' },
      { label: 'snap', command: 'sudo snap install dalfox' },
    ]
  },
  {
    name: 'nikto', category: 'Vulnerability', phase: 4, binaryName: 'nikto',
    description: 'Web server vulnerability scanner',
    versionFlag: '-Version',
    installMethods: [
      { label: 'apt (Debian/Ubuntu)', command: 'sudo apt-get install -y nikto' },
      { label: 'brew (macOS)', command: 'brew install nikto' },
    ]
  },
  {
    name: 'interactsh-client', category: 'Vulnerability', phase: 4, binaryName: 'interactsh-client',
    description: 'OOB interaction detection (ProjectDiscovery)',
    versionFlag: '-version',
    installMethods: [
      { label: 'pdtm', command: 'pdtm -install interactsh-client' },
      { label: 'go install', command: 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest' },
    ]
  },
  // --- Exploitation ---
  {
    name: 'sqlmap', category: 'Exploitation', phase: 4, binaryName: 'sqlmap',
    description: 'Automatic SQL injection and database takeover tool',
    versionFlag: '--version',
    installMethods: [
      { label: 'pip', command: 'pip install sqlmap' },
      { label: 'apt (Debian/Ubuntu)', command: 'sudo apt-get install -y sqlmap' },
      { label: 'brew (macOS)', command: 'brew install sqlmap' },
      { label: 'git clone', command: 'git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap' },
    ]
  },
];

// --- Wordlists & Templates (centralized resources) ---
export const RESOURCE_DEFINITIONS: ResourceDefinition[] = [
  {
    name: 'SecLists',
    type: 'wordlist',
    description: 'Collection of security-related fuzzing lists (usernames, passwords, URLs, payloads, web shells, etc.)',
    defaultPath: path.join(WORDLISTS_DIR, 'SecLists'),
    verifyPath: path.join(WORDLISTS_DIR, 'SecLists', 'Discovery'),
    installMethods: [
      { label: 'git clone (latest)', command: `git clone --depth 1 https://github.com/danielmiessler/SecLists.git ${path.join(WORDLISTS_DIR, 'SecLists')}` },
      { label: 'curl + extract', command: `mkdir -p ${WORDLISTS_DIR} && curl -sL https://github.com/danielmiessler/SecLists/archive/refs/heads/master.tar.gz | tar xz -C ${WORDLISTS_DIR} && mv ${path.join(WORDLISTS_DIR, 'SecLists-master')} ${path.join(WORDLISTS_DIR, 'SecLists')}` },
      { label: 'apt (Kali)', command: 'sudo apt-get install -y seclists' },
    ]
  },
  {
    name: 'Nuclei Templates',
    type: 'templates',
    description: 'Community-curated vulnerability templates for Nuclei scanner',
    defaultPath: path.join(TEMPLATES_DIR, 'nuclei-templates'),
    verifyPath: path.join(TEMPLATES_DIR, 'nuclei-templates', 'http'),
    installMethods: [
      { label: 'nuclei -update-templates', command: `nuclei -update-templates -td ${path.join(TEMPLATES_DIR, 'nuclei-templates')}` },
      { label: 'git clone (latest)', command: `git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ${path.join(TEMPLATES_DIR, 'nuclei-templates')}` },
      { label: 'curl + extract', command: `mkdir -p ${TEMPLATES_DIR} && curl -sL https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz | tar xz -C ${TEMPLATES_DIR} && mv ${path.join(TEMPLATES_DIR, 'nuclei-templates-main')} ${path.join(TEMPLATES_DIR, 'nuclei-templates')}` },
    ]
  },
  {
    name: 'Fuzzing Templates',
    type: 'templates',
    description: 'Nuclei fuzzing templates for web vulnerability discovery',
    defaultPath: path.join(TEMPLATES_DIR, 'fuzzing-templates'),
    verifyPath: path.join(TEMPLATES_DIR, 'fuzzing-templates'),
    installMethods: [
      { label: 'git clone (latest)', command: `git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git ${path.join(TEMPLATES_DIR, 'fuzzing-templates')}` },
    ]
  },
  {
    name: 'PayloadsAllTheThings',
    type: 'wordlist',
    description: 'Comprehensive payload collection for web security testing',
    defaultPath: path.join(WORDLISTS_DIR, 'PayloadsAllTheThings'),
    verifyPath: path.join(WORDLISTS_DIR, 'PayloadsAllTheThings', 'SQL Injection'),
    installMethods: [
      { label: 'git clone (latest)', command: `git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ${path.join(WORDLISTS_DIR, 'PayloadsAllTheThings')}` },
    ]
  },
];

export class ToolManager {
  private static statusCache: Record<string, { method: ExecutionMethod; version?: string }> = {};

  static getToolsHome() { return TOOLS_HOME; }
  static getWordlistsDir() { return WORDLISTS_DIR; }
  static getTemplatesDir() { return TEMPLATES_DIR; }

  static async getToolStatus(toolName: string): Promise<{ method: ExecutionMethod; version?: string }> {
    if (this.statusCache[toolName]) return this.statusCache[toolName];

    const def = TOOL_DEFINITIONS.find(t => t.name === toolName);
    if (!def) return { method: 'UNAVAILABLE' };

    // 1. Check for system binary and get version
    try {
      const { stdout: whichOut } = await execAsync(`which ${def.binaryName}`);
      if (whichOut.trim()) {
        let version: string | undefined;
        try {
          const { stdout, stderr } = await execAsync(`${def.binaryName} ${def.versionFlag} 2>&1`, { timeout: 5000 });
          const raw = (stdout || stderr).trim();
          const vMatch = raw.match(/v?(\d+\.\d+[\.\d]*)/);
          version = vMatch ? vMatch[1] : raw.substring(0, 60);
        } catch { /* version detection failed, tool still exists */ }
        const result = { method: 'BINARY' as ExecutionMethod, version };
        this.statusCache[toolName] = result;
        return result;
      }
    } catch {
      // not found via which
    }

    // 2. Check ~/go/bin (common go install location)
    try {
      const goPath = path.join(process.env.HOME || '/root', 'go', 'bin', def.binaryName);
      await execAsync(`test -x ${goPath}`);
      let version: string | undefined;
      try {
        const { stdout } = await execAsync(`${goPath} ${def.versionFlag} 2>&1`, { timeout: 5000 });
        const vMatch = stdout.match(/v?(\d+\.\d+[\.\d]*)/);
        version = vMatch ? vMatch[1] : undefined;
      } catch {}
      const result = { method: 'BINARY' as ExecutionMethod, version };
      this.statusCache[toolName] = result;
      return result;
    } catch {}

    // 3. NPX fallback
    if (def.npxPackage) {
      return { method: 'NPX' };
    }

    // 4. Polyfill fallback
    return { method: 'POLYFILL' };
  }

  static async getAllStatus() {
    const results = [];
    for (const def of TOOL_DEFINITIONS) {
      const status = await this.getToolStatus(def.name);
      results.push({
        name: def.name,
        category: def.category,
        phase: `Phase ${def.phase}`,
        description: def.description,
        status: status.method === 'BINARY' ? 'installed' : status.method === 'UNAVAILABLE' ? 'missing' : 'fallback',
        method: status.method,
        version: status.version || null,
        installMethods: def.installMethods
      });
    }
    return results;
  }

  static clearCache() { this.statusCache = {}; }

  // --- Resource (Wordlist / Template) status ---
  static async getResourceStatus() {
    const results = [];
    for (const res of RESOURCE_DEFINITIONS) {
      const installed = existsSync(res.verifyPath);
      let size: string | null = null;
      if (installed) {
        try {
          const { stdout } = await execAsync(`du -sh ${res.defaultPath} 2>/dev/null`);
          size = stdout.split('\t')[0]?.trim() || null;
        } catch {}
      }
      results.push({
        name: res.name,
        type: res.type,
        description: res.description,
        installed,
        path: res.defaultPath,
        size,
        installMethods: res.installMethods,
      });
    }
    return results;
  }

  static async getResourceContents(resourceName: string, subpath?: string): Promise<string[]> {
    const res = RESOURCE_DEFINITIONS.find(r => r.name === resourceName);
    if (!res) return [];
    const target = subpath ? path.join(res.defaultPath, subpath) : res.defaultPath;
    if (!existsSync(target)) return [];
    try {
      const entries = await readdir(target, { withFileTypes: true });
      return entries.map(e => (e.isDirectory() ? `${e.name}/` : e.name)).sort();
    } catch { return []; }
  }

  // --- Install tool or resource ---
  static async installTool(toolName: string, methodIndex: number): Promise<{ success: boolean; output: string }> {
    const def = TOOL_DEFINITIONS.find(t => t.name === toolName);
    if (!def) return { success: false, output: `Unknown tool: ${toolName}` };
    const method = def.installMethods[methodIndex];
    if (!method) return { success: false, output: `Invalid install method index: ${methodIndex}` };

    try {
      const { stdout, stderr } = await execAsync(method.command, { timeout: 300_000 });
      this.clearCache();
      return { success: true, output: (stdout + '\n' + stderr).trim() };
    } catch (err: any) {
      return { success: false, output: err.message || 'Install failed' };
    }
  }

  static async installResource(resourceName: string, methodIndex: number): Promise<{ success: boolean; output: string }> {
    const res = RESOURCE_DEFINITIONS.find(r => r.name === resourceName);
    if (!res) return { success: false, output: `Unknown resource: ${resourceName}` };
    const method = res.installMethods[methodIndex];
    if (!method) return { success: false, output: `Invalid install method index: ${methodIndex}` };

    // ensure parent dirs exist
    const parentDir = path.dirname(res.defaultPath);
    if (!existsSync(parentDir)) mkdirSync(parentDir, { recursive: true });

    try {
      const { stdout, stderr } = await execAsync(method.command, { timeout: 600_000 });
      return { success: true, output: (stdout + '\n' + stderr).trim() };
    } catch (err: any) {
      return { success: false, output: err.message || 'Install failed' };
    }
  }

  // --- Install ALL missing tools via pdtm (batch) ---
  static async pdtmInstallAll(): Promise<{ success: boolean; output: string }> {
    const pdtmStatus = await this.getToolStatus('pdtm');
    if (pdtmStatus.method !== 'BINARY') {
      return { success: false, output: 'pdtm is not installed. Install pdtm first to batch-install ProjectDiscovery tools.' };
    }

    const pdTools = TOOL_DEFINITIONS.filter(t =>
      t.installMethods.some(m => m.label === 'pdtm') && t.name !== 'pdtm'
    );

    const results: string[] = [];
    for (const tool of pdTools) {
      const status = await this.getToolStatus(tool.name);
      if (status.method === 'BINARY') continue;
      try {
        const { stdout, stderr } = await execAsync(`pdtm -install ${tool.name}`, { timeout: 120_000 });
        results.push(`${tool.name}: OK`);
      } catch (err: any) {
        results.push(`${tool.name}: FAILED — ${err.message}`);
      }
    }

    this.clearCache();
    return { success: true, output: results.length > 0 ? results.join('\n') : 'All ProjectDiscovery tools already installed.' };
  }

  /**
   * Orchestrates tool execution based on availability
   */
  static async execute(toolName: string, args: string[], jobId: string, polyfillFn?: () => Promise<any>): Promise<any> {
    const status = await this.getToolStatus(toolName);
    const def = TOOL_DEFINITIONS.find(t => t.name === toolName)!;

    const timeoutMs = TOOL_TIMEOUTS_MS[toolName] ?? 60_000;

    if (status.method === 'BINARY') {
      console.log(`[Job ${jobId}] Executing ${toolName} via BINARY (timeout ${timeoutMs}ms)`);
      const result = await spawnAsync(def.binaryName, args, { timeoutMs });
      if (result.timedOut && polyfillFn) {
        console.log(`[Job ${jobId}] ${toolName} timed out — falling back to polyfill`);
        return await polyfillFn();
      }
      return result;
    }

    if (status.method === 'NPX' && def.npxPackage) {
      console.log(`[Job ${jobId}] Executing ${toolName} via NPX (timeout ${timeoutMs}ms)`);
      const result = await spawnAsync('npx', ['-y', def.npxPackage, ...args], { timeoutMs });
      if (result.timedOut && polyfillFn) {
        console.log(`[Job ${jobId}] ${toolName} (npx) timed out — falling back to polyfill`);
        return await polyfillFn();
      }
      return result;
    }

    if (status.method === 'POLYFILL' && polyfillFn) {
      console.log(`[Job ${jobId}] Executing ${toolName} via POLYFILL`);
      return await polyfillFn();
    }

    throw new Error(`Tool ${toolName} is unavailable and no polyfill provided.`);
  }

  // --- Polyfill Implementations ---

  static async polyfillPortScan(hostname: string, ports: number[]) {
    const open: number[] = [];
    for (const port of ports) {
      try {
        const status = await portscanner.checkPortStatus(port, hostname);
        if (status === 'open') open.push(port);
      } catch (e) {}
    }
    return { stdout: `Open ports on ${hostname}: ${open.join(', ')}`, stderr: '' };
  }

  /**
   * Brute-force subdomain discovery using SecLists prefixes (top-5,000 by
   * default, capped at `max`). Resolution is DNS-only (no HTTP probe per
   * candidate) so 5,000 candidates clear in ~30s on a residential link
   * instead of hours. Wildcard-DNS hosts short-circuit before any work.
   */
  static async polyfillSubdomainDiscovery(hostname: string, max = 500) {
    // Wildcard sentinel: if a random subdomain resolves, the host is wildcard
    // and brute-forcing yields garbage — skip.
    const wildcardSub = `wildcard-check-${Math.random().toString(36).substring(7)}.${hostname}`;
    try {
      const records = await dns.resolve4(wildcardSub);
      if (records && records.length > 0) {
        return { stdout: '', stderr: 'Wildcard DNS detected. Skipping brute-force subdomain discovery.' };
      }
    } catch {
      // expected: random subdomain should NXDOMAIN
    }

    const prefixes = getSubdomains(max);
    const concurrency = 50;
    const discovered: string[] = [];

    for (let i = 0; i < prefixes.length; i += concurrency) {
      const slice = prefixes.slice(i, i + concurrency);
      const results = await Promise.all(slice.map(async (sub) => {
        const fqdn = `${sub}.${hostname}`;
        try {
          const records = await dns.resolve4(fqdn);
          return records && records.length > 0 ? fqdn : null;
        } catch {
          return null;
        }
      }));
      for (const r of results) if (r) discovered.push(r);
    }

    return { stdout: discovered.join('\n'), stderr: '' };
  }

  /**
   * HTTP path enumeration polyfill backed by SecLists common.txt.
   *
   * Handles three wildcard patterns:
   * - **200 wildcard**: every unknown path returns 200 with the same body (classic).
   * - **302 SPA catch-all**: every unknown path 302-redirects to the same Location
   *   (React/Vue/Angular SPAs that let the client-side router handle all paths).
   * - **403 WAF blanket**: every unknown path returns 403 (Akamai/Cloudflare
   *   blocking by default; no path-specific signal).
   */
  static async polyfillPathEnumeration(origin: string, max = 250) {
    const paths = getCommonPaths(max);
    const concurrency = 20;
    const discovered: { url: string; status: number; bodyLen: number }[] = [];

    // Probe a random path to detect wildcard behavior
    let wildcardBody: string | null = null;
    let wildcardRedirect: string | null = null;
    let wildcardStatus: number | null = null;
    try {
      const probe = await axios.get(
        `${origin}/__levarg_wildcard_${Math.random().toString(36).slice(2, 10)}`,
        { timeout: 4000, validateStatus: () => true, maxRedirects: 0 }
      );
      wildcardStatus = probe.status;
      if (probe.status === 200) {
        const body = typeof probe.data === 'string' ? probe.data : JSON.stringify(probe.data ?? '');
        wildcardBody = body.slice(0, 2000);
      } else if (probe.status >= 300 && probe.status < 400) {
        wildcardRedirect = String(probe.headers['location'] || '');
      }
    } catch { /* origin may be unreachable; skip */ }

    for (let i = 0; i < paths.length; i += concurrency) {
      const slice = paths.slice(i, i + concurrency);
      const results = await Promise.all(slice.map(async (p) => {
        const url = `${origin}/${p.replace(/^\//, '')}`;
        try {
          const res = await axios.get(url, { timeout: 4000, validateStatus: () => true, maxRedirects: 0 });
          const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '');

          if (res.status === 404) return null;

          // 200 wildcard: same body as canary
          if (wildcardBody && res.status === 200 && body.slice(0, 2000) === wildcardBody) return null;

          // SPA catch-all: same redirect target as canary
          if (wildcardRedirect && res.status >= 300 && res.status < 400) {
            const loc = String(res.headers['location'] || '');
            if (loc === wildcardRedirect) return null;
          }

          // WAF blanket block: canary got the same status with no distinguishing info
          if (wildcardStatus === res.status && (res.status === 403 || res.status === 401)) return null;

          return { url, status: res.status, bodyLen: body.length };
        } catch {
          return null;
        }
      }));
      for (const r of results) if (r) discovered.push(r);
    }

    const warnings: string[] = [];
    if (wildcardBody) warnings.push('Wildcard 200 detected; canary-filtered.');
    if (wildcardRedirect) warnings.push(`SPA catch-all detected (302 → ${wildcardRedirect}); redirect-filtered.`);
    if (wildcardStatus === 403) warnings.push('WAF blanket 403 detected; 403s filtered.');

    const ndjson = discovered.map(d => JSON.stringify(d)).join('\n');
    return { stdout: ndjson, stderr: warnings.join(' ') };
  }

  static async polyfillWhatWeb(url: string) {
    const fingerprint = await StackGapAnalyzer.fingerprint(url);
    const output = Object.entries(fingerprint)
      .map(([key, value]) => {
        if (Array.isArray(value)) {
          return `${key.toUpperCase()}: ${value.join(', ')}`;
        }
        return `${key.toUpperCase()}: ${value}`;
      })
      .join('\n');
    return { stdout: output, stderr: '' };
  }

  static async polyfillHttpx(url: string) {
    try {
      const res = await axios.get(url, { 
        maxRedirects: 5, 
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' }
      });
      
      const title = (res.data.match(/<title>(.*?)<\/title>/i) || [])[1] || 'No Title';
      const tech = await StackGapAnalyzer.fingerprint(url);
      
      const result = {
        timestamp: new Date().toISOString(),
        hash: Math.random().toString(36).substring(7),
        port: new URL(url).port || (url.startsWith('https') ? '443' : '80'),
        url: url,
        input: url,
        title: title,
        scheme: new URL(url).protocol.replace(':', ''),
        webserver: res.headers['server'] || 'unknown',
        content_type: res.headers['content-type'],
        method: 'GET',
        status_code: res.status,
        content_length: JSON.stringify(res.data).length,
        tech: Object.values(tech).flat().filter(v => v !== 'Unknown' && v !== 'None detected'),
        chain: res.request?._redirectable?._redirectCount > 0 ? 'Redirected' : 'Direct'
      };
      
      return { stdout: JSON.stringify(result, null, 2), stderr: '' };
    } catch (e: any) {
      return { stdout: '', stderr: e.message };
    }
  }
}

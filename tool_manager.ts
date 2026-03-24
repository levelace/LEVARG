import { exec } from 'child_process';
import { promisify } from 'util';
import portscanner from 'portscanner';
import axios from 'axios';
import { StackGapAnalyzer } from './stack_gap_analyzer.js';

const execAsync = promisify(exec);

export type ToolCategory = 'Recon' | 'Fingerprinting' | 'Discovery' | 'Vulnerability' | 'Exploitation';
export type ExecutionMethod = 'BINARY' | 'NPX' | 'POLYFILL' | 'UNAVAILABLE';

interface ToolDefinition {
  name: string;
  category: ToolCategory;
  phase: number;
  binaryName: string;
  npxPackage?: string;
  description: string;
}

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  { name: 'nmap', category: 'Recon', phase: 1, binaryName: 'nmap', description: 'Network exploration and port scanning' },
  { name: 'subfinder', category: 'Recon', phase: 1, binaryName: 'subfinder', description: 'Passive subdomain discovery' },
  { name: 'amass', category: 'Recon', phase: 1, binaryName: 'amass', description: 'In-depth attack surface mapping' },
  { name: 'whatweb', category: 'Fingerprinting', phase: 2, binaryName: 'whatweb', description: 'Web technology identifier' },
  { name: 'ffuf', category: 'Discovery', phase: 3, binaryName: 'ffuf', npxPackage: 'ffuf', description: 'Fast web fuzzer' },
  { name: 'dirb', category: 'Discovery', phase: 3, binaryName: 'dirb', description: 'Web content scanner' },
  { name: 'nuclei', category: 'Vulnerability', phase: 4, binaryName: 'nuclei', description: 'Template-based vulnerability scanner' },
  { name: 'sqlmap', category: 'Exploitation', phase: 4, binaryName: 'sqlmap', description: 'Automatic SQL injection tool' },
  { name: 'httpx', category: 'Fingerprinting', phase: 2, binaryName: 'httpx', description: 'Fast and multi-purpose HTTP toolkit' }
];

export class ToolManager {
  private static statusCache: Record<string, { method: ExecutionMethod, version?: string }> = {};

  static async getToolStatus(toolName: string) {
    const def = TOOL_DEFINITIONS.find(t => t.name === toolName);
    if (!def) return { method: 'UNAVAILABLE' as ExecutionMethod };

    // 1. Check for System Binary
    try {
      await execAsync(`which ${def.binaryName}`);
      return { method: 'BINARY' as ExecutionMethod };
    } catch (e) {
      // 2. Check for NPX capability (if defined)
      if (def.npxPackage) {
        return { method: 'NPX' as ExecutionMethod };
      }
      // 3. Fallback to Polyfill (if we have logic for it)
      return { method: 'POLYFILL' as ExecutionMethod };
    }
  }

  static async getAllStatus() {
    const results = [];
    for (const def of TOOL_DEFINITIONS) {
      const status = await this.getToolStatus(def.name);
      results.push({
        name: def.name,
        category: def.category,
        phase: `Phase ${def.phase}`,
        status: status.method !== 'UNAVAILABLE' ? 'available' : 'missing',
        method: status.method
      });
    }
    return results;
  }

  /**
   * Orchestrates tool execution based on availability
   */
  static async execute(toolName: string, args: string, jobId: string, polyfillFn?: () => Promise<any>): Promise<any> {
    const status = await this.getToolStatus(toolName);
    const def = TOOL_DEFINITIONS.find(t => t.name === toolName)!;

    if (status.method === 'BINARY') {
      console.log(`[Job ${jobId}] Executing ${toolName} via BINARY`);
      return await execAsync(`${def.binaryName} ${args}`);
    } 

    if (status.method === 'NPX' && def.npxPackage) {
      console.log(`[Job ${jobId}] Executing ${toolName} via NPX`);
      return await execAsync(`npx -y ${def.npxPackage} ${args}`);
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

  static async polyfillSubdomainDiscovery(hostname: string) {
    // Check for wildcard DNS first
    const wildcardSub = `wildcard-check-${Math.random().toString(36).substring(7)}.${hostname}`;
    let isWildcard = false;
    try {
      // Check both 80 and 443 to be sure
      const port80 = await portscanner.checkPortStatus(80, wildcardSub).catch(() => 'closed');
      const port443 = await portscanner.checkPortStatus(443, wildcardSub).catch(() => 'closed');
      
      if (port80 === 'open' || port443 === 'open') {
        isWildcard = true;
      } else {
        // Fallback to HTTP check
        const res = await axios.get(`http://${wildcardSub}`, { timeout: 2000, validateStatus: () => true }).catch(() => null);
        if (res && res.status !== 404) isWildcard = true;
      }
    } catch (e) {}

    if (isWildcard) {
      return { stdout: '', stderr: 'Wildcard DNS detected. Skipping brute-force subdomain discovery.' };
    }

    const common = ['dev', 'api', 'admin', 'test', 'staging', 'auth', 'git', 'db', 'v1', 'v2', 'web', 'mail', 'ftp', 'ssh', 'vpn', 'cloud', 'shop', 'blog', 'app', 'portal'];
    const discovered: string[] = [];
    for (const sub of common) {
      try {
        const res = await axios.get(`https://${sub}.${hostname}`, { timeout: 1500, validateStatus: () => true });
        if (res.status !== 404) {
          discovered.push(`${sub}.${hostname}`);
        }
      } catch (e) {}
    }
    return { stdout: discovered.join('\n'), stderr: '' };
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

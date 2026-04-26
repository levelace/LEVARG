import { exec, spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import path from 'path';
import axios from 'axios';

const execAsync = promisify(exec);

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.2';
const OLLAMA_HOME = process.env.OLLAMA_HOME || path.join(process.env.HOME || '/root', '.ollama');

export class OllamaManager {
  private static process: ChildProcess | null = null;
  private static managed = false;

  /**
   * Ensures Ollama is installed, running, and has the default model.
   * Called once at app startup — handles everything automatically.
   */
  static async bootstrap(): Promise<void> {
    console.log('[Ollama] Bootstrapping...');

    // 1. Install if missing
    if (!await this.isInstalled()) {
      console.log('[Ollama] Not found — installing...');
      const installed = await this.install();
      if (!installed) {
        console.warn('[Ollama] Installation failed — AI features will be unavailable.');
        return;
      }
    }
    console.log('[Ollama] Binary found.');

    // 2. Start if not already running
    if (!await this.isRunning()) {
      console.log('[Ollama] Not running — starting...');
      await this.start();
      const ready = await this.waitForReady(30);
      if (!ready) {
        console.warn('[Ollama] Failed to start — AI features will be unavailable.');
        return;
      }
    }
    console.log('[Ollama] Server is running.');

    // 3. Pull model if not present
    if (!await this.hasModel(OLLAMA_MODEL)) {
      console.log(`[Ollama] Model "${OLLAMA_MODEL}" not found — pulling (this may take a few minutes)...`);
      await this.pullModel(OLLAMA_MODEL);
    }
    console.log(`[Ollama] Model "${OLLAMA_MODEL}" ready.`);
    console.log('[Ollama] Bootstrap complete — AI features are available.');
  }

  /** Check if the ollama binary exists on the system */
  static async isInstalled(): Promise<boolean> {
    try {
      await execAsync('which ollama');
      return true;
    } catch {
      // Also check common install locations
      const commonPaths = ['/usr/local/bin/ollama', '/usr/bin/ollama', path.join(process.env.HOME || '', 'bin', 'ollama')];
      return commonPaths.some(p => existsSync(p));
    }
  }

  /** Check if the Ollama server is reachable */
  static async isRunning(): Promise<boolean> {
    try {
      await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /** Install Ollama — tries the official install script, with binary fallback */
  static async install(): Promise<boolean> {
    const platform = process.platform;

    // Method 1: Official install script (Linux/macOS)
    if (platform === 'linux' || platform === 'darwin') {
      try {
        console.log('[Ollama] Trying official install script...');
        await execAsync('curl -fsSL https://ollama.com/install.sh | sh', { timeout: 120_000 });
        if (await this.isInstalled()) return true;
      } catch (err: any) {
        console.warn('[Ollama] Install script failed:', err.message);
      }
    }

    // Method 2: Direct binary download (Linux)
    if (platform === 'linux') {
      try {
        const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
        console.log(`[Ollama] Trying direct binary download (linux/${arch})...`);
        await execAsync(
          `curl -fsSL https://ollama.com/download/ollama-linux-${arch} -o /tmp/ollama && chmod +x /tmp/ollama && sudo mv /tmp/ollama /usr/local/bin/ollama`,
          { timeout: 120_000 }
        );
        if (await this.isInstalled()) return true;
      } catch (err: any) {
        console.warn('[Ollama] Binary download failed:', err.message);
      }

      // Method 3: Without sudo
      try {
        const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
        const localBin = path.join(process.env.HOME || '/root', 'bin');
        await execAsync(`mkdir -p ${localBin}`);
        console.log(`[Ollama] Trying user-local install to ${localBin}...`);
        await execAsync(
          `curl -fsSL https://ollama.com/download/ollama-linux-${arch} -o ${localBin}/ollama && chmod +x ${localBin}/ollama`,
          { timeout: 120_000 }
        );
        if (existsSync(`${localBin}/ollama`)) {
          // Add to PATH for this process
          process.env.PATH = `${localBin}:${process.env.PATH}`;
          return true;
        }
      } catch (err: any) {
        console.warn('[Ollama] User-local install failed:', err.message);
      }
    }

    return false;
  }

  /** Start the Ollama server as a managed child process */
  static async start(): Promise<void> {
    if (this.process) return;

    // Find the binary
    let binary = 'ollama';
    try {
      const { stdout } = await execAsync('which ollama');
      binary = stdout.trim();
    } catch {
      const localBin = path.join(process.env.HOME || '/root', 'bin', 'ollama');
      if (existsSync(localBin)) binary = localBin;
    }

    this.process = spawn(binary, ['serve'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, OLLAMA_HOST: new URL(OLLAMA_URL).host, OLLAMA_MODELS: path.join(OLLAMA_HOME, 'models') },
      detached: false,
    });

    this.managed = true;

    this.process.stdout?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.log(`[Ollama] ${msg}`);
    });

    this.process.stderr?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg && !msg.includes('level=INFO')) console.error(`[Ollama] ${msg}`);
    });

    this.process.on('exit', (code) => {
      console.log(`[Ollama] Process exited with code ${code}`);
      this.process = null;
    });
  }

  /** Wait for the Ollama server to become ready */
  static async waitForReady(timeoutSec: number): Promise<boolean> {
    const deadline = Date.now() + timeoutSec * 1000;
    while (Date.now() < deadline) {
      if (await this.isRunning()) return true;
      await new Promise(r => setTimeout(r, 1000));
    }
    return false;
  }

  /** Check if a specific model is available locally */
  static async hasModel(model: string): Promise<boolean> {
    try {
      const res = await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: 5000 });
      const models: { name: string }[] = res.data?.models || [];
      return models.some(m => m.name === model || m.name.startsWith(`${model}:`));
    } catch {
      return false;
    }
  }

  /** Pull a model from the Ollama registry */
  static async pullModel(model: string): Promise<boolean> {
    try {
      // Use the API endpoint — streams progress
      const res = await axios.post(`${OLLAMA_URL}/api/pull`, { name: model, stream: false }, { timeout: 600_000 });
      if (res.data?.status === 'success' || res.status === 200) {
        console.log(`[Ollama] Model "${model}" pulled successfully.`);
        return true;
      }
      return false;
    } catch (err: any) {
      console.warn(`[Ollama] Failed to pull model "${model}":`, err.message);
      // Fallback: try CLI
      try {
        await execAsync(`ollama pull ${model}`, { timeout: 600_000 });
        return true;
      } catch {
        return false;
      }
    }
  }

  /** Gracefully shut down the managed Ollama process */
  static shutdown(): void {
    if (this.process && this.managed) {
      console.log('[Ollama] Shutting down managed server...');
      this.process.kill('SIGTERM');
      this.process = null;
    }
  }
}

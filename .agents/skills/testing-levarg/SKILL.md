# Testing LEVARG

LEVARG is an autonomous security orchestration platform for web reconnaissance and vulnerability research. It runs as a Node.js app with a Vite frontend and Express backend.

## Dev Server Setup

```bash
cd /home/ubuntu/repos/LEVARG
npm install
npm run dev
```

The app runs on `http://localhost:3000`. The Vite dev server proxies `/api/*` requests to the Express backend (port 3001).

The database file (`pocforge.db`) is created automatically in the project directory on first run.

## Key Testing Areas

### 1. Scope Enforcement (Critical for Blue Team)
- Navigate to **Scope Control** in the sidebar
- Add domains to the approved list (e.g., `example.com`, `tiktok.com`)
- Test out-of-scope blocking: Set Fuzzing Scanner target to an unapproved domain → should see "Target domain not in scope" error
- Test in-scope acceptance: Set target to an approved domain → scan should run normally
- Scope enforcement applies to both `/api/scans` (Fuzzing Scanner) and `/api/flows/:id/run` (Auto-Hunter)

### 2. Arsenal Tool Statuses
- Navigate to **Arsenal** in the sidebar
- Tools with polyfill implementations should show **POLYFILL** (amber badge): `nmap`, `subfinder`, `whatweb`, `httpx`
- Tools without implementations should show **UNAVAILABLE** (red badge): `amass`, `dirb`, `nuclei`, `sqlmap`
- This is controlled by `tool_manager.ts` — the `polyfillTools` whitelist determines which tools get POLYFILL status

### 3. Request Lab
- Navigate to **Request Lab** in the sidebar
- Enter a URL and click **Execute** to send an HTTP request
- After receiving a response, the **AI Analyze** button appears in the header
- Without a `GEMINI_API_KEY` environment variable, clicking AI Analyze should return: `"AI analysis unavailable — no API key configured"`
- **Known limitation**: Very large response bodies (e.g., full HTML pages from sites like TikTok) may cause a JSON parse error in the UI when clicking AI Analyze. The backend endpoint works correctly — verify via browser console: `fetch('/api/ai/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({status:200,headers:{},body:'test'})}).then(r=>r.text()).then(console.log)`

### 4. Fuzzing Scanner
- Navigate to **Fuzzing Scanner** in the sidebar
- Requires at least one payload set — create via API if none exist: `curl -X POST http://localhost:3000/api/payloads -H 'Content-Type: application/json' -d '{"name":"test-xss","payloads":["<script>alert(1)</script>"]}'`
- Use `§FUZZ§` markers in the target URL for injection points (e.g., `https://example.com/?id=§FUZZ§`)
- The `§` character may be difficult to type via GUI — use browser console to set the input value programmatically if needed

### 5. Dashboard
- Basic smoke test — navigate to **Dashboard** and verify metric cards load without errors

## Testing Tips

- The Fuzzing Scanner's scope check happens server-side on `/api/scans` POST. If the UI appears to hang after clicking Start Scan, check browser console for the error response.
- When testing AI analysis, prefer using endpoints that return small JSON responses (like `httpbin.org/get`) rather than full HTML pages to avoid payload size issues.
- Payload sets must exist before the Fuzzing Scanner's Start Scan button is enabled. The dropdown will be empty if no payload sets have been created.
- The `§` (section sign) character used for FUZZ markers can be set programmatically via browser console if keyboard input doesn't work.

## Devin Secrets Needed

- `GEMINI_API_KEY` (optional) — Required for AI analysis to return actual results instead of the 503 "no API key" error. Without it, the error handling path is tested instead.

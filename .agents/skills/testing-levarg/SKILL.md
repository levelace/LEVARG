# Testing LevarG — Security Arsenal, Tool Detection & Ollama

## Overview
LevarG is a security testing platform with a React frontend (Vite) and Express backend (tsx). Key testable features:
- **Security Arsenal UI** — 20+ security tools with version detection, status badges, and multi-method install dropdowns
- **Resources Tab** — SecLists, Nuclei Templates, Fuzzing Templates, PayloadsAllTheThings with install options
- **Ollama Integration** — Auto-install, start, pull model on app boot with graceful degradation
- **API Endpoints** — `/api/tools/status`, `/api/resources/status`, `/api/tools/install`, `/api/resources/install`

## How to Start the App
```bash
cd /home/ubuntu/levarg
npm install
npm run dev  # starts on http://localhost:3000
```

The server output will show Ollama bootstrap logs. If Ollama is not available, the app will print `[Ollama] Installation failed — AI features will be unavailable.` and continue running — this is expected graceful degradation.

## Navigation
- The app has a left sidebar with navigation items
- **Arsenal** (sidebar item) → opens the Security Arsenal / Tools page
- The Tools page has two tabs: **Tools** (default) and **Wordlists & Templates**
- There is a **Refresh** button in the top-right of the Arsenal area

## Key UI Elements to Test

### Tools Tab
- Header shows "Security Arsenal" with "X/Y TOOLS INSTALLED" counter
- Tool cards in a grid layout, each showing: name, description, category badge, phase badge, status badge
- Status badges: green "INSTALLED" (with version), amber "POLYFILL" (fallback), blue "NPX" (npm fallback)
- Clicking "Install" on a card expands a dropdown with multiple install methods (e.g., go install, curl for various OS/arch)
- If pdtm is installed, a batch install bar appears at the top

### Resources Tab
- Shows 4 resources: SecLists, Nuclei Templates, Fuzzing Templates, PayloadsAllTheThings
- Each shows installed/not-installed status with install method buttons
- Resources are stored under `~/.levarg/` directory

### Ollama Bootstrap
- Check server console for `[Ollama] Bootstrapping...` messages
- On a machine with internet access, expect: install → start → pull model → `[Ollama] Bootstrap complete`
- On restricted networks, expect graceful degradation with `[Ollama] Installation failed` message
- The app should remain fully functional regardless of Ollama availability

## API Endpoints for Verification
```bash
curl -s http://localhost:3000/api/tools/status | python3 -m json.tool | head -20
curl -s http://localhost:3000/api/resources/status | python3 -m json.tool
curl -s http://localhost:3000/health  # should return "OK"
```

## Common Issues
- **Ollama download 404**: On VMs or restricted networks, Ollama binary downloads may fail. This is expected — the app gracefully degrades.
- **All tools show as POLYFILL/NPX**: If no security tools (nmap, subfinder, etc.) are installed on the machine, all tools will show fallback status. Install some tools (e.g., `sudo apt install nmap`) to verify the "installed" status badge with version numbers.
- **Counter shows 0/20**: Normal if no tools are installed on the test environment.

## Lint & Build Commands
```bash
npm run lint   # tsc --noEmit
npm run build  # vite build + esbuild server.ts
```

## Devin Secrets Needed
None — the app runs entirely locally with no API keys required (Ollama is local LLM inference).

# LevarG (LEVELACE SENTINEL LLC) — Local Setup Guide

## Quick Start (one command)

```bash
chmod +x setup.sh && ./setup.sh
```

This auto-installs **everything**: Node.js, Go, Ollama + model, pdtm, all security tools, SecLists, Nuclei Templates, and npm dependencies. Works on Linux and macOS.

## Manual Install

### Requirements

- **Node.js 20.x LTS** (also works on 22.x / 24.x). Pinned via `.nvmrc`.
- On macOS / Linux: no extra build tools are needed — `better-sqlite3` ships prebuilt binaries for Node 20/22/23/24/25.
- On Windows: prebuilt binaries are also shipped for the Node versions above; no Visual Studio / `windows-build-tools` required.

### Steps

```bash
nvm install   # picks up .nvmrc → Node 20
npm install
```

If you see a `better-sqlite3` / `node-gyp` compile error, you're almost certainly on a Node version without a matching prebuild. Fix by switching to the pinned version:

```bash
nvm use 20
rm -rf node_modules package-lock.json
npm install
```

## AI Analysis (Ollama — free, local, no API key)

AI-powered features (payload generation, response analysis, autonomous hunting) run through [Ollama](https://ollama.com), a local LLM runner — **no API keys or cloud accounts needed**.

```bash
# 1. Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh   # Linux / macOS
# Windows: download from https://ollama.com/download

# 2. Pull a model (one-time)
ollama pull llama3.2       # fast, ~2 GB — good default
# ollama pull mistral      # alternative: better quality, ~4 GB

# 3. Make sure Ollama is running before starting LevarG
ollama serve               # starts on http://localhost:11434
```

You can override the model or URL in a `.env` file (see `.env.example`).

## Run

```bash
npm run dev      # dev server with vite middleware, tsx runtime on port 3000
npm run lint     # tsc --noEmit
npm run build    # vite build + esbuild bundle of server.ts to dist/
npm start        # run the production bundle
```

---
*LEVELACE SENTINEL LLC — Handle: argila | HackerOne | Social: JUSCLICK-TEQIQ*

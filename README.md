# LevarG (LEVELACE SENTINEL LLC) — Local Setup Guide

## Requirements

- **Node.js 20.x LTS** (also works on 22.x / 24.x). Pinned via `.nvmrc`.
- On macOS / Linux: no extra build tools are needed — `better-sqlite3` ships prebuilt binaries for Node 20/22/23/24/25.
- On Windows: prebuilt binaries are also shipped for the Node versions above; no Visual Studio / `windows-build-tools` required.

## Install

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

## Run

```bash
npm run dev      # dev server with vite middleware, tsx runtime on port 3000
npm run lint     # tsc --noEmit
npm run build    # vite build + esbuild bundle of server.ts to dist/
npm start        # run the production bundle
```

---
*LEVELACE SENTINEL LLC — Handle: argila | HackerOne | Social: JUSCLICK-TEQIQ*

# Testing LEVARG locally

## What this app is

LEVARG is a React (Vite) + Express + SQLite SPA. The server bundles the frontend via a Vite middleware on `http://localhost:3000` and persists state in a local SQLite file (`pocforge.db`) through `better-sqlite3`. There is no remote staging / preview — all testing is local.

## Scope guardrails (IMPORTANT)

The repo contains offensive-security tooling (fuzzing scanner, payload banks with WAF-bypass tiers, stealth Puppeteer, Gemini-backed payload mutation, automation dashboard). When testing a PR:

- **Only test the surface area the PR actually changes.** Build fixes / UI changes / DB schema changes can be verified through the Scope Control view and the `/health` + `/api/scopes` endpoints — there is no need to click into `Fuzzing Scanner`, `Auto-Hunter`, `Stack Gap Analyzer`, `Recon Engine`, or `Payloads` to prove a build/lint/typing PR is working.
- **Do not trigger any scan, recon, or automation job** against any host. Those flows are out of scope of what should be exercised from an agent.
- The `Dashboard → Live Network Activity` widget makes its own outbound request to `https://www.google.com` on load. That is pre-existing behaviour, not something a typical PR introduces — worth noting in a report, not worth blocking on.

## Setup

Node is pinned via `.nvmrc` (20). Node 22 on the base Devin image also works because `better-sqlite3` 12.x ships prebuilts for 20/22/23/24/25.

```bash
cd /home/ubuntu/repos/LEVARG
rm -rf node_modules package-lock.json   # only if you want to re-verify the install path
npm install
```

If you see `node-gyp` / MSBuild / Visual Studio errors during install, the Node version doesn't have a `better-sqlite3` prebuilt and you need to switch to the pinned version (`nvm use`).

## Commands

| Command | What it does |
|---|---|
| `npm run dev` | tsx + Express on :3000, Vite middleware serves the SPA |
| `npm run lint` | `tsc --noEmit` |
| `npm run build` | Vite build (frontend) + esbuild bundle of `server.ts` → `dist/server.js` |
| `npm start` | Runs the production bundle; requires `npm run build` first |

No test suite is configured in `package.json`.

## Smoke-test recipe (proves the native DB module loaded)

Run these after `npm run dev` is up. All three must succeed, otherwise the `better-sqlite3` native binary didn't load or the schema init in `db.ts` failed:

```bash
# 1. Health endpoint — proves `app.listen` fired (server didn't crash at boot)
curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' http://localhost:3000/health
# expect: 200 2

# 2. DB read — proves better-sqlite3 loaded AND `scopes` table exists
curl -sS http://localhost:3000/api/scopes | jq 'type'
# expect: "array"

# 3. Check dev log for native-load failures
grep -Ei "Cannot find module 'sqlite3'|NODE_MODULE_VERSION|bindings\.node" /tmp/levarg-dev.log
# expect: no matches
```

`db.ts` runs `new Database('pocforge.db')` and `db.exec(<schema>)` at module top-level, and `server.ts` imports it before calling `app.listen`. So if the native module can't load, the server crashes before :3000 opens — "`/health` returns 200" is therefore a tight signal for the whole DB layer.

## UI-level DB round-trip (end-to-end proof)

If a PR touches the DB layer or Express routes, verify with one UI interaction instead of clicking around:

1. Open `http://localhost:3000/` in Chrome.
2. Click `Scope Control` in the sidebar.
3. Type `example.com` into the input, click `Add Domain`.
4. Expect the row to appear under `Approved Domains` with a short ID. Pre-existing frontend polls `/api/scopes` every 5s, so the list refresh is automatic.
5. Confirm via shell: `curl -sS http://localhost:3000/api/scopes | jq` should now return a JSON array containing that row with a UUID `id` and a `created_at` timestamp.

This exercises `INSERT INTO scopes` + `SELECT * FROM scopes` through `better-sqlite3.prepare(...)`, which is the same code path every other view uses.

## Concrete UI assertions for regression checks

- Tab title: `LevarG – Cyber Lab Platform`
- Sidebar `<h1>`: `LEVARG`
- Sidebar nav: 13 buttons — Dashboard, Methodology, Arsenal, Auto-Hunter, Scope Control, Recon Engine, Request Lab, HTTP History, Fuzzing Scanner, Stack Gap Analyzer, Data Encoder, State Engine, Payloads
- Browser devtools console should have no red errors on a fresh load

## Cleanup

```bash
pkill -f "tsx server.ts"       # stop the dev server
rm -f pocforge.db database.sqlite   # optional: wipe local DB between runs
```

## Known pitfalls

- `server.ts` had a historical bug where a full `ScopeManager.tsx` file was concatenated onto it with `--- END OF FILE --- / --- START OF FILE ---` markers, causing 125 `tsc` errors. If lint suddenly explodes with errors from TSX-looking syntax inside `server.ts`, check the file's tail first — it might be the same class of bug again.
- `AxiosHeaderValue` is `string | string[] | number | boolean | AxiosHeaders | null | undefined`. Calling `.includes` / `.toLowerCase` on it directly fails `tsc`; wrap with `String(header ?? '')`.
- Both `better-sqlite3` and `sqlite3` being in `package.json` is a smell — only `better-sqlite3` is imported in-repo; `sqlite3` is the one that tends to fail to build on newer Node and should be removed if it reappears.

## Devin Secrets Needed

None for local smoke testing. The app can use a `GEMINI_API_KEY` env var for payload-generation features in `automation_engine.ts` / `payload_oven.ts`, but those features are out of scope for build/lint/UI testing and should not be exercised from an agent.

# LevarG (LEVELACE SENTINEL LLC) — Local Setup Guide

If you are seeing `npm install` errors on Windows related to `better-sqlite3` or `node-gyp`, follow these steps:

## 0x00 — The Problem
You are likely using **Node.js v25.x** or a non-LTS version. Native modules like `better-sqlite3` require prebuilt binaries that are often not available for bleeding-edge Node versions on Windows, forcing a local C++ compilation which requires Visual Studio.

## 0x01 — The Fix (Recommended)
1.  **Install Node.js 20.x (LTS):** This is the most stable version for security tooling.
2.  **Use NVM:** If you have [nvm-windows](https://github.com/coreybutler/nvm-windows) installed:
    ```powershell
    nvm install 20
    nvm use 20
    ```
3.  **Clean Install:**
    ```powershell
    rm -rf node_modules
    npm install
    ```

## 0x02 — The Fix (Alternative: Build Tools)
If you must use Node 25, you need the C++ build environment:
1.  Open PowerShell as Administrator.
2.  Run: `npm install --global windows-build-tools` (or install "Desktop development with C++" via Visual Studio Installer).

## 0x03 — Running the App
```powershell
npm run dev
```

---
*LEVELACE SENTINEL LLC — Handle: argila | HackerOne | Social: JUSCLICK-TEQIQ*

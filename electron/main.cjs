/**
 * LevarG — Electron main process.
 *
 * Starts the bundled Express server in-process via dynamic import(), then
 * opens the UI in a BrowserWindow.  On quit the server is torn down cleanly.
 *
 * Native modules (better-sqlite3) are rebuilt for Electron's Node ABI
 * automatically by electron-builder during packaging.
 */

const { app, BrowserWindow, shell, dialog } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');

const PORT = 3000;
const SERVER_URL = `http://localhost:${PORT}`;

let mainWindow = null;

// ---------------------------------------------------------------------------
// Paths — resolve correctly whether running from source or packaged app
// ---------------------------------------------------------------------------

function getAppRoot() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'app.asar.unpacked');
  }
  return path.join(__dirname, '..');
}

function getDataDir() {
  if (app.isPackaged) {
    return app.getPath('userData');
  }
  return path.join(__dirname, '..');
}

// ---------------------------------------------------------------------------
// Server lifecycle — in-process via dynamic import
// ---------------------------------------------------------------------------

async function startServer() {
  const dataDir = getDataDir();
  const appRoot = getAppRoot();

  // Ensure the data directory exists
  fs.mkdirSync(dataDir, { recursive: true });

  // Set env vars before importing the server module
  process.env.NODE_ENV = 'production';
  process.env.ELECTRON = '1';
  process.env.LEVARG_DATA_DIR = dataDir;

  // CWD → app root so relative path resolution in server code works
  process.chdir(app.isPackaged ? path.join(process.resourcesPath, 'app') : path.join(__dirname, '..'));

  // Dynamically import the bundled ESM server — this calls startServer()
  // inside server.ts which boots Express on PORT 3000.
  const serverModule = path.join(__dirname, '..', 'dist', 'server.js');
  await import(serverModule);
}

/**
 * Poll the Express /health endpoint until it responds.
 */
function waitForServer(timeoutMs = 30000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const req = http.get(`${SERVER_URL}/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else {
          retry();
        }
      });
      req.on('error', retry);
      req.setTimeout(2000, () => {
        req.destroy();
        retry();
      });
    };
    const retry = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error('Server did not start within timeout'));
      } else {
        setTimeout(check, 500);
      }
    };
    check();
  });
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: 'LevarG',
    icon: path.join(__dirname, 'icon.png'),
    backgroundColor: '#050505',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: true,
  });

  mainWindow.loadURL(SERVER_URL);

  // Open external links in the OS browser, not inside Electron
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://localhost') || url.startsWith(SERVER_URL)) {
      return { action: 'allow' };
    }
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.whenReady().then(async () => {
  try {
    await startServer();
  } catch (err) {
    console.error('[Electron] Server import failed:', err);
    dialog.showErrorBox(
      'LevarG — Server Error',
      `Failed to start the backend server:\n\n${err.message}`,
    );
    app.quit();
    return;
  }

  try {
    await waitForServer();
  } catch (err) {
    dialog.showErrorBox(
      'LevarG — Startup Error',
      'The backend server did not start in time.\n\nCheck the console for errors.',
    );
    app.quit();
    return;
  }

  createWindow();

  app.on('activate', () => {
    // macOS dock re-click
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // On macOS, apps stay in dock until Cmd+Q
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

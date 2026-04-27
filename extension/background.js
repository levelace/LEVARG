// LEVARG OS-Browser Bridge — service worker.
//
// Reads cookies for the active tab's URL via chrome.cookies.getAll() (which
// CAN read HttpOnly cookies, unlike page-level JS / bookmarklets) and POSTs
// them to a LEVARG ingest endpoint keyed by a per-scope token.
//
// All scope enforcement happens server-side in LEVARG: out-of-scope cookie
// hosts are silently dropped at ingest time. The extension's job is just to
// transport whatever cookies it can see for the active tab.

async function getConfig() {
  const cfg = await chrome.storage.local.get(['levargIngestUrl', 'levargToken']);
  return {
    ingestUrl: cfg.levargIngestUrl || '',
    token: cfg.levargToken || '',
  };
}

async function captureForTab(tab) {
  if (!tab || !tab.url) {
    return { ok: false, error: 'No active tab' };
  }
  const { ingestUrl, token } = await getConfig();
  if (!ingestUrl || !token) {
    return { ok: false, error: 'LEVARG extension is not configured. Open options and paste your token + ingest URL.' };
  }

  let url;
  try {
    url = new URL(tab.url);
  } catch {
    return { ok: false, error: 'Active tab URL is invalid' };
  }
  if (!/^https?:$/.test(url.protocol)) {
    return { ok: false, error: `Refusing to capture from non-http(s) tab '${tab.url}'` };
  }

  // Pull cookies for the entire registrable domain so we get cross-subdomain
  // session cookies (login cookies often live on `.example.com`, not the
  // exact subdomain). chrome.cookies.getAll({domain}) does this when given
  // a bare hostname.
  const hostname = url.hostname;
  const parts = hostname.split('.');
  const baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  const cookies = await chrome.cookies.getAll({ domain: baseDomain });

  const body = {
    token,
    sessionName: `os-browser:${hostname}@${new Date().toISOString().replace(/[:.]/g, '-')}`,
    cookies: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      expires: c.expirationDate,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite:
        c.sameSite === 'strict'
          ? 'Strict'
          : c.sameSite === 'lax'
          ? 'Lax'
          : c.sameSite === 'no_restriction'
          ? 'None'
          : 'Unspecified',
    })),
    storage: {},
    userAgent: navigator.userAgent,
  };

  let resp;
  try {
    resp = await fetch(ingestUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return { ok: false, error: `Network error: ${e.message}` };
  }
  let json = {};
  try {
    json = await resp.json();
  } catch {
    json = {};
  }
  if (!resp.ok) {
    return { ok: false, error: json.error || `HTTP ${resp.status}` };
  }
  return {
    ok: true,
    sessionId: json.sessionId,
    accepted: json.accepted,
    droppedOutOfScope: json.droppedOutOfScope,
    droppedHosts: json.droppedHosts,
    capturedTotal: cookies.length,
  };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'capture-active-tab') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const result = await captureForTab(tabs[0]);
      sendResponse(result);
    });
    return true; // async response
  }
  return false;
});

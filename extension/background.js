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

  // Pull every cookie the browser would send when visiting this URL. Using
  // {url} (not {domain}) is what we want here: chrome's cookie store filters
  // by request-relevance, so we transparently get cross-subdomain cookies
  // set on `.example.com` while loading `sub.example.com`, and we don't have
  // to extract a registrable domain ourselves. The naive `parts.slice(-2)`
  // approach we used previously over-captured on multi-part TLDs (.co.uk,
  // .com.au, .co.jp), where `parts.slice(-2)` returns the public suffix and
  // chrome.cookies.getAll({domain: 'co.uk'}) would scrape every .co.uk site
  // in the browser. Server-side scope filtering would still drop those
  // before storage, but they'd needlessly traverse the network.
  const hostname = url.hostname;
  const cookies = await chrome.cookies.getAll({ url: tab.url });

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

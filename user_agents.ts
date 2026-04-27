/**
 * user_agents — curated catalog of real browser User-Agent strings.
 *
 * Real production UA strings for the current major browsers across desktop
 * and mobile platforms (Windows / macOS / Linux / Android / iOS). Useful
 * for:
 *   - authenticated-testing flows where the target's WAF fingerprints the
 *     UA and rejects requests that don't look like a real browser;
 *   - SessionVault overlays that need a UA matching the cookie jar's
 *     origin device (mismatched UA + session is a common bot-detection
 *     signal);
 *   - the auth-flow editor's UA picker, so a replayed login sends the same
 *     UA the operator's normal browser would.
 *
 * Security-tool UA strings (Burp / ZAP / Nuclei / Nessus / Qualys / etc.)
 * are intentionally NOT included — they're aggressively blocklisted by
 * modern WAFs and would only hurt every flow that touches them.
 *
 * All strings here are real, not fabricated — sourced from current public
 * release notes / vendor docs / observed traffic. Versions are pinned to
 * recent stable releases as of the file's last update; bump as needed.
 */

export interface UserAgentEntry {
  id: string;
  label: string;
  platform: string;
  category: 'browser';
  ua: string;
}

export const USER_AGENTS: UserAgentEntry[] = [
  // --- Browsers: Windows ---
  {
    id: 'chrome-win',
    label: 'Chrome 131 on Windows 10/11',
    platform: 'Windows',
    category: 'browser',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  },
  {
    id: 'edge-win',
    label: 'Edge 131 on Windows 10/11',
    platform: 'Windows',
    category: 'browser',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86',
  },
  {
    id: 'firefox-win',
    label: 'Firefox 133 on Windows 10/11',
    platform: 'Windows',
    category: 'browser',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  },

  // --- Browsers: macOS ---
  {
    id: 'safari-mac',
    label: 'Safari 18 on macOS Sequoia (15.1)',
    platform: 'macOS',
    category: 'browser',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
  },
  {
    id: 'chrome-mac',
    label: 'Chrome 131 on macOS Sequoia',
    platform: 'macOS',
    category: 'browser',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  },
  {
    id: 'firefox-mac',
    label: 'Firefox 133 on macOS Sequoia',
    platform: 'macOS',
    category: 'browser',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0',
  },

  // --- Browsers: Linux ---
  {
    id: 'chrome-linux',
    label: 'Chrome 131 on Linux (X11 x86_64)',
    platform: 'Linux',
    category: 'browser',
    ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  },
  {
    id: 'firefox-linux',
    label: 'Firefox 133 on Linux (X11 x86_64)',
    platform: 'Linux',
    category: 'browser',
    ua: 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
  },
  {
    id: 'firefox-ubuntu',
    label: 'Firefox 133 on Ubuntu (X11 x86_64)',
    platform: 'Linux',
    category: 'browser',
    ua: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
  },

  // --- Browsers: Android ---
  {
    id: 'chrome-android',
    label: 'Chrome 131 on Android 14 (Pixel)',
    platform: 'Android',
    category: 'browser',
    ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  },
  {
    id: 'samsung-android',
    label: 'Samsung Internet 26 on Android 14 (Galaxy S24)',
    platform: 'Android',
    category: 'browser',
    ua: 'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
  },
  {
    id: 'firefox-android',
    label: 'Firefox 133 on Android 14',
    platform: 'Android',
    category: 'browser',
    ua: 'Mozilla/5.0 (Android 14; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0',
  },

  // --- Browsers: iOS ---
  {
    id: 'safari-ios',
    label: 'Safari 18 on iPhone (iOS 18.1)',
    platform: 'iOS',
    category: 'browser',
    ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  },
  {
    id: 'safari-ipados',
    label: 'Safari 18 on iPad (iPadOS 18.1)',
    platform: 'iOS',
    category: 'browser',
    ua: 'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  },

];

export function getUserAgent(id: string | null | undefined): string | null {
  if (!id) return null;
  return USER_AGENTS.find((u) => u.id === id)?.ua ?? null;
}

export function pickRandomBrowserUA(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)].ua;
}

/**
 * Default HTTP client identity for Auto-Hunter outbound requests.
 *
 * Real Chrome 131 on Linux x86_64 — UA + matching client-hints + the same
 * Accept / Accept-Language / Accept-Encoding / Sec-Fetch- triple a real
 * Chrome navigation sends. WAFs that fingerprint on header *shape* (not
 * just UA) are common; advertising the right UA but missing Sec-Ch-Ua-*
 * headers is itself a tell. Centralising the identity here keeps every
 * outbound call site consistent and easy to update when Chrome's stable
 * channel rolls forward.
 */
export const DEFAULT_HTTP_IDENTITY = {
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  acceptLanguage: 'en-US,en;q=0.9',
  // Node 11.7+ decompresses gzip / deflate / brotli natively via axios; zstd
  // (Chrome 123+) is omitted because Node lacks runtime support and
  // advertising it would force the server to send bytes we cannot decode.
  acceptEncoding: 'gzip, deflate, br',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  secChUaMobile: '?0',
  secChUaPlatform: '"Linux"',
  secFetchSite: 'none',
  secFetchMode: 'navigate',
  secFetchUser: '?1',
  secFetchDest: 'document',
  upgradeInsecureRequests: '1',
} as const;

/**
 * Header pairs as a flat array of strings — convenient for CLI tools like
 * httpx / nuclei / katana that take repeated `-H "Name: value"` flags.
 */
export function defaultHttpIdentityHeaderArgs(): string[] {
  const id = DEFAULT_HTTP_IDENTITY;
  return [
    '-H', `User-Agent: ${id.userAgent}`,
    '-H', `Accept-Language: ${id.acceptLanguage}`,
    '-H', `Accept-Encoding: ${id.acceptEncoding}`,
    '-H', `Accept: ${id.accept}`,
    '-H', `Sec-Ch-Ua: ${id.secChUa}`,
    '-H', `Sec-Ch-Ua-Mobile: ${id.secChUaMobile}`,
    '-H', `Sec-Ch-Ua-Platform: ${id.secChUaPlatform}`,
    '-H', `Sec-Fetch-Site: ${id.secFetchSite}`,
    '-H', `Sec-Fetch-Mode: ${id.secFetchMode}`,
    '-H', `Sec-Fetch-User: ${id.secFetchUser}`,
    '-H', `Sec-Fetch-Dest: ${id.secFetchDest}`,
    '-H', `Upgrade-Insecure-Requests: ${id.upgradeInsecureRequests}`,
  ];
}

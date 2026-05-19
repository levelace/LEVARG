import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import db from './db.js';
import { SessionVault } from './session_vault.js';

interface GapFinding {
  endpoint: string;
  mutation_type: string;
  baseline_status: number;
  mutated_status: number;
  evidence: string;
  confidence: string;
}

export class StackGapAnalyzer {
  static async fingerprint(url: string) {
    try {
      const res = await axios.get(url, { validateStatus: () => true, timeout: 5000 });
      const headers = res.headers;
      const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');
      
      let cdn = 'Unknown';
      let proxy = 'Unknown';
      let backend = 'Unknown';
      let waf = 'Unknown';
      let language = 'Unknown';
      let framework = 'Unknown';
      let errors: string[] = [];

      // 1. Header Analysis
      const serverHeader = String(headers['server'] ?? '').toLowerCase();
      const poweredBy = String(headers['x-powered-by'] ?? '').toLowerCase();
      const via = String(headers['via'] ?? '').toLowerCase();

      // CDN / WAF / Auth
      if (headers['cf-ray'] || serverHeader.includes('cloudflare')) { cdn = 'Cloudflare'; waf = 'Cloudflare WAF'; }
      else if (headers['x-amz-cf-id'] || via.includes('cloudfront')) cdn = 'AWS CloudFront';
      else if (headers['fastly-client-ip'] || headers['x-fastly-request-id']) cdn = 'Fastly';
      else if (headers['x-akamai-request-id'] || serverHeader.includes('akamai')) cdn = 'Akamai';
      else if (serverHeader.includes('sucuri')) { cdn = 'Sucuri'; waf = 'Sucuri WAF'; }
      else if (serverHeader.includes('imperva') || headers['x-iinfo']) waf = 'Imperva Incapsula';

      // Auth Stack Detection
      if (body.includes('amazoncognito.com') || body.includes('cognito-idp') || body.includes('aws-amplify')) { 
        framework = 'AWS Cognito'; 
        backend = 'AWS Cognito'; 
      }
      if (body.includes('okta.com') || headers['x-okta-request-id'] || body.includes('okta-sign-in')) { 
        framework = 'Okta'; 
        backend = 'Okta'; 
      }
      if (headers['x-shopify-stage'] || body.includes('myshopify.com') || body.includes('shopify-checkout') || body.includes('cdn.shopify.com/s/files')) { 
        framework = 'Shopify'; 
        backend = 'Shopify'; 
      }
      if (body.includes('firebaseapp.com') || body.includes('firebaseio.com') || body.includes('firebase-auth')) {
        framework = 'Firebase';
        backend = 'Firebase';
      }

      // Proxy
      if (serverHeader.includes('nginx')) proxy = 'Nginx';
      else if (serverHeader.includes('envoy')) proxy = 'Envoy';
      else if (serverHeader.includes('haproxy')) proxy = 'HAProxy';
      else if (serverHeader.includes('varnish') || headers['x-varnish']) proxy = 'Varnish Cache';
      else if (serverHeader.includes('apache')) proxy = 'Apache HTTP Server';

      // Backend / Language / Framework from headers
      if (poweredBy) backend = headers['x-powered-by'];
      else if (serverHeader.includes('express')) { backend = 'Express'; language = 'Node.js'; framework = 'Express'; }
      else if (serverHeader.includes('werkzeug')) { backend = 'Werkzeug'; language = 'Python'; framework = 'Flask'; }
      else if (serverHeader.includes('gunicorn')) { backend = 'Gunicorn'; language = 'Python'; }
      else if (serverHeader.includes('tomcat')) { backend = 'Tomcat'; language = 'Java'; }

      if (poweredBy.includes('php')) language = 'PHP';
      else if (poweredBy.includes('asp.net')) { language = 'C#'; framework = 'ASP.NET'; }
      else if (poweredBy.includes('next.js')) { language = 'Node.js'; framework = 'Next.js'; }

      // 2. Cookie Analysis
      const setCookie = headers['set-cookie'] || [];
      const cookies = Array.isArray(setCookie) ? setCookie.join(';') : setCookie;

      if (cookies.includes('__cfduid') || cookies.includes('cf_clearance')) { cdn = 'Cloudflare'; waf = 'Cloudflare WAF'; }
      if (cookies.includes('BIGipServer')) waf = 'F5 BIG-IP';
      if (cookies.includes('JSESSIONID')) { language = 'Java'; backend = backend !== 'Unknown' ? backend : 'Java Servlet Container'; }
      if (cookies.includes('PHPSESSID')) language = 'PHP';
      if (cookies.includes('csrftoken') || cookies.includes('sessionid')) { language = language !== 'Unknown' ? language : 'Python'; framework = framework !== 'Unknown' ? framework : 'Django'; }
      if (cookies.includes('XSRF-TOKEN') && cookies.includes('laravel_session')) { language = 'PHP'; framework = 'Laravel'; }
      if (cookies.includes('connect.sid')) { language = 'Node.js'; framework = 'Express'; }

      // 3. Error Message Analysis in Body
      if (body) {
        if (body.includes('SyntaxError: ') || body.includes('ReferenceError: ') || body.includes('TypeError: ')) {
          errors.push('JavaScript/Node.js Error');
          language = 'Node.js';
        }
        if (body.includes('Traceback (most recent call last):')) {
          errors.push('Python Traceback');
          language = 'Python';
        }
        if (body.includes('java.lang.NullPointerException') || body.includes('at java.base/')) {
          errors.push('Java Exception');
          language = 'Java';
        }
        if (body.includes('Fatal error:') && body.includes('on line')) {
          errors.push('PHP Fatal Error');
          language = 'PHP';
        }
        if (body.includes('ActiveRecord::RecordNotFound')) {
          errors.push('Ruby on Rails Error');
          language = 'Ruby';
          framework = 'Ruby on Rails';
        }
        if (body.includes('SQL syntax') || body.includes('mysql_fetch_array()') || body.includes('MySQL server version for the right syntax')) {
          errors.push('SQL Injection Error (MySQL)');
        }
        if (body.includes('ORA-00933:') || body.includes('Oracle error') || body.includes('TNS:listener does not currently know of service')) {
          errors.push('SQL Injection Error (Oracle)');
        }
        if (body.includes('PostgreSQL query failed:') || body.includes('PSQLException') || body.includes('ERROR: syntax error at or near')) {
          errors.push('SQL Injection Error (PostgreSQL)');
        }
        if (body.includes('Microsoft OLE DB Provider for SQL Server') || body.includes('Unclosed quotation mark after the character string')) {
          errors.push('SQL Injection Error (MSSQL)');
        }
      }

      return { 
        cdn, 
        proxy, 
        backend, 
        waf, 
        language, 
        framework, 
        errors: errors.length > 0 ? errors : ['None detected'] 
      };
    } catch (err) {
      return { 
        cdn: 'Error', 
        proxy: 'Error', 
        backend: 'Error', 
        waf: 'Error', 
        language: 'Error', 
        framework: 'Error', 
        errors: ['Connection failed'] 
      };
    }
  }

  static async analyze(
    url: string,
    method: string = 'GET',
    headers: Record<string, string> = {},
    sessionId?: string,
  ) {
    // Scope Check
    const scopes = db.prepare('SELECT domain FROM scopes').all() as { domain: string }[];
    const isAllowed = scopes.some(s => {
      try {
        const targetHost = new URL(url).hostname;
        return targetHost === s.domain || targetHost.endsWith(`.${s.domain}`);
      } catch (e) {
        return false;
      }
    });
    if (scopes.length > 0 && !isAllowed) {
      throw new Error('Target domain not in scope');
    }

    const findings: GapFinding[] = [];

    // Baseline (session-aware)
    const baseHeaders = SessionVault.applyToHeaders(sessionId, url, headers);
    const baselineRes = await axios({ method, url, headers: baseHeaders, validateStatus: () => true, timeout: 5000 }).catch(() => null);

    if (!baselineRes) return findings;

    const baselineStatus = baselineRes.status;
    const baselineBody = typeof baselineRes.data === 'string' ? baselineRes.data : JSON.stringify(baselineRes.data ?? '');
    const baselineCT = String(baselineRes.headers['content-type'] ?? '').toLowerCase();

    /**
     * Mutation classes:
     * - **escalation**: header/method probes that aim to flip 401/403 → 200.
     *   Only flag if baseline was unauthorized AND mutation returned 200 AND
     *   the body is not the same auth-redirect HTML.
     * - **smuggling**: TE/CL/H2C probes. Only flag if response shape betrays
     *   desync (HTTP/1.x status line embedded in body, multiple Content-Length
     *   headers reflected, or server emits 400/501 with a smuggling-specific
     *   error string).
     * - **normalization**: path-mangled URLs aimed at auth bypass. Only flag
     *   if mutation returns 200 AND base was 401/403/404 AND body is not the
     *   same SPA shell as baseline.
     */
    interface Mutation {
      type: string;
      class: 'escalation' | 'smuggling' | 'normalization' | 'control';
      headers: Record<string, string>;
      url: string;
      method?: string;
      data?: string;
    }

    const mutations: Mutation[] = [
      // Escalation: header tricks for IP/auth bypass
      { type: 'Header: X-Forwarded-For', class: 'escalation', headers: { ...headers, 'X-Forwarded-For': '127.0.0.1' }, url },
      { type: 'Header: X-Original-URL', class: 'escalation', headers: { ...headers, 'X-Original-URL': '/admin' }, url },
      { type: 'Header: X-Rewrite-URL', class: 'escalation', headers: { ...headers, 'X-Rewrite-URL': '/admin' }, url },
      { type: 'Header: X-Forwarded-Host', class: 'escalation', headers: { ...headers, 'X-Forwarded-Host': 'localhost' }, url },

      // Method confusion: only meaningful as escalation
      { type: 'Method: POST', class: 'escalation', headers, url, method: 'POST' },
      { type: 'Method: PUT', class: 'escalation', headers, url, method: 'PUT' },
      { type: 'Method: DELETE', class: 'escalation', headers, url, method: 'DELETE' },

      // H2C smuggling probes
      { type: 'H2C Upgrade', class: 'smuggling', headers: { ...headers, 'Connection': 'Upgrade', 'Upgrade': 'h2c' }, url },
      { type: 'H2C HTTP2-Settings', class: 'smuggling', headers: { ...headers, 'Connection': 'Upgrade', 'Upgrade': 'h2c', 'HTTP2-Settings': 'AAMAAABkAAQAAP__', 'Host': 'localhost' }, url },

      // CL.TE / TE.CL desync probes
      { type: 'Smuggling: CL.TE', class: 'smuggling', headers: { ...headers, 'Content-Length': '4', 'Transfer-Encoding': 'chunked' }, url, method: 'POST', data: '1\r\nZ\r\nQ' },
      { type: 'Smuggling: TE.CL', class: 'smuggling', headers: { ...headers, 'Content-Length': '6', 'Transfer-Encoding': 'chunked' }, url, method: 'POST', data: '0\r\n\r\nX' },
      { type: 'Smuggling: Double-CL', class: 'smuggling', headers: { ...headers, 'Content-Length': '0', 'Content-Length ': '0' }, url, method: 'POST' },
      { type: 'Smuggling: Tab-TE', class: 'smuggling', headers: { ...headers, 'Transfer-Encoding\t': 'chunked' }, url, method: 'POST', data: '0\r\n\r\n' },

      // Normalization bypasses: only meaningful when base was unauthorized
      { type: 'Normalization: /..;/', class: 'normalization', headers, url: url.replace(/(\/[^\/]+)$/, '/..;/admin') },
      { type: 'Normalization: /..%2f', class: 'normalization', headers, url: url.replace(/(\/[^\/]+)$/, '/..%2fadmin') },
      { type: 'Normalization: /%2e%2e%2f', class: 'normalization', headers, url: url.replace(/(\/[^\/]+)$/, '/%2e%2e%2fadmin') },
      { type: 'Normalization: /.;/admin', class: 'normalization', headers, url: url.replace(/(\/[^\/]+)$/, '/.;/admin') },
    ];

    // For normalization probes, also fetch the would-be target URL directly
    // (e.g. /admin without the path-mangling). If the mangled URL returns the
    // same content as a direct /admin GET, the server normalized cleanly —
    // there's no bypass, the server just resolves /..%2fadmin to /admin like
    // any browser. A real bypass means the WAF blocks /admin but lets the
    // mangled form through.
    let directAdminStatus: number | null = null;
    let directAdminBody = '';
    try {
      const adminUrl = new URL(url);
      adminUrl.pathname = '/admin';
      const adminRes = await axios.get(adminUrl.toString(), {
        headers: SessionVault.applyToHeaders(sessionId, adminUrl.toString(), headers),
        validateStatus: () => true,
        timeout: 5000,
      });
      directAdminStatus = adminRes.status;
      directAdminBody = typeof adminRes.data === 'string' ? adminRes.data : JSON.stringify(adminRes.data ?? '');
    } catch { /* skip if /admin probe fails */ }

    /** Snippet that strongly suggests an admin/internal panel was reached. */
    const ADMIN_MARKERS = [
      'admin panel', 'administrator', 'dashboard', 'admin login',
      'sign in to admin', '/wp-admin', 'phpmyadmin', 'adminer',
      'spring boot admin', 'rabbitmq management', 'kibana',
    ];
    /** Indicators of HTTP request smuggling at the proxy/origin boundary. */
    const SMUGGLING_MARKERS = [
      'HTTP/1.1 ', 'HTTP/1.0 ',                        // status line embedded in body
      'invalid chunked encoding', 'malformed chunk',
      'duplicate content-length', 'invalid content-length',
      'Bad chunk', 'transfer-encoding chunked but no chunked encoding',
    ];

    for (const mutation of mutations) {
      try {
        const mHeaders = SessionVault.applyToHeaders(sessionId, mutation.url, mutation.headers);
        const mRes = await axios({
          method: mutation.method || method,
          url: mutation.url,
          headers: mHeaders,
          validateStatus: () => true,
          timeout: 5000,
          data: mutation.data,
        });

        const mStatus = mRes.status;
        const mBody = typeof mRes.data === 'string' ? mRes.data : JSON.stringify(mRes.data ?? '');
        const mCT = String(mRes.headers['content-type'] ?? '').toLowerCase();

        let triggered = false;
        let evidence = '';
        let confidence: 'high' | 'medium' = 'medium';

        if (mutation.class === 'escalation') {
          // Only flag if baseline was 401/403/404 → mutation 200 AND body
          // differs from baseline (not just the same auth-required HTML).
          const escalated = (baselineStatus === 401 || baselineStatus === 403 || baselineStatus === 404)
            && mStatus === 200
            && mBody !== baselineBody;
          if (escalated) {
            const hasAdminSignal = ADMIN_MARKERS.some(m => mBody.toLowerCase().includes(m));
            triggered = true;
            confidence = hasAdminSignal ? 'high' : 'medium';
            evidence = `${baselineStatus} → 200 (${mBody.length} bytes${hasAdminSignal ? ', admin marker present' : ''})`;
          }
        } else if (mutation.class === 'normalization') {
          // Only flag if base was unauthorized AND mutation reached an admin-
          // looking page that the direct /admin probe could NOT reach.
          if ((baselineStatus === 401 || baselineStatus === 403 || baselineStatus === 404) && mStatus === 200) {
            // If a direct /admin probe ALSO returns 200 with the same body,
            // the server simply has /admin open — that's a separate finding
            // (handled by Phase 4b sensitive-files), not a normalization gap.
            const sameAsDirect = directAdminStatus === 200 && mBody === directAdminBody;
            const hasAdminSignal = ADMIN_MARKERS.some(m => mBody.toLowerCase().includes(m));
            if (!sameAsDirect && hasAdminSignal) {
              triggered = true;
              confidence = 'high';
              evidence = `Path-normalization bypass: ${baselineStatus} on ${url} but 200 on ${mutation.url} with admin markers`;
            }
          }
        } else if (mutation.class === 'smuggling') {
          // Need actual evidence of desync, not status change.
          const hasSmugglingMarker = SMUGGLING_MARKERS.some(m => mBody.includes(m));
          // Status line embedded as a substring in HTML body (HTTP/1.1 200 OK)
          // strongly indicates desync. Skip if the response itself is HTML
          // describing HTTP requests (docs pages mention HTTP/1.1).
          const isHtml = mCT.includes('text/html') || baselineCT.includes('text/html');
          const hasEmbeddedStatusLine = isHtml && /HTTP\/1\.[01] \d{3} /.test(mBody) && !baselineBody.includes('HTTP/1.');
          if (hasSmugglingMarker || hasEmbeddedStatusLine) {
            triggered = true;
            confidence = 'high';
            evidence = `Smuggling marker in response: ${SMUGGLING_MARKERS.find(m => mBody.includes(m)) ?? 'embedded HTTP status line'}`;
          }
        }

        if (triggered) {
          const finding: GapFinding = {
            endpoint: url,
            mutation_type: mutation.type,
            baseline_status: baselineStatus,
            mutated_status: mStatus,
            evidence,
            confidence,
          };
          findings.push(finding);
          db.prepare('INSERT INTO stack_gap_findings (id, endpoint, mutation_type, baseline_status, mutated_status, evidence, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(uuidv4(), finding.endpoint, finding.mutation_type, finding.baseline_status, finding.mutated_status, finding.evidence, finding.confidence);
        }
      } catch {
        // Connection / timeout errors on mutations carry no signal
      }
    }

    return findings;
  }
}

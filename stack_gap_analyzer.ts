import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import db from './db.js';

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
      const serverHeader = (headers['server'] || '').toLowerCase();
      const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
      const via = (headers['via'] || '').toLowerCase();

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

  static async analyze(url: string, method: string = 'GET', headers: any = {}) {
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

    // Baseline
    const startTime = Date.now();
    const baselineRes = await axios({ method, url, headers, validateStatus: () => true, timeout: 5000 }).catch(() => null);
    const baselineLatency = Date.now() - startTime;
    
    if (!baselineRes) return findings;

    const baselineStatus = baselineRes.status;
    const baselineLength = JSON.stringify(baselineRes.data).length;

    const mutations = [
      // Header Mutations
      { type: 'Header: X-Forwarded-For', headers: { ...headers, 'X-Forwarded-For': '127.0.0.1' }, url },
      { type: 'Header: X-Original-URL', headers: { ...headers, 'X-Original-URL': '/admin' }, url },
      { type: 'Header: X-Rewrite-URL', headers: { ...headers, 'X-Rewrite-URL': '/admin' }, url },
      { type: 'Header: X-Forwarded-Host', headers: { ...headers, 'X-Forwarded-Host': 'localhost' }, url },
      
      // Parameter Duplication
      { type: 'Param Duplication', headers, url: url.includes('?') ? `${url}&id=1&id=2` : `${url}?id=1&id=2` },
      
      // URL Normalization
      { type: 'URL Normalization: /../', headers, url: url.replace(/(\/[^\/]+)$/, '/../admin') },
      { type: 'URL Normalization: //', headers, url: url.replace(/(\/[^\/]+)$/, '//admin') },
      { type: 'URL Normalization: /%2e/', headers, url: url.replace(/(\/[^\/]+)$/, '/%2e/admin') },
      
      // Encoding Variations
      { type: 'Encoding: %2e', headers, url: url + '%2e' },
      { type: 'Encoding: %252e', headers, url: url + '%252e' },
      { type: 'Encoding: %2f', headers, url: url + '%2f' },
      
      // Method Confusion
      { type: 'Method Confusion: POST', headers, url, method: 'POST' },
      { type: 'Method Confusion: HEAD', headers, url, method: 'HEAD' },
      { type: 'Method Confusion: OPTIONS', headers, url, method: 'OPTIONS' },
      { type: 'Method Confusion: TRACE', headers, url, method: 'TRACE' },
      
      // Content Type Confusion
      { type: 'Content-Type: multipart/form-data', headers: { ...headers, 'Content-Type': 'multipart/form-data' }, url },
      { type: 'Content-Type: text/plain', headers: { ...headers, 'Content-Type': 'text/plain' }, url },

      // H2C Smuggling / Upgrade Mutations
      { type: 'H2C Smuggling: Upgrade', headers: { ...headers, 'Connection': 'Upgrade', 'Upgrade': 'h2c' }, url },
      { type: 'H2C Smuggling: HTTP2-Settings', headers: { ...headers, 'Connection': 'Upgrade', 'Upgrade': 'h2c', 'HTTP2-Settings': 'AAMAAABkAAQAAP__', 'Host': 'localhost' }, url },

      // Chunked Encoding / Transfer-Encoding Mutations (Smuggling Basics)
      { type: 'Transfer-Encoding: chunked', headers: { ...headers, 'Transfer-Encoding': 'chunked' }, url, method: 'POST', data: '0\r\n\r\n' },
      { type: 'Transfer-Encoding: xchunked', headers: { ...headers, 'Transfer-Encoding': 'xchunked' }, url, method: 'POST', data: '0\r\n\r\n' },
      { type: 'Transfer-Encoding: chunked, identity', headers: { ...headers, 'Transfer-Encoding': 'chunked, identity' }, url, method: 'POST', data: '0\r\n\r\n' },

      // CL.TE / TE.CL Desync / Smuggling (Probes)
      { type: 'Smuggling: CL.TE Probe', headers: { ...headers, 'Content-Length': '4', 'Transfer-Encoding': 'chunked' }, url, method: 'POST', data: '1\r\nZ\r\nQ' },
      { type: 'Smuggling: TE.CL Probe', headers: { ...headers, 'Content-Length': '6', 'Transfer-Encoding': 'chunked' }, url, method: 'POST', data: '0\r\n\r\nX' },
      { type: 'Smuggling: Double Content-Length', headers: { ...headers, 'Content-Length': '0', 'Content-Length ': '0' }, url, method: 'POST' },
      { type: 'Smuggling: Tab-Space-TE', headers: { ...headers, 'Transfer-Encoding\t': 'chunked' }, url, method: 'POST', data: '0\r\n\r\n' },

      // Normalization Bypasses (Modern Path Traversal/Auth Bypass Probes)
      { type: 'Normalization: /.;/', headers, url: url.replace(/(\/[^\/]+)$/, '/.;/admin') },
      { type: 'Normalization: /..;/', headers, url: url.replace(/(\/[^\/]+)$/, '/..;/admin') },
      { type: 'Normalization: /..%2f', headers, url: url.replace(/(\/[^\/]+)$/, '/..%2fadmin') },
      { type: 'Normalization: /%2e%2e%2f', headers, url: url.replace(/(\/[^\/]+)$/, '/%2e%2e%2fadmin') },
      { type: 'Normalization: /%ef%bc%8f', headers, url: url.replace(/(\/[^\/]+)$/, '/%ef%bc%8fadmin') },
      { type: 'Normalization: Null Byte', headers, url: url + '%00' },
    ];

    for (const mutation of mutations) {
      try {
        const mStartTime = Date.now();
        const mRes = await axios({
          method: mutation.method || method,
          url: mutation.url,
          headers: mutation.headers,
          validateStatus: () => true,
          timeout: 5000
        });
        const mLatency = Date.now() - mStartTime;

        const mStatus = mRes.status;
        const mLength = JSON.stringify(mRes.data).length;
        
        const lengthDiff = Math.abs(mLength - baselineLength);
        const isSignificantLengthDiff = baselineLength > 0 && (lengthDiff / baselineLength) > 0.1;

        if (mStatus !== baselineStatus || isSignificantLengthDiff) {
          const finding: GapFinding = {
            endpoint: url,
            mutation_type: mutation.type,
            baseline_status: baselineStatus,
            mutated_status: mStatus,
            evidence: `Length diff: ${lengthDiff}, Latency diff: ${Math.abs(mLatency - baselineLatency)}ms`,
            confidence: mStatus !== baselineStatus ? 'high' : 'medium'
          };
          findings.push(finding);
          
          db.prepare('INSERT INTO stack_gap_findings (id, endpoint, mutation_type, baseline_status, mutated_status, evidence, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(uuidv4(), finding.endpoint, finding.mutation_type, finding.baseline_status, finding.mutated_status, finding.evidence, finding.confidence);
        }
      } catch (err) {
        // Ignore timeout or connection errors for mutations
      }
    }

    return findings;
  }
}

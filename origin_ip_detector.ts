/**
 * origin_ip_detector — Discover the real origin IP behind CDN/proxy/WAF.
 *
 * When a target sits behind Cloudflare, Akamai, Fastly, etc., the DNS A
 * record points to the CDN edge, not the origin. Finding the origin IP
 * lets an operator bypass the WAF entirely by sending requests directly.
 *
 * Techniques:
 *   1. DNS history — check for historical A/AAAA records that predate CDN
 *   2. Subdomain scanning — mail, ftp, cpanel, staging, etc. often skip CDN
 *   3. TLS certificate analysis — SANs and CN may reveal origin hostname
 *   4. HTTP header leaks — X-Forwarded-For echoes, Server headers, etc.
 *   5. SPF/DMARC/MX record analysis — mail infrastructure often points
 *      to the same host
 *   6. favicon hash matching — Shodan favicon_hash search
 *   7. CORS/CSP header analysis — may reference origin IPs/hostnames
 */

import axios from 'axios';
import * as dns from 'dns';
import * as tls from 'tls';
import { promisify } from 'util';

const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveCname = promisify(dns.resolveCname);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OriginIpResult {
  ip: string;
  source: string;
  confidence: 'high' | 'medium' | 'low';
  notes: string;
}

export interface OriginIpReport {
  target: string;
  cdnDetected: string | null;
  cdnIps: string[];
  candidates: OriginIpResult[];
  subdomainHits: Array<{ subdomain: string; ips: string[] }>;
  mailInfra: Array<{ type: string; value: string; ips: string[] }>;
  certificateInfo: { cn: string | null; sans: string[] } | null;
  headerLeaks: Record<string, string>;
}

// CDN IP ranges (partial — enough for fingerprinting, not exhaustive)
const CDN_RANGES: Record<string, RegExp[]> = {
  Cloudflare: [
    /^103\.21\.244\./,  /^103\.22\.200\./, /^103\.31\.4\./, /^104\.16\./, /^104\.17\./,
    /^104\.18\./, /^104\.19\./, /^104\.20\./, /^104\.21\./, /^104\.22\./, /^104\.23\./,
    /^104\.24\./, /^104\.25\./, /^104\.26\./, /^104\.27\./, /^108\.162\./, /^131\.0\.72\./,
    /^141\.101\./, /^162\.158\./, /^172\.64\./, /^172\.65\./, /^172\.66\./, /^172\.67\./,
    /^173\.245\./, /^188\.114\./, /^190\.93\./, /^197\.234\./, /^198\.41\./,
  ],
  Fastly: [/^151\.101\./, /^199\.232\./, /^23\.235\./],
  Akamai: [/^23\.32\./, /^23\.33\./, /^23\.34\./, /^23\.35\./, /^23\.36\./, /^104\.64\./, /^104\.65\./],
  'AWS CloudFront': [/^13\.32\./, /^13\.33\./, /^13\.35\./, /^52\.84\./, /^52\.85\./, /^54\.182\./, /^54\.192\./, /^54\.230\./, /^54\.239\./],
};

function identifyCdn(ips: string[]): string | null {
  for (const ip of ips) {
    for (const [cdn, ranges] of Object.entries(CDN_RANGES)) {
      if (ranges.some(r => r.test(ip))) return cdn;
    }
  }
  return null;
}

function isCdnIp(ip: string): boolean {
  for (const ranges of Object.values(CDN_RANGES)) {
    if (ranges.some(r => r.test(ip))) return true;
  }
  return false;
}

// Common subdomains that often bypass CDN
const ORIGIN_SUBDOMAINS = [
  'mail', 'smtp', 'pop', 'pop3', 'imap', 'webmail', 'mx', 'mx1', 'mx2',
  'ftp', 'sftp', 'cpanel', 'whm', 'webdisk', 'cpcalendars', 'cpcontacts',
  'direct', 'direct-connect', 'origin', 'origin-www', 'raw',
  'dev', 'staging', 'stage', 'test', 'uat', 'preview', 'beta',
  'old', 'legacy', 'backup', 'bak',
  'api', 'api2', 'api-internal', 'internal',
  'admin', 'panel', 'manage', 'dashboard',
  'ns1', 'ns2', 'dns', 'dns1', 'dns2',
  'vpn', 'remote', 'ssh', 'git',
  'monitoring', 'grafana', 'prometheus', 'kibana',
  'jenkins', 'ci', 'build',
  'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
];

// ---------------------------------------------------------------------------
// Core Detector
// ---------------------------------------------------------------------------

export class OriginIpDetector {
  /**
   * Run all origin-IP discovery techniques against a target domain.
   */
  static async detect(
    domain: string,
    opts: { timeout?: number; maxSubdomains?: number } = {},
  ): Promise<OriginIpReport> {
    const timeout = opts.timeout ?? 5000;
    const maxSubdomains = opts.maxSubdomains ?? 40;
    const report: OriginIpReport = {
      target: domain,
      cdnDetected: null,
      cdnIps: [],
      candidates: [],
      subdomainHits: [],
      mailInfra: [],
      certificateInfo: null,
      headerLeaks: {},
    };

    // Step 1: Resolve the main domain
    let mainIps: string[] = [];
    try {
      mainIps = await dnsResolve4(domain);
    } catch {}
    try {
      const v6 = await dnsResolve6(domain);
      mainIps.push(...v6);
    } catch {}

    report.cdnDetected = identifyCdn(mainIps);
    report.cdnIps = mainIps.filter(ip => isCdnIp(ip));

    // Step 2: Subdomain scanning for non-CDN IPs
    const subdomainsToScan = ORIGIN_SUBDOMAINS.slice(0, maxSubdomains);
    const subdomainResults = await Promise.allSettled(
      subdomainsToScan.map(async (sub) => {
        const fqdn = `${sub}.${domain}`;
        try {
          const ips = await dnsResolve4(fqdn);
          const nonCdn = ips.filter(ip => !isCdnIp(ip));
          return { subdomain: fqdn, ips, nonCdn };
        } catch {
          return null;
        }
      }),
    );

    for (const result of subdomainResults) {
      if (result.status === 'fulfilled' && result.value && result.value.ips.length > 0) {
        report.subdomainHits.push({ subdomain: result.value.subdomain, ips: result.value.ips });
        for (const ip of result.value.nonCdn) {
          if (!report.candidates.some(c => c.ip === ip)) {
            report.candidates.push({
              ip,
              source: `subdomain:${result.value.subdomain}`,
              confidence: 'medium',
              notes: `Resolved from ${result.value.subdomain} (not in known CDN ranges)`,
            });
          }
        }
      }
    }

    // Step 3: MX record analysis
    try {
      const mxRecords = await dnsResolveMx(domain);
      for (const mx of mxRecords.slice(0, 5)) {
        try {
          const mxIps = await dnsResolve4(mx.exchange);
          report.mailInfra.push({ type: 'MX', value: mx.exchange, ips: mxIps });
          for (const ip of mxIps) {
            if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
              report.candidates.push({
                ip,
                source: `MX:${mx.exchange}`,
                confidence: 'medium',
                notes: `MX record ${mx.exchange} (priority ${mx.priority}) resolves to non-CDN IP`,
              });
            }
          }
        } catch {}
      }
    } catch {}

    // Step 4: SPF record analysis — extract ip4:/ip6: directives and included hosts
    try {
      const txtRecords = await dnsResolveTxt(domain);
      for (const record of txtRecords) {
        const txt = record.join('');
        if (txt.includes('v=spf1')) {
          report.mailInfra.push({ type: 'SPF', value: txt, ips: [] });
          const ipMatches = txt.matchAll(/ip[46]:([^\s/]+)/g);
          for (const match of ipMatches) {
            const ip = match[1];
            if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
              report.candidates.push({
                ip,
                source: 'SPF',
                confidence: 'high',
                notes: `IP directly listed in SPF record`,
              });
            }
          }
          // Extract 'include:' and 'a:' directives
          const includeMatches = txt.matchAll(/(?:include:|a:)([^\s]+)/g);
          for (const match of includeMatches) {
            try {
              const includedIps = await dnsResolve4(match[1]);
              for (const ip of includedIps) {
                if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
                  report.candidates.push({
                    ip,
                    source: `SPF:include:${match[1]}`,
                    confidence: 'medium',
                    notes: `SPF include/a directive resolves to non-CDN IP`,
                  });
                }
              }
            } catch {}
          }
        }
        // DMARC record
        if (txt.includes('v=DMARC1')) {
          report.mailInfra.push({ type: 'DMARC', value: txt, ips: [] });
        }
      }
    } catch {}

    // Step 5: CNAME unwinding — sometimes reveals origin
    try {
      const cnames = await dnsResolveCname(domain);
      for (const cname of cnames) {
        try {
          const cnameIps = await dnsResolve4(cname);
          for (const ip of cnameIps) {
            if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
              report.candidates.push({
                ip,
                source: `CNAME:${cname}`,
                confidence: 'low',
                notes: `CNAME chain resolves through ${cname}`,
              });
            }
          }
        } catch {}
      }
    } catch {}

    // Step 6: TLS certificate analysis
    try {
      const certInfo = await this.getCertificateInfo(domain, timeout);
      report.certificateInfo = certInfo;
      // SANs might reveal origin hostnames
      for (const san of certInfo.sans) {
        const sanHost = san.replace('*.', '').replace('DNS:', '');
        if (sanHost !== domain && !sanHost.includes('*')) {
          try {
            const sanIps = await dnsResolve4(sanHost);
            for (const ip of sanIps) {
              if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
                report.candidates.push({
                  ip,
                  source: `TLS SAN:${sanHost}`,
                  confidence: 'low',
                  notes: `TLS certificate SAN entry ${sanHost} resolves to non-CDN IP`,
                });
              }
            }
          } catch {}
        }
      }
    } catch {}

    // Step 7: HTTP header leak detection
    try {
      const headerRes = await axios.get(`https://${domain}`, {
        timeout, validateStatus: () => true, maxRedirects: 3,
      });
      const leakHeaders = [
        'x-forwarded-for', 'x-real-ip', 'x-originating-ip', 'x-remote-ip',
        'x-remote-addr', 'x-host', 'x-forwarded-host', 'x-backend-server',
        'x-served-by', 'x-server', 'x-origin-server',
      ];
      for (const h of leakHeaders) {
        const val = headerRes.headers[h];
        if (val) {
          report.headerLeaks[h] = String(val);
          // Try to extract IPs from the header value
          const ipMatches = String(val).matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
          for (const m of ipMatches) {
            const ip = m[1];
            if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
              report.candidates.push({
                ip,
                source: `Header:${h}`,
                confidence: 'high',
                notes: `Origin IP leaked in ${h} response header`,
              });
            }
          }
        }
      }

      // Check CORS/CSP headers for origin references
      const corsOrigin = headerRes.headers['access-control-allow-origin'];
      if (corsOrigin && corsOrigin !== '*') {
        report.headerLeaks['access-control-allow-origin'] = String(corsOrigin);
      }
      const csp = headerRes.headers['content-security-policy'];
      if (csp) {
        const ipInCsp = String(csp).matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
        for (const m of ipInCsp) {
          const ip = m[1];
          if (!isCdnIp(ip) && !report.candidates.some(c => c.ip === ip)) {
            report.candidates.push({
              ip,
              source: 'CSP header',
              confidence: 'medium',
              notes: `IP found in Content-Security-Policy header`,
            });
          }
        }
      }
    } catch {}

    // Sort candidates by confidence
    const confOrder = { high: 0, medium: 1, low: 2 };
    report.candidates.sort((a, b) => confOrder[a.confidence] - confOrder[b.confidence]);

    return report;
  }

  /**
   * Extract TLS certificate info (CN and SANs) from a domain.
   */
  private static getCertificateInfo(
    domain: string,
    timeout: number,
  ): Promise<{ cn: string | null; sans: string[] }> {
    return new Promise((resolve) => {
      const socket = tls.connect(443, domain, { servername: domain, timeout }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        const rawCn = cert.subject?.CN;
        const cn = Array.isArray(rawCn) ? rawCn[0] ?? null : rawCn ?? null;
        const sans: string[] = [];
        if (cert.subjectaltname) {
          for (const entry of cert.subjectaltname.split(',')) {
            sans.push(entry.trim());
          }
        }
        resolve({ cn, sans });
      });
      socket.on('error', () => resolve({ cn: null, sans: [] }));
      socket.setTimeout(timeout, () => { socket.destroy(); resolve({ cn: null, sans: [] }); });
    });
  }
}

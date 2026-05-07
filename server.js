'use strict';

const express = require('express');
const axios   = require('axios');
const cheerio = require('cheerio');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { randomUUID } = require('crypto');
const fs   = require('fs');
const path = require('path');
const http = require('http');
const captures = require('./captures');

const app = express();
// Captures from mitmproxy include base64 bodies up to ~64KB → JSON payload can hit ~100KB.
app.use(express.json({ limit: '8mb' }));

// ── Pretty URLs / hide .html for security ─────────────────────────────────────
// Root → home
app.get('/', (req, res) => res.redirect(302, '/home'));
// Block backup / source / hidden files (e.g. *.bak, *.old, *.swp, *.map, *~).
// These can leak server-side source if accidentally placed under public/.
app.use((req, res, next) => {
  if (req.method === 'GET' && /\.(bak\d*|old|orig|swp|swo|tmp|map|log|env|ini|conf|sh|py|js\.bak|json\.bak)(\?.*)?$|~$|\/\./i.test(req.path)) {
    return res.status(404).end();
  }
  next();
});
// Any direct *.html GET request is rewritten to its extensionless URL,
// so the .html paths are not exposed in the address bar.
app.use((req, res, next) => {
  if (req.method === 'GET' && req.path.endsWith('.html')) {
    const clean = req.path.slice(0, -5) || '/';
    const qs = req.url.slice(req.path.length); // preserve ?query#hash
    return res.redirect(301, clean + qs);
  }
  next();
});
// Serve static with implicit .html extension: /dashboard → public/dashboard.html
// `index:false` disables auto serving of /index.html at "/"
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  index: false,
  dotfiles: 'ignore',
}));

const jobs       = new Map();   // jobId → { total, done, results }
const sseClients = new Map();   // jobId → Set<res>

// ── Proxy URL parsing ────────────────────────────────────────────────────────
function parseProxyUrl(raw) {
  raw = raw.trim();
  if (!raw) return null;
  // Already has scheme
  if (/^(socks[45]?|http|https):\/\//i.test(raw)) return raw;
  const parts = raw.split(':');
  // host:port:user:pass — detect by 2nd token being a pure port number.
  // This handles usernames that contain '@' (e.g. user@zone:pass).
  if (parts.length >= 4 && /^\d+$/.test(parts[1])) {
    const [host, port, user, ...passParts] = parts;
    return `socks5://${encodeURIComponent(user)}:${encodeURIComponent(passParts.join(':'))}@${host}:${port}`;
  }
  // host:port
  if (parts.length === 2) return `socks5://${raw}`;
  return null;
}

function createAgent(proxyUrl) {
  if (/^socks/i.test(proxyUrl)) return new SocksProxyAgent(proxyUrl);
  return new HttpsProxyAgent(proxyUrl);
}

// Flexible proxy parser → returns { host, port, user, pass } or null.
// Accepts: scheme://[user:pass@]host:port  |  host:port:user:pass  |  host:port
// NOTE: host:port:user:pass is checked FIRST (before @-split) when the 2nd colon-token
// is a pure port number. This correctly handles usernames that contain '@' such as
// 'Thai1994@.custom2' in '1.2.3.4:9093:Thai1994@.custom2:pass'.
function parseProxyFlex(raw) {
  if (!raw) return null;
  raw = String(raw).trim();
  // With scheme
  const m = raw.match(/^(?:socks[45]?h?|http|https):\/\/(.+)$/i);
  const body = m ? m[1] : raw;
  const parts = body.split(':');
  // host:port:user:pass — prioritise when 2nd token is a port number.
  // Handles usernames/passwords that contain '@' or ':'.
  if (!m && parts.length >= 4 && /^\d+$/.test(parts[1])) {
    return { host: parts[0], port: parts[1], user: parts[2], pass: parts.slice(3).join(':') };
  }
  // scheme://user:pass@host:port  OR  user:pass@host:port (no scheme)
  const at = body.lastIndexOf('@');
  if (at !== -1) {
    const creds = body.slice(0, at);
    const hp = body.slice(at + 1);
    const ci = creds.indexOf(':');
    const hi = hp.indexOf(':');
    if (hi === -1) return null;
    return {
      user: ci === -1 ? creds : creds.slice(0, ci),
      pass: ci === -1 ? '' : creds.slice(ci + 1),
      host: hp.slice(0, hi),
      port: hp.slice(hi + 1),
    };
  }
  // host:port:user:pass fallback (no scheme, no @)
  if (parts.length >= 4) {
    return { host: parts[0], port: parts[1], user: parts[2], pass: parts.slice(3).join(':') };
  }
  if (parts.length === 2) return { host: parts[0], port: parts[1], user: '', pass: '' };
  return null;
}

function buildProxyUrl(scheme, p) {
  const creds = p.user ? `${encodeURIComponent(p.user)}:${encodeURIComponent(p.pass || '')}@` : '';
  return `${scheme}://${creds}${p.host}:${p.port}`;
}

// Auto-detect proxy protocol by live-testing SOCKS5 first, then HTTP CONNECT.
// Returns { scheme, url, exitIp }. Throws on all failures.
async function detectAndTestProxy(rawInput) {
  const p = parseProxyFlex(rawInput);
  if (!p || !p.host || !p.port) throw new Error('Cannot parse proxy');
  // If user specified scheme, honour it only — do not fallback.
  const schemeMatch = String(rawInput).trim().match(/^(socks[45]?h?|http|https):\/\//i);
  const forced = schemeMatch ? schemeMatch[1].toLowerCase().replace('socks4a','socks4').replace('socks5h','socks5') : null;
  const order = forced
    ? [forced === 'http' || forced === 'https' ? 'http' : 'socks5']
    : ['socks5', 'http'];
  // Try multiple IP-echo endpoints over both HTTPS and plain HTTP.
  // Some proxies (port-restricted / cheap residential) only allow port 80,
  // or block specific hosts (e.g. api.ipify.org). Fall back gracefully.
  const TEST_URLS = [
    'https://api.ipify.org?format=json',
    'http://api.ipify.org/?format=json',
    'https://ifconfig.me/ip',
    'http://ifconfig.me/ip',
    'http://ip-api.com/json/?fields=query',
  ];
  const errs = [];
  for (const sch of order) {
    const url = buildProxyUrl(sch, p);
    let lastErr = null;
    for (const testUrl of TEST_URLS) {
      try {
        const agent = sch === 'socks5' ? new SocksProxyAgent(url) : new HttpsProxyAgent(url);
        const r = await axios.get(testUrl, {
          httpsAgent: agent, httpAgent: agent, timeout: 15000,
          responseType: 'text', transformResponse: [d => d],
        });
        const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
        // Extract IPv4 from JSON or plain text
        const m = body.match(/(?:"(?:ip|query)"\s*:\s*"([^"]+)")|(\b\d{1,3}(?:\.\d{1,3}){3}\b)/);
        const ip = m ? (m[1] || m[2]) : null;
        if (ip) return { scheme: sch, url, exitIp: ip, parsed: p };
        lastErr = `no IP in response from ${testUrl}`;
      } catch(e) { lastErr = `${testUrl} -> ${e.code || e.message}`; }
    }
    errs.push(`${sch}: ${lastErr}`);
  }
  throw new Error(errs.join(' | '));
}

// ── Shared axios config ──────────────────────────────────────────────────────
const BASE_HEADERS = {
  'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
};

function axiosCfg(agent, timeout) {
  return { httpsAgent: agent, httpAgent: agent, timeout, headers: BASE_HEADERS };
}

// Strip fields that are iframe placeholders (JS-only dynamic content)
function cleanVal($el) {
  // Remove iframe/noscript elements before getting text
  $el.find('iframe, .noscript, .load-div, script').remove();
  return $el.text().trim();
}

// ── Fetch TLS fingerprints via /json endpoint ────────────────────────────────
async function fetchTls(agent, timeout) {
  try {
    const { data } = await axios.get(
      'https://tls.browserleaks.com/json',
      axiosCfg(agent, Math.min(timeout, 15000))
    );
    return {
      tls_ja4:   data.ja4        || '',
      tls_ja3:   data.ja3_hash   || '',
      h2_akamai: data.akamai_hash|| '',
    };
  } catch (_) {
    return { tls_ja4: '', tls_ja3: '', h2_akamai: '' };
  }
}

// ── Fetch hostname via reverse DNS (server-side, no proxy needed) ─────────────
async function fetchHostname(ip) {
  const dns = require('dns').promises;
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames[0] || '';
  } catch (_) { return ''; }
}

// ── Fetch Whois via RDAP (works for ALL registries: ARIN, APNIC, RIPE, etc.) ──
// Always fetch DIRECTLY from server (not via proxy) — we're looking up the proxy's IP
async function fetchWhoisRDAP(ip) {
  const urls = [
    `https://rdap.org/ip/${ip}`,
    `https://rdap.arin.net/registry/ip/${ip}`,
    `https://rdap.db.ripe.net/ip/${ip}`,
  ];
  for (const url of urls) {
    try {
      const { data } = await axios.get(url, {
        timeout: 10000,
        headers: { 'Accept': 'application/rdap+json,application/json', 'User-Agent': 'proxy-checker/1.0' },
      });
      const w = {};
      // Name / handle
      w.whois_name  = data.name || '';
      w.whois_type  = data.type || '';
      // IP range
      if (data.startAddress && data.endAddress)
        w.whois_range = `${data.startAddress} - ${data.endAddress}`;
      // CIDR — field is cidr0_cidrs in ARIN responses
      const cidrs = data.cidr0_cidrs || data.cidr0CidrsArray || [];
      if (Array.isArray(cidrs) && cidrs.length)
        w.whois_cidr = cidrs.map(c => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ');
      // Registry
      w.whois_reg = (data.port43 || '').replace(/^whois\./, '').split('.').slice(-2, -1)[0]?.toUpperCase() || '';
      if (!w.whois_reg && data.links)
        w.whois_reg = data.links.find(l => l.rel === 'self')?.href?.match(/\/\/([\w.]+)/)?.[1] || '';
      // Country
      w.whois_country = data.country || '';
      // Registration dates
      for (const ev of data.events || []) {
        if (ev.eventAction === 'registration') w.whois_created = ev.eventDate?.slice(0, 10) || '';
        if (ev.eventAction === 'last changed')  w.whois_changed = ev.eventDate?.slice(0, 10) || '';
      }
      // Org description
      const orgEntity = (data.entities || []).find(e => Array.isArray(e.roles) && e.roles.includes('registrant'));
      if (orgEntity?.vcardArray) {
        const vcard = orgEntity.vcardArray[1] || [];
        const fn = vcard.find(f => f[0] === 'fn');
        if (fn) w.whois_org = fn[3] || '';
      }
      if (Object.values(w).some(Boolean)) return w;
    } catch (_) {}
  }
  return {};
}

// ── Fetch Scamalytics fraud score (direct, no proxy) ──────────────────────────
const SCAMALYTICS_USER = '69ea22661e27f';
const SCAMALYTICS_KEY  = '3a7d2162f8fdbce8605b90ce891091c776200fb42adcb89a219bce96473a8e5b';

async function fetchScamalytics(ip) {
  try {
    const { data } = await axios.get(
      `https://api11.scamalytics.com/v3/${SCAMALYTICS_USER}/?key=${SCAMALYTICS_KEY}&ip=${encodeURIComponent(ip)}`,
      { timeout: 10000, headers: { 'User-Agent': 'proxy-checker/1.0' } }
    );
    const s = data.scamalytics || {};
    const ext = data.external_datasources || {};
    const proxy = s.scamalytics_proxy || {};
    const x4b = ext.x4bnet || {};
    const fh  = ext.firehol || {};
    const p2  = ext.ip2proxy || {};
    return {
      sc_score:       s.scamalytics_score ?? '',
      sc_risk:        s.scamalytics_risk  || '',
      sc_blacklisted: s.is_blacklisted_external || false,
      sc_is_vpn:      proxy.is_vpn       || x4b.is_vpn       || false,
      sc_is_dc:       proxy.is_datacenter|| x4b.is_datacenter|| false,
      sc_is_tor:      x4b.is_tor         || false,
      sc_is_proxy:    fh.is_proxy        || false,
      sc_proxy_type:  p2.proxy_type && p2.proxy_type !== '0' ? p2.proxy_type : '',
      sc_isp_score:   s.scamalytics_isp_score ?? '',
      sc_isp_risk:    s.scamalytics_isp_risk   || '',
      sc_url:         s.scamalytics_url  || '',
      sc_fh_bl30:     fh.ip_blacklisted_30 || false,
      sc_spambot:     x4b.is_blacklisted_spambot || false,
    };
  } catch (_) { return {}; }
}

// ── Core checker ─────────────────────────────────────────────────────────────
async function checkProxy(raw, timeout = 30000) {
  const proxyUrl = parseProxyUrl(raw);
  if (!proxyUrl) return { proxy: raw, status: 'error', error: 'Invalid proxy format' };

  let agent;
  try { agent = createAgent(proxyUrl); }
  catch (e) { return { proxy: raw, status: 'error', error: 'Bad proxy URL: ' + e.message }; }

  const t0 = Date.now();
  try {
    // Fetch main page + TLS data + RDAP Whois in parallel
    const [mainRes, tlsData] = await Promise.all([
      axios.get('https://browserleaks.com/ip', axiosCfg(agent, timeout)),
      fetchTls(agent, Math.min(timeout, 15000)),
    ]);

    const latency = Date.now() - t0;
    const $ = cheerio.load(mainRes.data);
    const r = { proxy: raw, status: 'ok', latency, ...tlsData };

    // IP Address (server-rendered)
    const ipEl = $('#client-ipv4');
    r.ip      = ipEl.find('.flag-text').first().text().trim() || ipEl.attr('data-ip') || '';
    r.ip_iso  = ipEl.attr('data-iso_code') || '';

    // IPv6 — server-rendered fallback (JS iframe ignored)
    const ipv6El = $('#client-ipv6');
    ipv6El.find('iframe, .noscript, .load-div').remove();
    const ipv6txt = ipv6El.text().trim();
    r.ipv6 = ipv6txt && !ipv6txt.includes('<') ? ipv6txt : 'n/a';

    // Hostname — reverse DNS (fast, no extra proxy request)
    if (r.ip) r.hostname = await fetchHostname(r.ip);

    // All table rows key→value
    $('table tr').each((_, tr) => {
      const cells = $(tr).find('> td');
      if (cells.length < 2) return;
      const k  = cells.eq(0).text().trim();
      const el = cells.eq(1);
      // Use cleanVal to strip iframe placeholders
      const v  = cleanVal(el.clone());

      // Skip empty or iframe-only values
      if (!v || v.includes('<iframe')) return;

      switch (k) {
        case 'Country':
          r.country     = el.find('.flag-text').first().text().replace(/\s*\(.*?\)/g, '').trim() || v;
          r.country_iso = el.find('.flag-container').first().attr('data-iso_code') || '';
          break;
        case 'State/Region':  r.region   = v; break;
        case 'City':          r.city     = v; break;
        case 'ISP':           r.isp      = v; break;
        case 'Organization':  r.org      = v; break;
        case 'Network':       r.network  = v; break;
        case 'Usage Type':    r.usage    = v; break;
        case 'Timezone':      r.timezone = v.split(' ')[0] || v; break;
        case 'Coordinates':   r.coords   = el.attr('data-lat') && el.attr('data-lon')
                                          ? `${el.attr('data-lat')},${el.attr('data-lon')}`
                                          : v; break;
        // TCP/IP Fingerprint
        case 'OS':          r.tcp_os   = v; break;
        case 'MTU':         r.tcp_mtu  = v; break;
        case 'Link Type':   r.tcp_link = v; break;
        case 'Distance':    r.tcp_dist = v; break;
        case 'JA4T':        r.tcp_ja4t = el.find('.mono').text().trim() || v; break;
        // TLS — only override if not already fetched from tls.browserleaks.com
        case 'JA4':       if (!r.tls_ja4)    r.tls_ja4   = el.find('.mono').text().trim() || v; break;
        case 'JA3 Hash':  if (!r.tls_ja3)    r.tls_ja3   = el.find('.mono').text().trim() || v; break;
        case 'Akamai Hash': if (!r.h2_akamai) r.h2_akamai = el.find('.mono').text().trim() || v; break;
      }
    });

    // ── Whois — parse từ BrowserLeaks HTML nếu có, fallback sang RDAP ─────────
    let whoisFromHtml = false;
    $('table.wball').each((_, table) => {
      const $t = $(table);
      if (!$t.find('h3').first().text().includes('Whois')) return;
      whoisFromHtml = true;
      $t.find('tr').each((_, tr) => {
        const cells = $(tr).find('> td');
        if (cells.length < 2) return;
        const k = cells.eq(0).text().trim();
        const v = cleanVal(cells.eq(1).clone());
        if (!v) return;
        switch (k) {
          case 'Source Registry': r.whois_reg     = v; break;
          case 'Net Range':       r.whois_range   = v; break;
          case 'CIDR':            r.whois_cidr    = v; break;
          case 'Name':            if (!r.whois_name) r.whois_name = v; break;
          case 'Net Type':        r.whois_type    = v; break;
          case 'Registration':    if (!r.whois_created) r.whois_created = v; break;
        }
      });
    });

    // If no Whois data was actually parsed (even if table existed), fetch from RDAP
    // Also fetch Scamalytics — both direct (no proxy)
    const postFetches = [];
    if (!r.whois_name && !r.whois_range && r.ip)
      postFetches.push(fetchWhoisRDAP(r.ip).then(w => Object.assign(r, w)));
    if (r.ip)
      postFetches.push(fetchScamalytics(r.ip).then(s => Object.assign(r, s)));
    await Promise.all(postFetches);

    // HTTP/2 Akamai — label empty string clearly
    if (!r.h2_akamai) r.h2_akamai = '';   // kept empty, UI shows "n/a (HTTP/1.1)"

    return r;
  } catch (err) {
    return {
      proxy:   raw,
      status:  'error',
      latency: Date.now() - t0,
      error:   err.code || err.message || 'Connection failed',
    };
  }
}

// ── Proxy Library (persistent, deduped) ──────────────────────────────────────
const LIB_FILE = path.join(__dirname, 'proxy-library.json');

function libLoad() {
  try { return JSON.parse(fs.readFileSync(LIB_FILE, 'utf8')); }
  catch (_) { return {}; }  // { proxy_string: { proxy, ip, country, isp, usage, sc_risk, sc_score, saved_at } }
}

function libSave(data) {
  fs.writeFileSync(LIB_FILE, JSON.stringify(data, null, 2));
}

function libAddResults(results) {
  const lib = libLoad();
  let added = 0;
  for (const r of results) {
    if (r.status !== 'ok' || !r.proxy) continue;
    if (!lib[r.proxy]) {
      lib[r.proxy] = {
        proxy:    r.proxy,
        ip:       r.ip       || '',
        country:  r.country  || '',
        city:     r.city     || '',
        isp:      r.isp      || '',
        usage:    r.usage    || '',
        tcp_os:   r.tcp_os   || '',
        sc_risk:  r.sc_risk  || '',
        sc_score: r.sc_score ?? '',
        sc_is_vpn: r.sc_is_vpn || false,
        sc_is_dc:  r.sc_is_dc  || false,
        sc_is_tor: r.sc_is_tor || false,
        saved_at: new Date().toISOString(),
      };
      added++;
    } else {
      // Update metadata but keep original saved_at
      Object.assign(lib[r.proxy], {
        ip: r.ip||lib[r.proxy].ip, country: r.country||lib[r.proxy].country,
        city: r.city||lib[r.proxy].city, isp: r.isp||lib[r.proxy].isp,
        usage: r.usage||lib[r.proxy].usage, tcp_os: r.tcp_os||lib[r.proxy].tcp_os,
        sc_risk: r.sc_risk||lib[r.proxy].sc_risk, sc_score: r.sc_score??lib[r.proxy].sc_score,
        sc_is_vpn: r.sc_is_vpn||lib[r.proxy].sc_is_vpn,
        sc_is_dc:  r.sc_is_dc ||lib[r.proxy].sc_is_dc,
        sc_is_tor: r.sc_is_tor||lib[r.proxy].sc_is_tor,
        updated_at: new Date().toISOString(),
      });
    }
  }
  libSave(lib);
  return added;
}

// ── Per-customer Proxy Library (per API key) ─────────────────────────────────
const CUST_LIB_FILE = path.join(__dirname, 'customer-libraries.json');
function custLibAll() {
  try { return JSON.parse(fs.readFileSync(CUST_LIB_FILE, 'utf8')); }
  catch (_) { return {}; }  // { [keyId]: { [proxy]: {...} } }
}
function custLibSaveAll(data) {
  fs.writeFileSync(CUST_LIB_FILE, JSON.stringify(data, null, 2));
}
function custLibAdd(keyId, results) {
  if (!keyId) return 0;
  const all = custLibAll();
  const lib = all[keyId] || {};
  let added = 0;
  for (const r of results) {
    if (r.status !== 'ok' || !r.proxy) continue;
    if (!lib[r.proxy]) {
      lib[r.proxy] = {
        proxy: r.proxy, ip: r.ip||'', country: r.country||'', city: r.city||'',
        isp: r.isp||'', usage: r.usage||'', tcp_os: r.tcp_os||'',
        sc_risk: r.sc_risk||'', sc_score: r.sc_score ?? '',
        sc_is_vpn: r.sc_is_vpn||false, sc_is_dc: r.sc_is_dc||false, sc_is_tor: r.sc_is_tor||false,
        saved_at: new Date().toISOString(),
      };
      added++;
    } else {
      Object.assign(lib[r.proxy], {
        ip: r.ip||lib[r.proxy].ip, country: r.country||lib[r.proxy].country,
        city: r.city||lib[r.proxy].city, isp: r.isp||lib[r.proxy].isp,
        usage: r.usage||lib[r.proxy].usage, tcp_os: r.tcp_os||lib[r.proxy].tcp_os,
        sc_risk: r.sc_risk||lib[r.proxy].sc_risk, sc_score: r.sc_score ?? lib[r.proxy].sc_score,
        sc_is_vpn: r.sc_is_vpn||lib[r.proxy].sc_is_vpn,
        sc_is_dc:  r.sc_is_dc ||lib[r.proxy].sc_is_dc,
        sc_is_tor: r.sc_is_tor||lib[r.proxy].sc_is_tor,
        updated_at: new Date().toISOString(),
      });
    }
  }
  all[keyId] = lib;
  custLibSaveAll(all);
  return added;
}

function broadcast(jobId, payload) {
  const clients = sseClients.get(jobId);
  if (!clients || clients.size === 0) return;
  const msg = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of clients) { try { res.write(msg); } catch (_) {} }
}

// ── Job runner (sliding-window concurrency) ──────────────────────────────────
async function runJob(jobId, proxies, concurrency, timeout, ownerKeyId) {
  let idx = 0;

  const worker = async () => {
    while (idx < proxies.length) {
      const raw    = proxies[idx++];
      const result = await checkProxy(raw, timeout);
      const job    = jobs.get(jobId);
      if (!job) return;
      job.done++;
      job.results.push(result);
      broadcast(jobId, { type: 'result', result, done: job.done, total: job.total });
      if (job.done >= job.total) {
        broadcast(jobId, { type: 'done' });
        // Auto-save all OK proxies to library
        if (ownerKeyId) custLibAdd(ownerKeyId, job.results);
        else            libAddResults(job.results);
        setTimeout(() => { jobs.delete(jobId); sseClients.delete(jobId); }, 600_000);
      }
    }
  };

  const workers = Math.min(concurrency, proxies.length);
  await Promise.allSettled(Array.from({ length: workers }, worker));
}

const { execSync, exec } = require('child_process');

// ── VPN Management ────────────────────────────────────────────────────────────
const WG_CONF    = '/etc/wireguard/wg0.conf';
const WG_DIR     = '/etc/wireguard';
const WG_DATA    = path.join(__dirname, 'vpn-clients.json');
const SS_CONF    = '/etc/shadowsocks-libev/config.json';
const SERVER_IP  = '103.162.14.102';
const VPN_TOKEN  = process.env.VPN_TOKEN || 'vpnadmin2026';
const PORT       = process.env.PORT || 3000;

function wgLoadClients() {
  try { return JSON.parse(fs.readFileSync(WG_DATA, 'utf8')); } catch(_) { return {}; }
}
function wgSaveClients(data) { fs.writeFileSync(WG_DATA, JSON.stringify(data, null, 2)); }

function wgNextIp(clients) {
  const used = new Set(Object.values(clients).map(c => c.ip));
  for (let i = 2; i <= 254; i++) {
    const ip = `10.8.0.${i}`;
    if (!used.has(ip)) return ip;
  }
  throw new Error('No IPs available');
}

function wgCreateClient(name) {
  const privKey = execSync('wg genkey').toString().trim();
  const pubKey  = execSync(`echo "${privKey}" | wg pubkey`).toString().trim();
  const psk     = execSync('wg genpsk').toString().trim();
  const clients = wgLoadClients();
  const ip      = wgNextIp(clients);
  const serverPub = fs.readFileSync(path.join(WG_DIR, 'server_public.key'), 'utf8').trim();

  // Add peer to server config
  const peer = `\n[Peer]\n# ${name}\nPublicKey = ${pubKey}\nPresharedKey = ${psk}\nAllowedIPs = ${ip}/32\n`;
  fs.appendFileSync(WG_CONF, peer);
  execSync(`wg addconf wg0 <(printf '[Peer]\\nPublicKey = ${pubKey}\\nPresharedKey = ${psk}\\nAllowedIPs = ${ip}/32\\n')`, { shell: '/bin/bash' });

  clients[name] = { name, ip, pubKey, privKey, psk, createdAt: new Date().toISOString() };
  wgSaveClients(clients);

  // Build client .conf text
  const conf = `[Interface]
PrivateKey = ${privKey}
Address = ${ip}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${serverPub}
PresharedKey = ${psk}
Endpoint = ${SERVER_IP}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
  return { name, ip, conf };
}

function wgDeleteClient(name) {
  const clients = wgLoadClients();
  const c = clients[name];
  if (!c) return false;
  // Remove from running wg
  try { execSync(`wg set wg0 peer ${c.pubKey} remove`); } catch(_){}
  // Rewrite conf without this peer
  const raw = fs.readFileSync(WG_CONF, 'utf8');
  const cleaned = raw.replace(new RegExp(`\\n\\[Peer\\]\\n# ${name}\\n[\\s\\S]*?(?=\\n\\[Peer\\]|$)`, 'g'), '');
  fs.writeFileSync(WG_CONF, cleaned);
  delete clients[name];
  wgSaveClients(clients);
  return true;
}

function ssGetConfig() {
  try { return JSON.parse(fs.readFileSync(SS_CONF, 'utf8')); } catch(_) { return null; }
}

function ssLink(cfg) {
  const b64 = Buffer.from(`${cfg.method}:${cfg.password}`).toString('base64');
  return `ss://${b64}@${SERVER_IP}:${cfg.server_port}`;
}

// ── Settings Management ────────────────────────────────────────────────────────
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
function settingsLoad() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch(_) { return {}; }
}
function settingsSave(s) { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s, null, 2)); }

// ── API Key Management ─────────────────────────────────────────────────────────
const KEYS_FILE = path.join(__dirname, 'api-keys.json');

function keysLoad() {
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); } catch(_) { return {}; }
}
function keysSave(data) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2));
}

// Permissions available for keys
const ALL_PERMISSIONS = ['check_proxy', 'view_gateways', 'vpn_clients', 'l2tp_credentials', 'create_gateway'];

// Middleware: authenticate by API key (header x-api-key or query ?api_key=)
// perms: array of required permissions (all must be present)
function requireApiKey(perms = []) {
  return (req, res, next) => {
    const k = req.headers['x-api-key'] || req.query.api_key;
    if (!k) return res.status(401).json({ error: 'API key required. Set header: x-api-key' });
    const keys = keysLoad();
    const entry = Object.values(keys).find(x => x.key === k);
    if (!entry) return res.status(401).json({ error: 'Invalid API key' });
    if (!entry.enabled) return res.status(403).json({ error: 'API key disabled' });
    if (entry.expires_at && new Date(entry.expires_at) < new Date())
      return res.status(403).json({ error: 'API key expired', expired_at: entry.expires_at });
    if (perms.length && !perms.every(p => (entry.permissions || []).includes(p)))
      return res.status(403).json({ error: 'Permission denied', required: perms, has: entry.permissions });
    // Update last_used_at (non-blocking)
    entry.last_used_at = new Date().toISOString();
    keys[entry.id] = entry;
    setImmediate(() => keysSave(keys));
    req.apiKey = entry;
    next();
  };
}

// ── Admin: Key CRUD (requires master VPN token) ────────────────────────────────
function keyPublicView(k) {
  return {
    id: k.id, name: k.name, note: k.note || '',
    key_preview: k.key.slice(0, 8) + '…',
    key: k.key,  // full key shown in admin
    enabled: k.enabled,
    permissions: k.permissions || [],
    allowed_gateways: k.allowed_gateways || null,
    bandwidth_limit_gb: k.bandwidth_limit_gb || null,
    bandwidth_used_bytes: k.bandwidth_used_bytes || 0,
    proxy_check_limit: k.proxy_check_limit || null,
    proxy_checks_used: k.proxy_checks_used || 0,
    expires_at: k.expires_at || null,
    created_at: k.created_at,
    last_used_at: k.last_used_at || null,
  };
}

app.get('/api/admin/keys', requireVpnToken, (req, res) => {
  const keys = keysLoad();
  res.json({ keys: Object.values(keys).map(keyPublicView) });
});

app.post('/api/admin/keys', requireVpnToken, (req, res) => {
  const { name, note, permissions, allowed_gateways, bandwidth_limit_gb, proxy_check_limit, expires_at } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
  const keys = keysLoad();
  const id = randomUUID();
  const key = 'pk_' + require('crypto').randomBytes(20).toString('hex');
  const entry = {
    id, key, name: name.trim(), note: note || '',
    enabled: true,
    permissions: (permissions || ALL_PERMISSIONS).filter(p => ALL_PERMISSIONS.includes(p)),
    allowed_gateways: allowed_gateways || null,  // null = all gateways
    bandwidth_limit_gb: bandwidth_limit_gb ? Number(bandwidth_limit_gb) : null,
    bandwidth_used_bytes: 0,
    proxy_check_limit: proxy_check_limit ? Number(proxy_check_limit) : null,
    proxy_checks_used: 0,
    expires_at: expires_at || null,
    created_at: new Date().toISOString(),
    last_used_at: null,
  };
  keys[id] = entry;
  keysSave(keys);
  res.status(201).json(keyPublicView(entry));
});

app.put('/api/admin/keys/:id', requireVpnToken, (req, res) => {
  const { id } = req.params;
  const keys = keysLoad();
  if (!keys[id]) return res.status(404).json({ error: 'Not found' });
  const k = keys[id];
  const { name, note, enabled, permissions, allowed_gateways, bandwidth_limit_gb, proxy_check_limit, expires_at } = req.body;
  if (name !== undefined) k.name = name.trim();
  if (note !== undefined) k.note = note;
  if (enabled !== undefined) k.enabled = Boolean(enabled);
  if (permissions !== undefined) k.permissions = permissions.filter(p => ALL_PERMISSIONS.includes(p));
  if (allowed_gateways !== undefined) k.allowed_gateways = allowed_gateways || null;
  if (bandwidth_limit_gb !== undefined) k.bandwidth_limit_gb = bandwidth_limit_gb ? Number(bandwidth_limit_gb) : null;
  if (proxy_check_limit !== undefined) k.proxy_check_limit = proxy_check_limit ? Number(proxy_check_limit) : null;
  if (expires_at !== undefined) k.expires_at = expires_at || null;
  keys[id] = k;
  keysSave(keys);
  res.json(keyPublicView(k));
});

app.delete('/api/admin/keys/:id', requireVpnToken, (req, res) => {
  const keys = keysLoad();
  if (!keys[req.params.id]) return res.status(404).json({ error: 'Not found' });
  delete keys[req.params.id];
  keysSave(keys);
  res.json({ ok: true });
});

// Reset (regenerate) key value
app.post('/api/admin/keys/:id/reset', requireVpnToken, (req, res) => {
  const keys = keysLoad();
  if (!keys[req.params.id]) return res.status(404).json({ error: 'Not found' });
  keys[req.params.id].key = 'pk_' + require('crypto').randomBytes(20).toString('hex');
  keysSave(keys);
  res.json(keyPublicView(keys[req.params.id]));
});

// Reset usage counters (bandwidth + check count)
app.post('/api/admin/keys/:id/reset-usage', requireVpnToken, (req, res) => {
  const keys = keysLoad();
  if (!keys[req.params.id]) return res.status(404).json({ error: 'Not found' });
  keys[req.params.id].bandwidth_used_bytes = 0;
  keys[req.params.id].proxy_checks_used = 0;
  keysSave(keys);
  res.json(keyPublicView(keys[req.params.id]));
});

// Key self-info endpoint (for key holders to check their own quota)
app.get('/api/key/me', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const bwLimit = k.bandwidth_limit_gb ? k.bandwidth_limit_gb * 1024 * 1024 * 1024 : null;
  res.json({
    name: k.name,
    permissions: k.permissions,
    allowed_gateways: k.allowed_gateways,
    expires_at: k.expires_at,
    bandwidth: { used_bytes: k.bandwidth_used_bytes, limit_bytes: bwLimit, limit_gb: k.bandwidth_limit_gb },
    proxy_checks: { used: k.proxy_checks_used, limit: k.proxy_check_limit },
    last_used_at: k.last_used_at,
  });
});

// ── Customer Portal API (uses x-api-key) ──────────────────────────────────────

// Helper: build .ovpn file content
function buildOvpn(gw, certName) {
  const ca   = fs.readFileSync('/etc/openvpn/easy-rsa/pki/ca.crt', 'utf8').trim();
  const cert = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`, 'utf8');
  const key  = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/private/${certName}.key`, 'utf8').trim();
  const ta   = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();
  const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
  const certClean = certMatch ? certMatch[0].trim() : cert.trim();
  return `client\ndev tun\nproto udp\nremote ${SERVER_IP} ${gw.vpn_port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\ncompress lz4-v2\nverb 3\nkey-direction 1\n<ca>\n${ca}\n</ca>\n<cert>\n${certClean}\n</cert>\n<key>\n${key}\n</key>\n<tls-auth>\n${ta}\n</tls-auth>\n`;
}

// GET /api/customer/gateways — list accessible gateways + this key's VPN clients per gateway
app.get('/api/customer/gateways', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const gateways = gwLoad();
  let list = Object.values(gateways);
  if (k.allowed_gateways && k.allowed_gateways.length) {
    list = list.filter(g => k.allowed_gateways.includes(g.name));
  }
  const myClients = (k.vpn_clients || []);
  res.json({ gateways: list.map(g => ({
    name: g.name, country: g.country || '', exit_ip: g.exit_ip || '',
    vpn_port: g.vpn_port, server_ip: SERVER_IP,
    my_clients: myClients.filter(c => c.gateway === g.name),
  })) });
});

// GET /api/customer/vpn/clients — list all this key's VPN clients
app.get('/api/customer/vpn/clients', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  res.json({ clients: k.vpn_clients || [] });
});

// GET /api/customer/vpn/client/:certName/ovpn — re-download .ovpn
app.get('/api/customer/vpn/client/:certName/ovpn', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const certName = req.params.certName.replace(/[^a-zA-Z0-9_-]/g, '');
  const myClients = k.vpn_clients || [];
  const entry = myClients.find(c => c.cert_name === certName);
  if (!entry) return res.status(404).json({ error: 'Client not found or not owned by you' });
  const gateways = gwLoad();
  const gw = gateways[entry.gateway];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  try {
    const ovpn = buildOvpn(gw, certName);
    res.json({ ok: true, name: entry.client_name, ovpn });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/customer/vpn/client/:certName — revoke and delete a client
app.delete('/api/customer/vpn/client/:certName', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const certName = req.params.certName.replace(/[^a-zA-Z0-9_-]/g, '');
  const myClients = k.vpn_clients || [];
  const idx = myClients.findIndex(c => c.cert_name === certName);
  if (idx === -1) return res.status(404).json({ error: 'Client not found or not owned by you' });
  try {
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa revoke ${certName} 2>&1 || true`, { shell: '/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-crl 2>&1 || true`, { shell: '/bin/bash' });
    try { fs.unlinkSync(`/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`); } catch(_) {}
    try { fs.unlinkSync(`/etc/openvpn/easy-rsa/pki/private/${certName}.key`); } catch(_) {}
  } catch(_) {}
  const keys = keysLoad();
  keys[k.id].vpn_clients = myClients.filter((_, i) => i !== idx);
  keysSave(keys);
  res.json({ ok: true });
});

// POST /api/customer/gateway/:name/client — generate OpenVPN config and track ownership
app.post('/api/customer/gateway/:name/client', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g, '');
  if (!keyCanAccessGateway(k, name))
    return res.status(403).json({ error: 'You do not have access to this gateway' });
  const clientName = (req.body.client_name || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24);
  if (!clientName) return res.status(400).json({ error: 'client_name required' });
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  // Prefix cert name with short key id to prevent collisions between customers
  const keyPrefix = k.id.replace(/-/g,'').slice(0,8);
  const certName = `${name}_${keyPrefix}_${clientName}`;
  // Check if this client name already exists for this key+gateway
  const existing = (k.vpn_clients || []).find(c => c.gateway === name && c.client_name === clientName);
  if (existing) return res.status(409).json({ error: 'Client name already exists. Choose a different name or delete the existing one first.' });
  try {
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-req ${certName} nopass 2>&1`, { shell: '/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa sign-req client ${certName} 2>&1`, { shell: '/bin/bash' });
    const ovpn = buildOvpn(gw, certName);
    // Track ownership in key record
    const keys = keysLoad();
    if (!keys[k.id].vpn_clients) keys[k.id].vpn_clients = [];
    keys[k.id].vpn_clients.push({ gateway: name, client_name: clientName, cert_name: certName, created_at: new Date().toISOString() });
    keysSave(keys);
    res.json({ ok: true, name: clientName, cert_name: certName, ovpn });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Per-customer Proxy Library API ───────────────────────────────────────────
app.get('/api/customer/library', requireApiKey(), (req, res) => {
  const lib = (custLibAll())[req.apiKey.id] || {};
  const items = Object.values(lib).sort((a, b) => (b.saved_at || '').localeCompare(a.saved_at || ''));
  res.json({ count: items.length, items });
});
app.delete('/api/customer/library/:proxy', requireApiKey(), (req, res) => {
  const all = custLibAll();
  const lib = all[req.apiKey.id] || {};
  const key = decodeURIComponent(req.params.proxy);
  if (lib[key]) { delete lib[key]; all[req.apiKey.id] = lib; custLibSaveAll(all); }
  res.json({ ok: true, count: Object.keys(lib).length });
});
app.delete('/api/customer/library', requireApiKey(), (req, res) => {
  const all = custLibAll();
  all[req.apiKey.id] = {};
  custLibSaveAll(all);
  res.json({ ok: true });
});
app.get('/api/customer/library/export', requireApiKey(), (req, res) => {
  const lib = (custLibAll())[req.apiKey.id] || {};
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="proxy-library.txt"');
  res.send(Object.keys(lib).join('\n'));
});

// GET /api/customer/l2tp — list this key's own L2TP credentials (filtered by key_id)
app.get('/api/customer/l2tp', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const l2tp = l2tpLoad();
  // Only return credentials that belong to this key
  const users = Object.values(l2tp.users || {}).filter(u => u.key_id === k.id);
  res.json({ server_ip: SERVER_IP, psk: l2tp.psk, users });
});

// Helper: check if a key has access to a gateway (owns it OR admin-granted)
function keyCanAccessGateway(k, gwName) {
  const myGws = k.my_gateways || [];
  const allowedGws = k.allowed_gateways || [];
  if (myGws.includes(gwName)) return true;          // customer owns this tunnel
  if (allowedGws.length && allowedGws.includes(gwName)) return true; // admin granted
  return false;
}

// POST /api/customer/l2tp/gateway/:name — create or return existing L2TP user
// L2TP is only allowed on gateways the customer owns (proxy tunnels in my_gateways).
// Admin-granted shared gateways are NOT allowed — L2TP must route through the customer's own proxy.
app.post('/api/customer/l2tp/gateway/:name', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g, '');
  const myGws = k.my_gateways || [];
  if (!myGws.includes(name))
    return res.status(403).json({ error: 'L2TP is only available on your own proxy tunnels. Add a proxy first to create a tunnel.' });
  const gateways = gwLoad();
  if (!gateways[name]) return res.status(404).json({ error: 'Gateway not found' });
  const l2tp = l2tpLoad();
  // Check if already exists for this key+gateway
  const existingEntry = Object.values(l2tp.users || {}).find(u => u.key_id === k.id && u.gateway === name);
  if (existingEntry) return res.json({ server_ip: SERVER_IP, psk: l2tp.psk, user: existingEntry, created: false });
  // Create new user: username = keyPrefix + gateway abbreviation
  const keyPrefix = k.id.replace(/-/g,'').slice(0,8);
  const username = `${keyPrefix}`;
  const password = require('crypto').randomBytes(8).toString('hex');
  const chapName = `${name}__${username}`;
  const chapLine = `"${chapName}" * "${password}" *\n`;
  try {
    fs.appendFileSync(CHAP_SECRETS, chapLine);
  } catch(e) { return res.status(500).json({ error: 'Failed to write chap-secrets: ' + e.message }); }
  const newUser = { gateway: name, username, chap_name: chapName, password, key_id: k.id, created_at: new Date().toISOString() };
  if (!l2tp.users) l2tp.users = {};
  l2tp.users[chapName] = newUser;
  l2tpSave(l2tp);
  res.json({ server_ip: SERVER_IP, psk: l2tp.psk, user: newUser, created: true });
});

// GET /api/customer/proxies — list gateways owned by this API key (no extra permission needed)
app.get('/api/customer/proxies', requireApiKey(), (req, res) => {
  const k = req.apiKey;
  const gateways = gwLoad();
  const myGws = (k.my_gateways || []).map(n => {
    const g = gateways[n];
    if (!g) return null;
    const gCopy = { ...g };
    // Live service status
    try { execSync(`systemctl is-active openvpn-server@${n}`, { stdio:'ignore' }); gCopy.vpn_running = true; } catch(_) { gCopy.vpn_running = false; }
    try { execSync(`systemctl is-active tun2socks@${n}`, { stdio:'ignore' }); gCopy.tun_running = true; } catch(_) { gCopy.tun_running = false; }
    try { execSync(`systemctl is-active mitmproxy@${n}`, { stdio:'ignore' }); gCopy.mitm_running = true; } catch(_) { gCopy.mitm_running = false; }
    gCopy.running = gCopy.vpn_running && gCopy.tun_running;
    // Mask proxy password for display
    try { const u = new URL(gCopy.proxy_url); if (u.password) { u.password='***'; } gCopy.proxy_display = u.toString(); } catch(_) { gCopy.proxy_display = gCopy.proxy_url; }
    delete gCopy.proxy_url;
    return gCopy;
  }).filter(Boolean);
  res.json({ gateways: myGws });
});

// ── Customer gateway control (start/stop/restart/mitm/test/clients) ──────────
function _ownsOrFail(req, res) {
  const k = req.apiKey;
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const myGws = k.my_gateways || [];
  if (!myGws.includes(name)) { res.status(403).json({ error: 'Not your gateway' }); return null; }
  const gateways = gwLoad();
  if (!gateways[name]) { res.status(404).json({ error: 'Gateway not found' }); return null; }
  return { name, gw: gateways[name], gateways };
}

// POST /api/customer/gateway/:name/(start|stop|restart)
app.post('/api/customer/gateway/:name/:action(start|stop|restart)', requireApiKey(), (req, res) => {
  const ctx = _ownsOrFail(req, res); if (!ctx) return;
  const action = req.params.action;
  try {
    if (action === 'stop') {
      execSync(`systemctl stop openvpn-server@${ctx.name}`);
      execSync(`systemctl stop tun2socks@${ctx.name}`);
    } else {
      execSync(`systemctl ${action} tun2socks@${ctx.name}`);
      execSync(`systemctl ${action} openvpn-server@${ctx.name}`);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/customer/gateway/:name/mitm/(start|stop) — proxy to admin route
app.post('/api/customer/gateway/:name/mitm/:action(start|stop)', requireApiKey(), async (req, res) => {
  const ctx = _ownsOrFail(req, res); if (!ctx) return;
  try {
    const settings = settingsLoad();
    const token = settings.admin_password || VPN_TOKEN;
    const r = await fetch(`http://127.0.0.1:${PORT}/api/gateways/${encodeURIComponent(ctx.name)}/mitm/${req.params.action}`, {
      method: 'POST', headers: { 'x-vpn-token': token, 'Content-Type':'application/json' }
    });
    const d = await r.json().catch(()=>({}));
    res.status(r.status).json(d);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/customer/gateway/:name/clients — list OpenVPN client cert names this key owns on this gateway
app.get('/api/customer/gateway/:name/clients', requireApiKey(), (req, res) => {
  const ctx = _ownsOrFail(req, res); if (!ctx) return;
  const k = req.apiKey;
  const myClients = (k.vpn_clients || []).filter(c => c.gateway === ctx.name);
  res.json({ clients: myClients.map(c => ({ client_name: c.client_name, cert_name: c.cert_name, created_at: c.created_at })) });
});

// POST /api/customer/proxy — create a new VPN gateway from a proxy URL (any valid key)
app.post('/api/customer/proxy', requireApiKey(), async (req, res) => {
  const k = req.apiKey;
  const { proxy_url } = req.body;
  if (!proxy_url) return res.status(400).json({ error: 'proxy_url required' });
  // Auto-generate unique gateway name from key prefix + index
  const keys = keysLoad();
  const keyPrefix = k.id.replace(/-/g,'').slice(0,6);
  const myGws = keys[k.id].my_gateways || [];
  const gwIndex = myGws.length + 1;
  const name = `c${keyPrefix}${gwIndex}`;
  const gateways = gwLoad();
  if (gateways[name]) {
    // Try incrementing
    let idx = gwIndex + 1;
    while (gateways[`c${keyPrefix}${idx}`] && idx < 100) idx++;
    if (idx >= 100) return res.status(429).json({ error: 'Too many gateways' });
  }
  const finalName = gateways[name] ? `c${keyPrefix}${(() => { let i=gwIndex+1; while(gateways[`c${keyPrefix}${i}`]&&i<100)i++; return i; })()}` : name;
  try {
    // Re-use admin gateway creation via internal HTTP call (keeps logic DRY)
    const settings = settingsLoad();
    const token = settings.admin_password || VPN_TOKEN;
    const r = await fetch(`http://127.0.0.1:${PORT}/api/gateways`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-vpn-token': token },
      body: JSON.stringify({ name: finalName, proxy_url }),
    });
    const d = await r.json();
    if (!r.ok) return res.status(r.status).json(d);
    // Track ownership
    if (!keys[k.id].my_gateways) keys[k.id].my_gateways = [];
    keys[k.id].my_gateways.push(finalName);
    keysSave(keys);
    // Auto-generate OpenVPN client cert for this key on the new gateway
    const gateways2 = gwLoad();
    const gw2 = gateways2[finalName];
    if (gw2) {
      const certName = `${finalName}_${keyPrefix}_default`;
      try {
        execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-req ${certName} nopass 2>&1`, { shell: '/bin/bash' });
        execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa sign-req client ${certName} 2>&1`, { shell: '/bin/bash' });
        const ovpn = buildOvpn(gw2, certName);
        const keys2 = keysLoad();
        if (!keys2[k.id].vpn_clients) keys2[k.id].vpn_clients = [];
        keys2[k.id].vpn_clients.push({ gateway: finalName, client_name: 'default', cert_name: certName, created_at: new Date().toISOString() });
        keysSave(keys2);
        return res.status(201).json({ ok: true, gateway: finalName, vpn_port: d.vpn_port, exit_ip: d.exit_ip, ovpn, cert_name: certName });
      } catch(e) {
        return res.status(201).json({ ok: true, gateway: finalName, vpn_port: d.vpn_port, exit_ip: d.exit_ip, ovpn_error: e.message });
      }
    }
    res.status(201).json({ ok: true, gateway: finalName, vpn_port: d.vpn_port, exit_ip: d.exit_ip });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/customer/proxy/:name — delete a customer-owned gateway (any valid key)
app.delete('/api/customer/proxy/:name', requireApiKey(), async (req, res) => {
  const k = req.apiKey;
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const myGws = k.my_gateways || [];
  if (!myGws.includes(name)) return res.status(403).json({ error: 'Not your gateway' });
  try {
    const settings = settingsLoad();
    const token = settings.admin_password || VPN_TOKEN;
    const r = await fetch(`http://127.0.0.1:${PORT}/api/gateways/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: { 'x-vpn-token': token },
    });
    const d = await r.json();
    if (!r.ok) return res.status(r.status).json(d);
    const keys = keysLoad();
    keys[k.id].my_gateways = myGws.filter(n => n !== name);
    // Also remove vpn_clients for this gateway
    if (keys[k.id].vpn_clients) {
      keys[k.id].vpn_clients = keys[k.id].vpn_clients.filter(c => c.gateway !== name);
    }
    keysSave(keys);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/customer/gateway/:name/ip — check current exit IP through the proxy
app.get('/api/customer/gateway/:name/ip', requireApiKey(), async (req, res) => {
  const k = req.apiKey;
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const myGws = k.my_gateways || [];
  if (!myGws.includes(name)) return res.status(403).json({ error: 'Not your gateway' });
  const gwData = gwLoad();
  const gw = gwData[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  if (!gw.proxy_url) return res.status(400).json({ error: 'No proxy configured' });
  try {
    const agent = createAgent(gw.proxy_url);
    const { data } = await axios.get('https://api.ipify.org?format=json', axiosCfg(agent, 10000));
    const ip = data.ip || String(data);
    // Persist exit_ip if it changed
    if (gw.exit_ip !== ip) {
      const gwData2 = gwLoad();
      if (gwData2[name]) { gwData2[name].exit_ip = ip; gwSave(gwData2); }
    }
    res.json({ ip, changed: gw.exit_ip !== ip });
  } catch(e) {
    res.status(502).json({ error: 'Could not reach proxy: ' + e.message });
  }
});

// ── VPN API routes ─────────────────────────────────────────────────────────────
function requireVpnToken(req, res, next) {
  const token = req.headers['x-vpn-token'] || req.query.token;
  const settings = settingsLoad();
  const validToken = settings.admin_password || VPN_TOKEN;
  if (token !== validToken) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Per-gateway access check used by the public self-serve page (g.html).
// Allows: (a) admin via x-vpn-token / ?token, OR
//         (b) customer API key (x-api-key / ?api_key) that owns this gateway —
//             ownership = key has a vpn_clients entry for this gateway,
//             OR allowed_gateways list explicitly includes it.
// Returns { ok, status, error, isAdmin, apiKey } so it can be reused by both
// Express middleware and the WebSocket upgrade handler.
function validateGatewayAccess(name, creds) {
  const settings = settingsLoad();
  const validToken = settings.admin_password || VPN_TOKEN;
  const tok = creds && creds.token;
  if (tok && tok === validToken) return { ok: true, isAdmin: true };
  const k = creds && creds.apiKey;
  if (!k) return { ok: false, status: 401, error: 'Authentication required (x-api-key or x-vpn-token)' };
  const keys = keysLoad();
  const entry = Object.values(keys).find(x => x.key === k);
  if (!entry) return { ok: false, status: 401, error: 'Invalid API key' };
  if (!entry.enabled) return { ok: false, status: 403, error: 'API key disabled' };
  if (entry.expires_at && new Date(entry.expires_at) < new Date())
    return { ok: false, status: 403, error: 'API key expired' };
  const owns = (entry.vpn_clients || []).some(c => c.gateway === name);
  const allowed = Array.isArray(entry.allowed_gateways) && entry.allowed_gateways.includes(name);
  if (!owns && !allowed)
    return { ok: false, status: 403, error: 'You do not have access to this gateway' };
  return { ok: true, isAdmin: false, apiKey: entry };
}

function requireGatewayAccess(req, res, next) {
  const name = String(req.params.name || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!name) return res.status(400).json({ error: 'Invalid gateway name' });
  const r = validateGatewayAccess(name, {
    token:  req.headers['x-vpn-token'] || req.query.token,
    apiKey: req.headers['x-api-key']   || req.query.api_key,
  });
  if (!r.ok) return res.status(r.status).json({ error: r.error });
  req.gwName = name;
  req.isAdmin = r.isAdmin;
  req.apiKey = r.apiKey || null;
  next();
}

// POST /api/admin/login — authenticate and return session token
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  const settings = settingsLoad();
  const validToken = settings.admin_password || VPN_TOKEN;
  if (!password || password !== validToken)
    return res.status(401).json({ error: 'Invalid password' });
  res.json({ ok: true, token: validToken });
});

// GET /api/admin/stats — dashboard overview statistics
app.get('/api/admin/stats', requireVpnToken, (req, res) => {
  const gateways = gwLoad();
  const keys = keysLoad();
  const l2tp = l2tpLoad();
  const gwList = Object.values(gateways);
  const keyList = Object.values(keys);
  const now = new Date();
  let gwRunning = 0;
  for (const gw of gwList) {
    try {
      const r = execSync(`systemctl is-active openvpn-server@${gw.name} 2>/dev/null`,
        { shell: '/bin/bash', timeout: 1000 }).toString().trim();
      if (r === 'active') gwRunning++;
    } catch (_) {}
  }
  const activeKeys  = keyList.filter(k => k.enabled && (!k.expires_at || new Date(k.expires_at) > now)).length;
  const expiredKeys = keyList.filter(k => k.enabled && k.expires_at && new Date(k.expires_at) <= now).length;
  const totalChecks = keyList.reduce((a, k) => a + (k.proxy_checks_used || 0), 0);
  const totalBwBytes = keyList.reduce((a, k) => a + (k.bandwidth_used_bytes || 0), 0);
  const totalOvClients = gwList.reduce((a, g) => a + (g.client_count || 0), 0);
  const l2tpUsers = Object.keys(l2tp.users || {}).length;
  const settings = settingsLoad();
  res.json({
    gateways: { total: gwList.length, running: gwRunning, stopped: gwList.length - gwRunning },
    keys: { total: keyList.length, active: activeKeys, expired: expiredKeys, disabled: keyList.filter(k => !k.enabled).length },
    clients: { openvpn: totalOvClients, l2tp: l2tpUsers, total: totalOvClients + l2tpUsers },
    usage: { checks: totalChecks, bandwidth_bytes: totalBwBytes },
    server_ip: SERVER_IP,
    brand_name: settings.brand_name || 'VPN Panel',
  });
});

// GET /api/admin/settings
app.get('/api/admin/settings', requireVpnToken, (req, res) => {
  const settings = settingsLoad();
  res.json({ brand_name: settings.brand_name || 'VPN Panel', server_ip: SERVER_IP });
});

// POST /api/admin/settings — update branding and/or password
app.post('/api/admin/settings', requireVpnToken, (req, res) => {
  const settings = settingsLoad();
  const { brand_name, admin_password, current_password } = req.body || {};
  if (admin_password) {
    const validToken = settings.admin_password || VPN_TOKEN;
    if (!current_password || current_password !== validToken)
      return res.status(401).json({ error: 'Current password is incorrect' });
    if (admin_password.length < 8)
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    settings.admin_password = admin_password;
  }
  if (brand_name !== undefined) settings.brand_name = brand_name.trim().slice(0, 50) || 'VPN Panel';
  settingsSave(settings);
  const currentToken = settings.admin_password || VPN_TOKEN;
  res.json({ ok: true, token: currentToken });
});


// WireGuard: list clients
app.get('/api/vpn/wg/clients', requireVpnToken, (req, res) => {
  const clients = wgLoadClients();
  res.json({ count: Object.keys(clients).length, clients: Object.values(clients).map(c => ({ name: c.name, ip: c.ip, createdAt: c.createdAt })) });
});

// WireGuard: create client
app.post('/api/vpn/wg/client', requireVpnToken, (req, res) => {
  const name = (req.body.name || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
  if (!name) return res.status(400).json({ error: 'Invalid name' });
  const clients = wgLoadClients();
  if (clients[name]) return res.status(409).json({ error: 'Client already exists' });
  try {
    const result = wgCreateClient(name);
    // Generate QR
    const qr = execSync(`echo "${result.conf.replace(/"/g,'\\"')}" | qrencode -t png -o -`, { maxBuffer: 2*1024*1024 });
    result.qr = `data:image/png;base64,${qr.toString('base64')}`;
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// WireGuard: delete client
app.delete('/api/vpn/wg/client/:name', requireVpnToken, (req, res) => {
  const ok = wgDeleteClient(req.params.name);
  if (!ok) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// WireGuard: download .conf
app.get('/api/vpn/wg/client/:name/conf', requireVpnToken, (req, res) => {
  const clients = wgLoadClients();
  const c = clients[req.params.name];
  if (!c) return res.status(404).end();
  const serverPub = fs.readFileSync(path.join(WG_DIR, 'server_public.key'), 'utf8').trim();
  const conf = `[Interface]\nPrivateKey = ${c.privKey}\nAddress = ${c.ip}/24\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = ${serverPub}\nPresharedKey = ${c.psk}\nEndpoint = ${SERVER_IP}:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${c.name}.conf"`);
  res.send(conf);
});

// WireGuard: QR code
app.get('/api/vpn/wg/client/:name/qr', requireVpnToken, (req, res) => {
  const clients = wgLoadClients();
  const c = clients[req.params.name];
  if (!c) return res.status(404).end();
  const serverPub = fs.readFileSync(path.join(WG_DIR, 'server_public.key'), 'utf8').trim();
  const conf = `[Interface]\nPrivateKey = ${c.privKey}\nAddress = ${c.ip}/24\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = ${serverPub}\nPresharedKey = ${c.psk}\nEndpoint = ${SERVER_IP}:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
  try {
    const qr = execSync(`printf '%s' "${conf.replace(/'/g,"'\\''").replace(/"/g,'\\"')}" | qrencode -t png -o -`, { shell: '/bin/bash', maxBuffer: 2*1024*1024 });
    res.setHeader('Content-Type', 'image/png');
    res.send(qr);
  } catch(e) { res.status(500).end(); }
});

// Shadowsocks: get info
app.get('/api/vpn/ss/info', requireVpnToken, (req, res) => {
  const cfg = ssGetConfig();
  if (!cfg) return res.status(500).json({ error: 'Cannot read SS config' });
  res.json({ server: SERVER_IP, port: cfg.server_port, method: cfg.method, password: cfg.password, link: ssLink(cfg) });
});

// Shadowsocks: reset password
app.post('/api/vpn/ss/reset', requireVpnToken, (req, res) => {
  const cfg = ssGetConfig();
  if (!cfg) return res.status(500).json({ error: 'Cannot read SS config' });
  const newPass = require('crypto').randomBytes(16).toString('hex');
  cfg.password = newPass;
  fs.writeFileSync(SS_CONF, JSON.stringify(cfg, null, 2));
  execSync('systemctl restart shadowsocks-libev');
  res.json({ ok: true, password: newPass, link: ssLink(cfg) });
});

// WireGuard: server status
app.get('/api/vpn/wg/status', requireVpnToken, (req, res) => {
  try {
    const out = execSync('wg show wg0').toString();
    res.json({ running: true, raw: out });
  } catch(_) { res.json({ running: false }); }
});

// ── Gateway API (tun2socks + policy routing) ─────────────────────────────────
const GW_DIR = '/etc/openvpn/gateways';
const GW_DATA = path.join(__dirname, 'gateways.json');

// Country → DNS mapping: DoH (HTTPS:443) upstreams via SOCKS proxy + direct fallback IP (only used if dnsproxy down).
// DoT (port 853) is NOT used because many SOCKS proxies block/throttle non-443 ports → silent timeouts → dnsproxy crashes.
// DoH always uses 443 (the same port as normal HTTPS) so it tunnels reliably through any SOCKS5/HTTP CONNECT proxy.
const COUNTRY_DNS = {
  CN: { u1: 'https://dns.alidns.com/dns-query',            u2: 'https://doh.pub/dns-query',                      fallback: '223.5.5.5' },
  HK: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  TW: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  JP: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  KR: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  SG: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  RU: { u1: 'https://dns.google/dns-query',                u2: 'https://dns.quad9.net/dns-query',                fallback: '8.8.8.8'   },
  IR: { u1: 'https://dns.google/dns-query',                u2: 'https://dns.quad9.net/dns-query',                fallback: '8.8.8.8'   },
  TR: { u1: 'https://dns.google/dns-query',                u2: 'https://one.one.one.one/dns-query',              fallback: '8.8.8.8'   },
  VN: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  TH: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  ID: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  MY: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  IN: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  US: { u1: 'https://dns.google/dns-query',                u2: 'https://one.one.one.one/dns-query',              fallback: '8.8.8.8'   },
  GB: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  DE: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  FR: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  NL: { u1: 'https://one.one.one.one/dns-query',           u2: 'https://dns.google/dns-query',                   fallback: '1.1.1.1'   },
  _:  { u1: 'https://dns.google/dns-query',                u2: 'https://one.one.one.one/dns-query',              fallback: '8.8.8.8'   },  // default
};

// Quick country lookup via ipinfo.io (free, no auth, 50k/mo)
async function getCountryCode(ip) {
  try {
    const { data } = await axios.get(`https://ipinfo.io/${encodeURIComponent(ip)}/country`, {
      timeout: 5000,
      headers: { 'User-Agent': 'proxy-checker/1.0', 'Accept': 'text/plain' },
    });
    return String(data).trim().toUpperCase().replace(/[^A-Z]/g, '').slice(0, 2) || '';
  } catch(_) { return ''; }
}
fs.mkdirSync(GW_DIR, { recursive: true });

function gwLoad() {
  try { return JSON.parse(fs.readFileSync(GW_DATA, 'utf8')); } catch(_) { return {}; }
}
function gwSave(data) { fs.writeFileSync(GW_DATA, JSON.stringify(data, null, 2)); }

// Allocate unique resources per gateway
function gwAllocResources(gateways) {
  const usedTables  = new Set(Object.values(gateways).map(g => g.table_id));
  const usedSubnets = new Set(Object.values(gateways).map(g => g.vpn_subnet_index));
  const usedT2S     = new Set(Object.values(gateways).map(g => g.t2s_subnet_index));
  let tableId = 100;
  while (usedTables.has(tableId)) tableId++;
  let vpnIdx = 0;
  while (usedSubnets.has(vpnIdx)) vpnIdx++;
  let t2sIdx = 0;
  while (usedT2S.has(t2sIdx)) t2sIdx++;
  return { tableId, vpnIdx, t2sIdx };
}

// Check if a UDP port is busy at OS level
function isUdpPortBusy(port) {
  try {
    const out = execSync(`ss -lnuH 'sport = :${port}'`, { encoding:'utf8' });
    return out.trim().length > 0;
  } catch(_) { return false; }
}

// Pick first free UDP port starting from `start`, skipping ones used by other gateways or OS sockets
function gwPickPort(gateways, start = 1195) {
  const used = new Set(Object.values(gateways).map(g => g.vpn_port));
  // Also avoid common OpenVPN/WG/SS ports
  [1194, 51820, 8388].forEach(p => used.add(p));
  let p = start;
  while (p < 65535) {
    if (!used.has(p) && !isUdpPortBusy(p)) return p;
    p++;
  }
  throw new Error('No free UDP port available');
}

// Validate & test proxy (auto-detect SOCKS5/HTTP). Returns exit IP.
async function gwTestProxy(proxyUrl) {
  const r = await detectAndTestProxy(proxyUrl);
  return r.exitIp;
}

// GET all gateways
app.get('/api/gateways', requireVpnToken, (req, res) => {
  const gateways = gwLoad();
  const result = [];
  for (const name in gateways) {
    const gw = { ...gateways[name] };
    try { execSync(`systemctl is-active openvpn-server@${gw.name}`); gw.vpn_running = true; } catch(_) { gw.vpn_running = false; }
    try { execSync(`systemctl is-active tun2socks@${gw.name}`); gw.tun_running = true; } catch(_) { gw.tun_running = false; }
    try { execSync(`systemctl is-active mitmproxy@${gw.name}`); gw.mitm_running = true; } catch(_) { gw.mitm_running = false; }
    gw.running = gw.vpn_running && gw.tun_running;
    // Redact password in proxy_url for display
    try {
      const u = new URL(gw.proxy_url);
      if (u.password) u.password = '***';
      gw.proxy_display = u.toString();
    } catch(_) { gw.proxy_display = gw.proxy_url; }
    delete gw.proxy_url_full;
    result.push(gw);
  }
  res.json({ gateways: result });
});

// POST create gateway
app.post('/api/gateways', requireVpnToken, async (req, res) => {
  try {
    const { name, proxy_url, vpn_port } = req.body;
    if (!name || !proxy_url) return res.status(400).json({ error: 'Missing params' });
    if (!/^[a-zA-Z0-9_-]{1,24}$/.test(name)) return res.status(400).json({ error: 'Invalid name' });

    const gateways = gwLoad();
    if (gateways[name]) return res.status(409).json({ error: 'Gateway exists' });

    // Auto-pick port if not provided, otherwise validate the requested one
    let port;
    if (vpn_port) {
      port = parseInt(vpn_port, 10);
      if (!port || port < 1024 || port > 65535) return res.status(400).json({ error: 'Invalid port' });
      for (const g of Object.values(gateways)) {
        if (g.vpn_port === port) return res.status(409).json({ error: `Port ${port} already used by gateway ${g.name}` });
      }
      if (isUdpPortBusy(port)) return res.status(409).json({ error: `Port ${port} is already in use on the server` });
    } else {
      port = gwPickPort(gateways);
    }

    // 1. Auto-detect proxy type (SOCKS5 / HTTP) + live-test (combined step)
    let detected;
    try { detected = await detectAndTestProxy(proxy_url); }
    catch(e) { return res.status(400).json({ error: 'Proxy test failed: ' + e.message }); }
    const exitIp = detected.exitIp;
    const normalizedProxy = detected.url;          // canonical URL stored in tun2socks.env
    const proxyScheme = detected.scheme;           // 'socks5' or 'http'

    // tun2socks only supports SOCKS5 / SS / HTTP CONNECT — both are fine.
    // (HTTP CONNECT does NOT carry UDP, so DNS/UDP from VPN clients will be blocked by the LEAK chain.)
    if (proxyScheme === 'http') {
      console.warn(`[gw ${name}] HTTP proxy detected — UDP will not work, only TCP.`);
    }

    // 3. Allocate resources
    const { tableId, vpnIdx, t2sIdx } = gwAllocResources(gateways);
    const vpnSubnet  = `10.${100 + vpnIdx}.0.0/24`;
    const vpnNetwork = `10.${100 + vpnIdx}.0.0`;
    const vpnDnsIp   = `10.${100 + vpnIdx}.0.1`;   // OpenVPN server IP — clients' DNS will also be pushed through tunnel
    const t2sDev     = `t2s-${name}`.slice(0, 15);  // IFNAMSIZ=16
    const t2sIp      = `10.${200 + t2sIdx}.0.1`;
    const gwPath     = path.join(GW_DIR, name);
    fs.mkdirSync(gwPath, { recursive: true });

    // 3b. Pre-flight cleanup — kill anything left over from a previous gateway with the same indexes
    //     (orphan dnsproxy still bound to port 15300+vpnIdx, stale TUN dev, leftover symlink, etc.)
    const dnsPort = 15300 + vpnIdx;
    try { execSync(`fuser -k ${dnsPort}/tcp ${dnsPort}/udp 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
    try { execSync(`ip link delete ${t2sDev} 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
    try { fs.unlinkSync(`/etc/openvpn/server/${name}.conf`); } catch(_){}

    // 4. tun2socks env file
    fs.writeFileSync(path.join(gwPath, 'tun2socks.env'),
      `TUN_DEV=${t2sDev}\nTUN_IP=${t2sIp}\nPROXY_URL=${normalizedProxy}\n`);

    // 4b. Create per-gateway dnsproxy OS user (isolated uid → isolated fwmark → isolated routing table)
    const gwUser = `dnsproxy-${name}`;
    try { execSync(`id ${gwUser}`, { stdio:'ignore' }); } catch(_) {
      execSync(`useradd -r -M -s /bin/false ${gwUser}`);
    }
    const gwUid = parseInt(execSync(`id -u ${gwUser}`).toString().trim(), 10);
    // fwmark = TABLE_ID (decimal) mapped to hex, unique per gateway
    const fwmark = `0x${tableId.toString(16)}`;

    // 4c. Per-gateway mitmproxy OS user (so its outbound is fwmark-routed via THIS gateway's tunnel)
    const mitmUser = `mitm-${name}`;
    try { execSync(`id ${mitmUser}`, { stdio:'ignore' }); } catch(_) {
      execSync(`useradd -r -M -s /bin/false -d /var/lib/mitmproxy ${mitmUser}`);
    }
    const mitmUid  = parseInt(execSync(`id -u ${mitmUser}`).toString().trim(), 10);
    const mitmPort = 18080 + vpnIdx;

    // 5. routing env for up.sh/down.sh (now also carries MITM_UID + MITM_PORT)
    fs.writeFileSync(path.join(gwPath, 'routing.env'),
      `TABLE_ID=${tableId}\nTUN_DEV=${t2sDev}\nVPN_SUBNET=${vpnSubnet}\nDNSPROXY_UID=${gwUid}\nFWMARK=${fwmark}\nMITM_UID=${mitmUid}\nMITM_PORT=${mitmPort}\n`);

    // 5a. mitm.env consumed by mitmproxy@<name>.service + capture-addon.py
    let captureToken = '';
    try { captureToken = fs.readFileSync('/etc/openvpn/mitm-ca/.capture-token', 'utf8').trim(); } catch(_){}
    fs.writeFileSync(path.join(gwPath, 'mitm.env'),
      `MITM_PORT=${mitmPort}\nMITM_UID=${mitmUid}\nGW_NAME=${name}\nCAPTURE_URL=http://127.0.0.1:${PORT}/api/_internal/capture\nCAPTURE_TOKEN=${captureToken}\nMAX_BODY=65536\n`);
    // Allow the mitm user to read its env file (systemd reads it as the User= user)
    try { execSync(`chgrp ${mitmUser} ${path.join(gwPath, 'mitm.env')} && chmod 640 ${path.join(gwPath, 'mitm.env')}`, { shell:'/bin/bash' }); } catch(_){}

    // 5b. Detect country from exit IP → select per-country DNS servers
    const countryCode = await getCountryCode(exitIp);
    const dnsCfg = COUNTRY_DNS[countryCode] || COUNTRY_DNS['_'];

    // dnsproxy env: upstreams chosen by proxy's country (routes through SOCKS)
    // Keep explicit fallback upstreams so DNS does not stall when one resolver is flaky.
    fs.writeFileSync(path.join(gwPath, 'dnsproxy.env'),
      `DNS_PORT=${dnsPort}\nDNS_PORT_BOOTSTRAP=tcp://8.8.8.8:53\nDNS_UPSTREAM_1=${dnsCfg.u1}\nDNS_UPSTREAM_2=${dnsCfg.u2}\nDNS_FALLBACK_1=${dnsCfg.u1}\nDNS_FALLBACK_2=${dnsCfg.u2}\n`);

    // dnsmasq-gw env: per-gateway resolver listening on the VPN gateway IP
    // DNS_FALLBACK intentionally omitted — raw IP fallback bypasses tun2socks → DNS leak.
    const vpnGwIp = `10.${100 + vpnIdx}.0.1`;
    fs.writeFileSync(path.join(gwPath, 'dnsmasq-gw.env'),
      `VPN_GW_IP=${vpnGwIp}\nDNS_PORT=${dnsPort}\n`);

    // 6. OpenVPN server config (DNS pushed is the VPN server itself → dnsmasq or redirect via tun2socks)
    //    To avoid DNS leak without running local resolver, we push public DNS but force all egress through tun2socks TUN,
    //    and block all FORWARD from VPN subnet except → tun2socks TUN (see up.sh).
    const ovpnConf = `# Auto-generated for gateway: ${name}
port ${port}
proto udp
dev tun
ca   ${gwPath}/ca.crt
cert ${gwPath}/server.crt
key  ${gwPath}/server.key
dh   ${gwPath}/dh.pem
tls-auth ${gwPath}/ta.key 0
topology subnet
server ${vpnNetwork} 255.255.255.0
ifconfig-pool-persist ${gwPath}/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 10.${100 + vpnIdx}.0.1"
push "block-outside-dns"
compress lz4-v2
mute 10
keepalive 10 120
cipher AES-256-GCM
auth SHA256
duplicate-cn
explicit-exit-notify 1
max-clients 50
persist-key
persist-tun
tun-mtu 1380
mssfix 1320
sndbuf 0
rcvbuf 0
push "sndbuf 0"
push "rcvbuf 0"
status ${gwPath}/status.log
log-append ${gwPath}/openvpn.log
verb 3
script-security 2
up   "/etc/openvpn/gateways/up.sh ${name}"
down "/etc/openvpn/gateways/down.sh ${name}"
`;
    fs.writeFileSync(path.join(gwPath, `${name}.conf`), ovpnConf);

    // 7. Copy PKI material
    for (const f of ['ca.crt','server.crt','server.key','dh.pem','ta.key']) {
      fs.copyFileSync(path.join('/etc/openvpn/server', f), path.join(gwPath, f));
    }

    // 8. Save state
    gateways[name] = {
      name, proxy_url: normalizedProxy, proxy_scheme: proxyScheme,
      vpn_port: port, exit_ip: exitIp,
      country: countryCode, dns_upstream1: dnsCfg.u1, dns_fallback: dnsCfg.fallback,
      table_id: tableId, vpn_subnet_index: vpnIdx, t2s_subnet_index: t2sIdx,
      vpn_subnet: vpnSubnet, t2s_dev: t2sDev,
      gw_user: gwUser, gw_uid: gwUid, fwmark,
      mitm_user: mitmUser, mitm_uid: mitmUid, mitm_port: mitmPort, mitm_enabled: false,
      client_count: 0, created_at: new Date().toISOString(),
    };
    gwSave(gateways);

    // 9. Enable + start both services (tun2socks FIRST, then openvpn)
    execSync(`systemctl daemon-reload`);
    execSync(`systemctl enable --now tun2socks@${name}`);
    // dnsproxy: best-effort start (only if dnsproxy binary + user exist)
    try { execSync(`id dnsproxy && test -x /usr/local/bin/dnsproxy && systemctl enable --now dnsproxy@${name}`, { shell:'/bin/bash' }); } catch(e) { console.warn('[gw dnsproxy]', e.message); }
    // dnsmasq-gw: per-gateway DNS resolver (listens on VPN gateway IP via bind-dynamic)
    try { execSync(`systemctl enable --now dnsmasq-gw@${name}`); } catch(e) { console.warn('[gw dnsmasq-gw]', e.message); }
    // watchdog timer: auto-restart tun2socks if proxy becomes unresponsive
    try { execSync(`systemctl enable --now tun2socks-watchdog@${name}.timer`); } catch(e) { console.warn('[gw watchdog]', e.message); }
    // Symlink openvpn server conf so systemd finds it
    const ovSymlink = `/etc/openvpn/server/${name}.conf`;
    if (!fs.existsSync(ovSymlink)) fs.symlinkSync(path.join(gwPath, `${name}.conf`), ovSymlink);
    execSync(`systemctl enable --now openvpn-server@${name}`);

    // 10. Open firewall UDP port (idempotent)
    try {
      execSync(`iptables -C INPUT -p udp --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${port} -j ACCEPT`, { shell:'/bin/bash' });
      execSync(`iptables-save > /etc/iptables/rules.v4 2>/dev/null || true`, { shell:'/bin/bash' });
    } catch(e) { console.warn('[gw firewall]', e.message); }

    // 11. Auto-create default L2TP user for this gateway
    // Username = gateway name, password = random 10-char alphanumeric
    try {
      const l2tpData = l2tpLoad();
      const l2tpPass = require('crypto').randomBytes(6).toString('hex'); // 12 hex chars
      const l2tpKey = `${name}__${name}`;
      if (!l2tpData.users[l2tpKey]) {
        l2tpData.users[l2tpKey] = {
          gateway: name, username: name, password: l2tpPass,
          created_at: new Date().toISOString(),
        };
        l2tpSave(l2tpData);
        l2tpSyncChap(l2tpData);
      }
    } catch(e) { console.warn('[gw l2tp auto-user]', e.message); }

    res.status(201).json({ ok: true, name, vpn_port: port, exit_ip: exitIp });
  } catch(e) {
    console.error('[gw create]', e);
    res.status(500).json({ error: e.message || 'Internal error' });
  }
});

// DELETE gateway (full cleanup: stop services, kill orphan procs, drop firewall, remove files)
app.delete('/api/gateways/:name', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  if (!gateways[name]) return res.status(404).json({ error: 'Not found' });
  const gw = gateways[name];

  // 1. Stop & disable services (ignore errors — units may already be down)
  for (const unit of [
    `openvpn-server@${name}`,
    `tun2socks-watchdog@${name}.timer`,
    `mitmproxy@${name}`,
    `dnsmasq-gw@${name}`,
    `dnsproxy@${name}`,
    `tun2socks@${name}`,
  ]) {
    try { execSync(`systemctl disable --now ${unit}`, { stdio:'ignore' }); } catch(_){}
    try { execSync(`systemctl reset-failed ${unit}`, { stdio:'ignore' }); } catch(_){}
  }

  // 2. Kill any orphan procs left holding the gateway's resources (port / IP / TUN dev)
  //    These can survive `systemctl disable --now` if the service crash-looped or the binary forked.
  try {
    const dnsPort = 15300 + (gw.vpn_subnet_index ?? 0);
    execSync(`fuser -k ${dnsPort}/tcp ${dnsPort}/udp 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' });
  } catch(_){}
  if (gw.mitm_port) {
    try { execSync(`fuser -k ${gw.mitm_port}/tcp 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
  }
  if (gw.gw_user) {
    try { execSync(`pkill -9 -u ${gw.gw_user} 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
  }
  if (gw.mitm_user) {
    try { execSync(`pkill -9 -u ${gw.mitm_user} 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
  }
  if (gw.t2s_dev) {
    try { execSync(`ip link delete ${gw.t2s_dev} 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
  }
  // Drop the per-gateway PREROUTING REDIRECT (no-op if MITM was not enabled)
  if (gw.vpn_subnet && gw.mitm_port) {
    try { execSync(`iptables -t nat -D PREROUTING -s ${gw.vpn_subnet} -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port ${gw.mitm_port} 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' }); } catch(_){}
  }

  // 3. Remove per-gateway dnsproxy + mitm OS users
  try { execSync(`userdel dnsproxy-${name} 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
  try { execSync(`userdel mitm-${name}     2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}

  // 4. Drop firewall rule (UDP listening port)
  if (gw.vpn_port) {
    try {
      execSync(`iptables -D INPUT -p udp --dport ${gw.vpn_port} -j ACCEPT 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' });
      execSync(`iptables-save > /etc/iptables/rules.v4 2>/dev/null || true`, { shell:'/bin/bash', stdio:'ignore' });
    } catch(_){}
  }

  // 5. Remove openvpn config symlink + gateway dir
  try { fs.unlinkSync(`/etc/openvpn/server/${name}.conf`); } catch(_){}
  try { fs.rmSync(path.join(GW_DIR, name), { recursive: true, force: true }); } catch(_){}

  delete gateways[name];
  gwSave(gateways);

  // 6. Remove all L2TP users for this gateway
  try {
    const l2tpData = l2tpLoad();
    const before = Object.keys(l2tpData.users).length;
    Object.keys(l2tpData.users).forEach(k => {
      if (l2tpData.users[k].gateway === name) delete l2tpData.users[k];
    });
    if (Object.keys(l2tpData.users).length !== before) {
      l2tpSave(l2tpData);
      l2tpSyncChap(l2tpData);
    }
  } catch(e) { console.warn('[gw delete l2tp]', e.message); }

  res.json({ ok: true });
});

// ── MITM (HTTPS interception) toggle per gateway ─────────────────────────────
// Starts/stops mitmproxy@<name> and adds/removes the iptables PREROUTING REDIRECT
// for TCP 80/443 from this gateway's VPN subnet. State is persisted to gateway record
// + a marker file so up.sh can re-arm the rule when OpenVPN restarts.
app.post('/api/gateways/:name/mitm/:action(start|stop|status)', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const action = req.params.action;
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  if (!gw.mitm_port || !gw.vpn_subnet) return res.status(400).json({ error: 'Gateway has no MITM config (recreate it)' });

  const markerFile = path.join(GW_DIR, name, 'mitm.enabled');
  const redirectRuleArgs = `-s ${gw.vpn_subnet} -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port ${gw.mitm_port}`;

  if (action === 'status') {
    let active = false;
    try { execSync(`systemctl is-active mitmproxy@${name}`, { stdio:'ignore' }); active = true; } catch(_){}
    let ruleActive = false;
    try { execSync(`iptables -t nat -C PREROUTING ${redirectRuleArgs} 2>/dev/null`, { shell:'/bin/bash', stdio:'ignore' }); ruleActive = true; } catch(_){}
    return res.json({ name, mitm_active: active, redirect_active: ruleActive, mitm_port: gw.mitm_port, marker: fs.existsSync(markerFile) });
  }

  try {
    if (action === 'start') {
      try { execSync(`systemctl daemon-reload`); } catch(_){}
      try { execSync(`systemctl reset-failed mitmproxy@${name}`, { stdio:'ignore' }); } catch(_){}
      execSync(`systemctl enable --now mitmproxy@${name}`);
      // Add PREROUTING REDIRECT (idempotent)
      execSync(`iptables -t nat -C PREROUTING ${redirectRuleArgs} 2>/dev/null || iptables -t nat -I PREROUTING 1 ${redirectRuleArgs}`, { shell:'/bin/bash' });
      // Block QUIC (UDP/443) + UDP/80 → force browser fallback to TCP so mitm có thể bắt
      for (const dport of [443, 80]) {
        const rule = `-s ${gw.vpn_subnet} -p udp --dport ${dport} -j REJECT --reject-with icmp-port-unreachable`;
        try { execSync(`iptables -C FORWARD ${rule} 2>/dev/null || iptables -I FORWARD 1 ${rule}`, { shell:'/bin/bash' }); } catch(_){}
      }
      try { execSync(`iptables-save > /etc/iptables/rules.v4 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
      // Persist marker so up.sh can restore the rule after an openvpn restart
      fs.writeFileSync(markerFile, '1\n');
      gw.mitm_enabled = true;
      gateways[name] = gw; gwSave(gateways);
      return res.json({ ok: true, name, mitm_active: true, mitm_port: gw.mitm_port });
    }
    if (action === 'stop') {
      // Remove redirect first so clients fail-open back to direct (no MITM hijack)
      try { execSync(`iptables -t nat -D PREROUTING ${redirectRuleArgs} 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
      // Remove QUIC block
      for (const dport of [443, 80]) {
        const rule = `-s ${gw.vpn_subnet} -p udp --dport ${dport} -j REJECT --reject-with icmp-port-unreachable`;
        try { execSync(`iptables -D FORWARD ${rule} 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
      }
      try { execSync(`systemctl disable --now mitmproxy@${name}`, { stdio:'ignore' }); } catch(_){}
      try { fs.unlinkSync(markerFile); } catch(_){}
      gw.mitm_enabled = false;
      gateways[name] = gw; gwSave(gateways);
      return res.json({ ok: true, name, mitm_active: false });
    }
  } catch(e) {
    console.error('[mitm toggle]', e);
    return res.status(500).json({ error: e.message || 'mitm toggle failed' });
  }
});

// start/stop/restart (restricted via regex so /client and /test don't match here)
app.post('/api/gateways/:name/:action(start|stop|restart)', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const action = req.params.action;
  if (!['start','stop','restart'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
  try {
    if (action === 'stop') {
      execSync(`systemctl stop openvpn-server@${name}`);
      execSync(`systemctl stop tun2socks@${name}`);
    } else {
      execSync(`systemctl ${action} tun2socks@${name}`);
      execSync(`systemctl ${action} openvpn-server@${name}`);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: `Failed: ${e.message}` }); }
});

// List existing OpenVPN clients for a gateway
app.get('/api/gateways/:name/clients', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  if (!gateways[name]) return res.status(404).json({ error: 'Not found' });
  // Find all issued certs matching name_* prefix (from pki/issued/)
  const pkiIssued = '/etc/openvpn/easy-rsa/pki/issued';
  let clients = [];
  try {
    const prefix = name + '_';
    clients = fs.readdirSync(pkiIssued)
      .filter(f => f.startsWith(prefix) && f.endsWith('.crt'))
      .map(f => f.slice(prefix.length, -4));
  } catch(_) {}
  res.json({ clients });
});

// Revoke an OpenVPN client cert
app.delete('/api/gateways/:name/client/:client', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const clientName = req.params.client.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Not found' });
  const certName = `${name}_${clientName}`;
  try {
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa revoke ${certName} 2>&1 || true`, { shell:'/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-crl 2>&1`, { shell:'/bin/bash' });
    // Remove cert files
    try { fs.unlinkSync(`/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`); } catch(_){}
    try { fs.unlinkSync(`/etc/openvpn/easy-rsa/pki/private/${certName}.key`); } catch(_){}
    if (gw.client_count > 0) { gateways[name].client_count--; gwSave(gateways); }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Re-download an existing client .ovpn (by regenerating cert inline — re-issue if needed)
app.get('/api/gateways/:name/client/:client/ovpn', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const clientName = req.params.client.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Not found' });
  const certName = `${name}_${clientName}`;
  const certPath = `/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`;
  const keyPath  = `/etc/openvpn/easy-rsa/pki/private/${certName}.key`;
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) return res.status(404).json({ error: 'Cert not found' });
  try {
    const ca   = fs.readFileSync('/etc/openvpn/easy-rsa/pki/ca.crt', 'utf8').trim();
    const cert = fs.readFileSync(certPath, 'utf8');
    const key  = fs.readFileSync(keyPath, 'utf8').trim();
    const ta   = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();
    const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
    const certClean = certMatch ? certMatch[0].trim() : cert.trim();
    const ovpn = `client\ndev tun\nproto udp\nremote ${SERVER_IP} ${gw.vpn_port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\ncompress lz4-v2\nverb 3\nkey-direction 1\n<ca>\n${ca}\n</ca>\n<cert>\n${certClean}\n</cert>\n<key>\n${key}\n</key>\n<tls-auth>\n${ta}\n</tls-auth>\n`;
    res.json({ ok: true, ovpn });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Create client .ovpn for a specific gateway
app.post('/api/gateways/:name/client', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const clientName = (req.body.client_name || '').replace(/[^a-zA-Z0-9_-]/g,'').slice(0, 32);
  if (!clientName) return res.status(400).json({ error: 'Invalid client name' });
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });

  const certName = `${name}_${clientName}`;
  try {
    // Generate client cert
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-req ${certName} nopass 2>&1`, { shell:'/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa sign-req client ${certName} 2>&1`, { shell:'/bin/bash' });

    const ca   = fs.readFileSync('/etc/openvpn/easy-rsa/pki/ca.crt', 'utf8').trim();
    const cert = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`, 'utf8');
    const key  = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/private/${certName}.key`, 'utf8').trim();
    const ta   = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();
    const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
    const certClean = certMatch ? certMatch[0].trim() : cert.trim();

    const ovpn = `client
dev tun
proto udp
remote ${SERVER_IP} ${gw.vpn_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3
key-direction 1
<ca>
${ca}
</ca>
<cert>
${certClean}
</cert>
<key>
${key}
</key>
<tls-auth>
${ta}
</tls-auth>
`;
    gateways[name].client_count = (gw.client_count || 0) + 1;
    gwSave(gateways);
    res.json({ ok: true, name: clientName, ovpn });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Re-test gateway's proxy and return current exit IP
app.post('/api/gateways/:name/test', requireVpnToken, async (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Not found' });
  try {
    const ip = await gwTestProxy(gw.proxy_url);
    gateways[name].exit_ip = ip;
    gateways[name].last_tested = new Date().toISOString();
    gwSave(gateways);
    res.json({ ok: true, exit_ip: ip });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET L2TP credentials for a specific gateway (all users in that gateway)
app.get('/api/gateways/:name/l2tp', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  if (!gateways[name]) return res.status(404).json({ error: 'Not found' });
  const l2tpData = l2tpLoad();
  const users = Object.values(l2tpData.users).filter(u => u.gateway === name);
  res.json({
    gateway: name,
    server_ip: SERVER_IP,
    psk: l2tpData.psk,
    users: users.map(u => ({ username: u.username, chap_name: `${u.gateway}__${u.username}`, password: u.password, created_at: u.created_at })),
  });
});

// POST reset/regenerate L2TP password for a specific user
app.post('/api/gateways/:name/l2tp/reset', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const l2tpData = l2tpLoad();
  const key = `${name}__${username}`;
  if (!l2tpData.users[key]) {
    // Auto-create if not exists (for gateways created before this feature)
    const gateways = gwLoad();
    if (!gateways[name]) return res.status(404).json({ error: 'Gateway not found' });
    const newPass = require('crypto').randomBytes(6).toString('hex');
    l2tpData.users[key] = { gateway: name, username, password: newPass, created_at: new Date().toISOString() };
    l2tpSave(l2tpData);
    l2tpSyncChap(l2tpData);
    return res.json({ ok: true, password: newPass, created: true });
  }
  const newPass = require('crypto').randomBytes(6).toString('hex');
  l2tpData.users[key].password = newPass;
  l2tpSave(l2tpData);
  l2tpSyncChap(l2tpData);
  res.json({ ok: true, password: newPass });
});

// Update proxy URL for existing gateway (no need to recreate)
app.put('/api/gateways/:name/proxy', requireVpnToken, async (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Not found' });
  const { proxy_url } = req.body;
  if (!proxy_url) return res.status(400).json({ error: 'Missing proxy_url' });
  let detected;
  try { detected = await detectAndTestProxy(proxy_url); }
  catch(e) { return res.status(400).json({ error: 'Proxy test failed: ' + e.message }); }
  const gwPath = path.join(GW_DIR, name);
  // Update tun2socks.env with new proxy URL
  const t2sEnvPath = path.join(gwPath, 'tun2socks.env');
  let t2sEnv = '';
  try { t2sEnv = fs.readFileSync(t2sEnvPath, 'utf8'); } catch(_) { t2sEnv = `TUN_DEV=${gw.t2s_dev}\nTUN_IP=10.${200 + gw.t2s_subnet_index}.0.1\n`; }
  t2sEnv = t2sEnv.replace(/^PROXY_URL=.*/m, `PROXY_URL=${detected.url}`);
  if (!/^PROXY_URL=/m.test(t2sEnv)) t2sEnv += `PROXY_URL=${detected.url}\n`;
  fs.writeFileSync(t2sEnvPath, t2sEnv);
  // Update gateways.json
  gateways[name].proxy_url    = detected.url;
  gateways[name].proxy_scheme = detected.scheme;
  gateways[name].exit_ip      = detected.exitIp;
  gateways[name].last_tested  = new Date().toISOString();
  gwSave(gateways);
  // Restart tun2socks to pick up new proxy
  try {
    execSync(`systemctl restart tun2socks@${name}`);
    // Restore custom routing table route (lost when TUN goes down)
    const tableId = gw.table_id;
    const t2sDev  = gw.t2s_dev;
    if (tableId && t2sDev) {
      setTimeout(() => {
        try { execSync(`ip route replace default dev ${t2sDev} table ${tableId}`); } catch(_){}
      }, 3000);
    }
  } catch(e) { console.warn('[proxy update] tun2socks restart failed:', e.message); }
  res.json({ ok: true, exit_ip: detected.exitIp, proxy_scheme: detected.scheme });
});



// ── OpenVPN API ────────────────────────────────────────────────────────────────
const OV_DIR     = '/etc/openvpn';
const OV_PKI     = '/etc/openvpn/easy-rsa/pki';
const OV_DATA    = path.join(__dirname, 'ovpn-clients.json');

function ovLoadClients() {
  try { return JSON.parse(fs.readFileSync(OV_DATA, 'utf8')); } catch(_) { return {}; }
}
function ovSaveClients(data) { fs.writeFileSync(OV_DATA, JSON.stringify(data, null, 2)); }

function ovCreateClient(name) {
  const easyrsa = '/etc/openvpn/easy-rsa/easyrsa';
  // Gen client key + cert (nopass, batch)
  execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-req ${name} nopass 2>&1`, { shell: '/bin/bash' });
  execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa sign-req client ${name} 2>&1`, { shell: '/bin/bash' });

  const ca      = fs.readFileSync(`${OV_PKI}/ca.crt`, 'utf8').trim();
  const cert    = fs.readFileSync(`${OV_PKI}/issued/${name}.crt`, 'utf8');
  const key     = fs.readFileSync(`${OV_PKI}/private/${name}.key`, 'utf8').trim();
  const ta      = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();

  // Extract cert block only
  const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
  const certClean = certMatch ? certMatch[0].trim() : cert.trim();

  const ovpn = `client
dev tun
proto udp
remote ${SERVER_IP} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3
key-direction 1
<ca>
${ca}
</ca>
<cert>
${certClean}
</cert>
<key>
${key}
</key>
<tls-auth>
${ta}
</tls-auth>
`;

  const clients = ovLoadClients();
  clients[name] = { name, createdAt: new Date().toISOString() };
  ovSaveClients(clients);
  return ovpn;
}

function ovRevokeClient(name) {
  try {
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa revoke ${name} 2>&1`, { shell: '/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-crl 2>&1`, { shell: '/bin/bash' });
    execSync(`cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem`);
  } catch(_){}
  const clients = ovLoadClients();
  delete clients[name];
  ovSaveClients(clients);
}

// OpenVPN: server status
app.get('/api/vpn/ov/status', requireVpnToken, (req, res) => {
  try {
    execSync('systemctl is-active openvpn-server@server');
    res.json({ running: true });
  } catch(_) { res.json({ running: false }); }
});

// OpenVPN: list clients
app.get('/api/vpn/ov/clients', requireVpnToken, (req, res) => {
  const clients = ovLoadClients();
  res.json({ count: Object.keys(clients).length, clients: Object.values(clients) });
});

// OpenVPN: create client
app.post('/api/vpn/ov/client', requireVpnToken, (req, res) => {
  const name = (req.body.name || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
  if (!name) return res.status(400).json({ error: 'Invalid name' });
  const clients = ovLoadClients();
  if (clients[name]) return res.status(409).json({ error: 'Client already exists' });
  try {
    const ovpn = ovCreateClient(name);
    res.json({ name, ovpn });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OpenVPN: download .ovpn
app.get('/api/vpn/ov/client/:name/ovpn', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g, '');
  const clients = ovLoadClients();
  if (!clients[name]) return res.status(404).end();
  try {
    const ca      = fs.readFileSync(`${OV_PKI}/ca.crt`, 'utf8').trim();
    const cert    = fs.readFileSync(`${OV_PKI}/issued/${name}.crt`, 'utf8');
    const key     = fs.readFileSync(`${OV_PKI}/private/${name}.key`, 'utf8').trim();
    const ta      = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();
    const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
    const certClean = certMatch ? certMatch[0].trim() : cert.trim();
    const ovpn = `client\ndev tun\nproto udp\nremote ${SERVER_IP} 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\ncompress lz4-v2\nverb 3\nkey-direction 1\n<ca>\n${ca}\n</ca>\n<cert>\n${certClean}\n</cert>\n<key>\n${key}\n</key>\n<tls-auth>\n${ta}\n</tls-auth>\n`;
    res.setHeader('Content-Type', 'application/x-openvpn-profile');
    res.setHeader('Content-Disposition', `attachment; filename="${name}.ovpn"`);
    res.send(ovpn);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OpenVPN: delete/revoke client
app.delete('/api/vpn/ov/client/:name', requireVpnToken, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g, '');
  const clients = ovLoadClients();
  if (!clients[name]) return res.status(404).json({ error: 'Not found' });
  ovRevokeClient(name);
  res.json({ ok: true });
});


// GET all
app.get('/api/library', (req, res) => {
  const lib = libLoad();
  const items = Object.values(lib).sort((a,b) => (b.saved_at||'').localeCompare(a.saved_at||''));
  res.json({ count: items.length, items });
});

// DELETE one
app.delete('/api/library/:proxy', (req, res) => {
  const lib = libLoad();
  const key = decodeURIComponent(req.params.proxy);
  if (lib[key]) { delete lib[key]; libSave(lib); }
  res.json({ ok: true, count: Object.keys(lib).length });
});

// DELETE all
app.delete('/api/library', (req, res) => {
  libSave({});
  res.json({ ok: true });
});

// GET export (plain text list)
app.get('/api/library/export', (req, res) => {
  const lib = libLoad();
  const lines = Object.keys(lib).join('\n');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="proxy-library.txt"');
  res.send(lines);
});

// ── Routes ───────────────────────────────────────────────────────────────────
app.post('/api/check', (req, res) => {
  const { proxies, concurrency = 5, timeout = 30000 } = req.body;
  const clean = (Array.isArray(proxies) ? proxies : [])
    .map(p => String(p).trim()).filter(Boolean);
  if (!clean.length) return res.status(400).json({ error: 'No proxies provided' });

  // If request carries an API key, validate check_proxy permission + quota
  const apiKeyVal = req.headers['x-api-key'] || req.query.api_key;
  let ownerKeyId = null;
  if (apiKeyVal) {
    const keys = keysLoad();
    const entry = Object.values(keys).find(x => x.key === apiKeyVal);
    if (!entry || !entry.enabled) return res.status(401).json({ error: 'Invalid API key' });
    if (entry.expires_at && new Date(entry.expires_at) < new Date()) return res.status(403).json({ error: 'API key expired' });
    if (!(entry.permissions || []).includes('check_proxy')) return res.status(403).json({ error: 'Permission denied: check_proxy' });
    if (entry.proxy_check_limit && entry.proxy_checks_used >= entry.proxy_check_limit)
      return res.status(429).json({ error: 'Proxy check quota exceeded', limit: entry.proxy_check_limit, used: entry.proxy_checks_used });
    // Track usage
    entry.proxy_checks_used = (entry.proxy_checks_used || 0) + clean.length;
    entry.last_used_at = new Date().toISOString();
    keys[entry.id] = entry;
    setImmediate(() => keysSave(keys));
    ownerKeyId = entry.id;
  }

  const jobId = randomUUID();
  jobs.set(jobId, { total: clean.length, done: 0, results: [] });
  sseClients.set(jobId, new Set());

  res.json({ jobId, total: clean.length });

  const c = Math.max(1, Math.min(50, Number(concurrency) || 5));
  const t = Math.max(5000, Math.min(120000, Number(timeout) || 30000));
  runJob(jobId, clean, c, t, ownerKeyId);
});

app.get('/api/stream/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).end();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  // Replay history for late subscribers
  for (const result of job.results) {
    res.write(`data: ${JSON.stringify({ type: 'result', result, done: job.done, total: job.total })}\n\n`);
  }

  if (job.done >= job.total) {
    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    res.end();
    return;
  }

  sseClients.get(req.params.jobId)?.add(res);
  req.on('close', () => sseClients.get(req.params.jobId)?.delete(res));
});

// Use raw http server so we can attach WebSocket upgrade handler for /ws/captures
const server = http.createServer(app);
captures.attach(app, server, requireVpnToken, requireGatewayAccess, validateGatewayAccess);

// ─────────────────────────────────────────────────────────────
// PUBLIC per-gateway endpoints (NO TOKEN)
// Anyone who knows the gateway name can: see status, toggle MITM,
// download .ovpn (creates a new client cert), download CA cert.
// Mounted AFTER captures.attach so /api/public/g/:name/captures (defined in captures.js) takes precedence.
// ─────────────────────────────────────────────────────────────
app.get('/api/public/g/:name/info', requireGatewayAccess, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  const out = {
    name: gw.name, country: gw.country, exit_ip: gw.exit_ip,
    vpn_port: gw.vpn_port, vpn_subnet: gw.vpn_subnet,
    mitm_port: gw.mitm_port || null, mitm_enabled: !!gw.mitm_enabled,
    server_ip: SERVER_IP, client_count: gw.client_count || 0,
  };
  try { execSync(`systemctl is-active openvpn-server@${name}`); out.vpn_running = true; } catch(_) { out.vpn_running = false; }
  try { execSync(`systemctl is-active tun2socks@${name}`); out.tun_running = true; } catch(_) { out.tun_running = false; }
  try { execSync(`systemctl is-active mitmproxy@${name}`); out.mitm_running = true; } catch(_) { out.mitm_running = false; }
  out.running = out.vpn_running && out.tun_running;
  res.json(out);
});

app.post('/api/public/g/:name/mitm/:action(start|stop)', requireGatewayAccess, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const action = req.params.action;
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  if (!gw.mitm_port || !gw.vpn_subnet) return res.status(400).json({ error: 'Gateway has no MITM config' });
  const markerFile = path.join(GW_DIR, name, 'mitm.enabled');
  const ruleArgs = `-s ${gw.vpn_subnet} -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port ${gw.mitm_port}`;
  try {
    if (action === 'start') {
      try { execSync(`systemctl daemon-reload`); } catch(_){}
      try { execSync(`systemctl reset-failed mitmproxy@${name}`, { stdio:'ignore' }); } catch(_){}
      execSync(`systemctl enable --now mitmproxy@${name}`);
      execSync(`iptables -t nat -C PREROUTING ${ruleArgs} 2>/dev/null || iptables -t nat -I PREROUTING 1 ${ruleArgs}`, { shell:'/bin/bash' });
      fs.writeFileSync(markerFile, '1\n');
      gw.mitm_enabled = true;
    } else {
      try { execSync(`iptables -t nat -D PREROUTING ${ruleArgs} 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
      try { execSync(`systemctl disable --now mitmproxy@${name}`, { stdio:'ignore' }); } catch(_){}
      try { fs.unlinkSync(markerFile); } catch(_){}
      gw.mitm_enabled = false;
    }
    gateways[name] = gw; gwSave(gateways);
    res.json({ ok: true, mitm_enabled: gw.mitm_enabled });
  } catch(e) {
    console.error('[public mitm]', e);
    res.status(500).json({ error: e.message || 'mitm toggle failed' });
  }
});

app.post('/api/public/g/:name/client', requireGatewayAccess, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,'');
  const clientName = (req.body.client_name || '').replace(/[^a-zA-Z0-9_-]/g,'').slice(0, 32);
  if (!clientName) return res.status(400).json({ error: 'Invalid client name' });
  const gateways = gwLoad();
  const gw = gateways[name];
  if (!gw) return res.status(404).json({ error: 'Gateway not found' });
  const certName = `${name}_${clientName}`;
  try {
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-req ${certName} nopass 2>&1`, { shell:'/bin/bash' });
    execSync(`cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa sign-req client ${certName} 2>&1`, { shell:'/bin/bash' });
    const ca   = fs.readFileSync('/etc/openvpn/easy-rsa/pki/ca.crt', 'utf8').trim();
    const cert = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/issued/${certName}.crt`, 'utf8');
    const key  = fs.readFileSync(`/etc/openvpn/easy-rsa/pki/private/${certName}.key`, 'utf8').trim();
    const ta   = fs.readFileSync('/etc/openvpn/server/ta.key', 'utf8').trim();
    const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/);
    const certClean = certMatch ? certMatch[0].trim() : cert.trim();
    const ovpn = `client
dev tun
proto udp
remote ${SERVER_IP} ${gw.vpn_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3
key-direction 1
<ca>
${ca}
</ca>
<cert>
${certClean}
</cert>
<key>
${key}
</key>
<tls-auth>
${ta}
</tls-auth>
`;
    gateways[name].client_count = (gw.client_count || 0) + 1;
    gwSave(gateways);
    res.setHeader('Content-Type', 'application/x-openvpn-profile');
    res.setHeader('Content-Disposition', `attachment; filename="${name}-${clientName}.ovpn"`);
    res.send(ovpn);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── L2TP/IPSec Management ─────────────────────────────────────────────────────
const L2TP_DATA       = path.join(__dirname, 'l2tp-users.json');
const CHAP_SECRETS    = '/etc/ppp/chap-secrets';
const IPSEC_SECRETS   = '/etc/ipsec.secrets';
const IPSEC_CONF      = '/etc/ipsec.conf';

function l2tpLoad() {
  try { return JSON.parse(fs.readFileSync(L2TP_DATA, 'utf8')); }
  catch(_) { return { psk: 'vpnadmin2026', users: {} }; }
}
function l2tpSave(data) { fs.writeFileSync(L2TP_DATA, JSON.stringify(data, null, 2)); }

// Sync in-memory users → /etc/ppp/chap-secrets
function l2tpSyncChap(data) {
  const lines = [
    '# L2TP/IPSec users — managed by proxy-checker',
    '# USERNAME        SERVER    SECRET    IPADDRESSES',
  ];
  for (const u of Object.values(data.users)) {
    const chapName = `${u.gateway}__${u.username}`;
    lines.push(`"${chapName}"  *  "${u.password}"  *`);
  }
  fs.writeFileSync(CHAP_SECRETS, lines.join('\n') + '\n');
  fs.chmodSync(CHAP_SECRETS, 0o600);
}

// Sync PSK → /etc/ipsec.secrets and reload strongSwan
function l2tpSyncPsk(psk) {
  fs.writeFileSync(IPSEC_SECRETS,
    `# Managed by proxy-checker — do not edit manually.\n%any : PSK "${psk}"\n`);
  fs.chmodSync(IPSEC_SECRETS, 0o600);
  try { execSync('ipsec rereadsecrets 2>/dev/null || true', { shell: '/bin/bash' }); } catch(_){}
}

// GET L2TP global config + status
app.get('/api/l2tp', requireVpnToken, (req, res) => {
  const data = l2tpLoad();
  let ipsecRunning = false, xl2tpdRunning = false;
  try { execSync('systemctl is-active strongswan-starter', { stdio:'ignore' }); ipsecRunning = true; } catch(_){}
  try { execSync('systemctl is-active xl2tpd', { stdio:'ignore' }); xl2tpdRunning = true; } catch(_){}
  // Count connected PPP sessions
  let connected = 0;
  try {
    const out = execSync("ip link show | grep -c '^[0-9]*: ppp'", { encoding:'utf8' });
    connected = parseInt(out.trim(), 10) || 0;
  } catch(_){}
  res.json({
    psk: data.psk,
    user_count: Object.keys(data.users).length,
    connected_sessions: connected,
    ipsec_running: ipsecRunning,
    xl2tpd_running: xl2tpdRunning,
    server_ip: SERVER_IP,
    l2tp_subnet: '10.253.0.0/24',
  });
});

// PUT update PSK
app.put('/api/l2tp/psk', requireVpnToken, (req, res) => {
  const { psk } = req.body;
  if (!psk || psk.length < 6) return res.status(400).json({ error: 'PSK must be at least 6 characters' });
  const data = l2tpLoad();
  data.psk = psk;
  l2tpSave(data);
  l2tpSyncPsk(psk);
  res.json({ ok: true });
});

// GET list L2TP users
app.get('/api/l2tp/users', requireVpnToken, (req, res) => {
  const data = l2tpLoad();
  const users = Object.values(data.users).map(u => ({
    gateway: u.gateway, username: u.username,
    chap_name: `${u.gateway}__${u.username}`,
    created_at: u.created_at,
  }));
  res.json({ count: users.length, users });
});

// POST add L2TP user
app.post('/api/l2tp/user', requireVpnToken, (req, res) => {
  const { gateway, username, password } = req.body;
  if (!gateway || !username || !password)
    return res.status(400).json({ error: 'Missing gateway, username or password' });
  if (!/^[a-zA-Z0-9_-]{1,24}$/.test(gateway))
    return res.status(400).json({ error: 'Invalid gateway name' });
  if (!/^[a-zA-Z0-9@._-]{1,64}$/.test(username))
    return res.status(400).json({ error: 'Invalid username (allowed: a-z A-Z 0-9 @ . _ -)' });
  const gateways = gwLoad();
  if (!gateways[gateway]) return res.status(404).json({ error: `Gateway '${gateway}' not found` });
  const data = l2tpLoad();
  const key = `${gateway}__${username}`;
  if (data.users[key]) return res.status(409).json({ error: 'User already exists' });
  data.users[key] = { gateway, username, password, created_at: new Date().toISOString() };
  l2tpSave(data);
  l2tpSyncChap(data);
  res.status(201).json({ ok: true, chap_name: key });
});

// DELETE L2TP user
app.delete('/api/l2tp/user/:key', requireVpnToken, (req, res) => {
  const key = decodeURIComponent(req.params.key);
  const data = l2tpLoad();
  if (!data.users[key]) return res.status(404).json({ error: 'User not found' });
  delete data.users[key];
  l2tpSave(data);
  l2tpSyncChap(data);
  res.json({ ok: true });
});

// POST start/stop/restart L2TP services
app.post('/api/l2tp/:action(start|stop|restart)', requireVpnToken, (req, res) => {
  const { action } = req.params;
  try {
    if (action === 'stop') {
      execSync('systemctl stop xl2tpd strongswan-starter');
    } else {
      const data = l2tpLoad();
      l2tpSyncPsk(data.psk);
      l2tpSyncChap(data);
      execSync(`systemctl ${action} strongswan-starter xl2tpd`);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Init: sync L2TP files on startup ──────────────────────────────────────────
try {
  const l2tpInit = l2tpLoad();
  l2tpSyncChap(l2tpInit);
  l2tpSyncPsk(l2tpInit.psk);
  l2tpSave(l2tpInit);  // persist defaults if file was missing
} catch(e) { console.warn('[l2tp init]', e.message); }

server.listen(PORT, '0.0.0.0', () => console.log(`[INFO] Proxy Checker → http://0.0.0.0:${PORT}`));

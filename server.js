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
app.use(express.static(path.join(__dirname, 'public')));

const jobs       = new Map();   // jobId → { total, done, results }
const sseClients = new Map();   // jobId → Set<res>

// ── Proxy URL parsing ────────────────────────────────────────────────────────
function parseProxyUrl(raw) {
  raw = raw.trim();
  if (!raw) return null;
  // Already has scheme
  if (/^(socks[45]?|http|https):\/\//i.test(raw)) return raw;
  const parts = raw.split(':');
  // host:port:user:pass
  if (parts.length === 4) {
    const [host, port, user, pass] = parts;
    return `socks5://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}`;
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
function parseProxyFlex(raw) {
  if (!raw) return null;
  raw = String(raw).trim();
  // With scheme
  const m = raw.match(/^(?:socks[45]?h?|http|https):\/\/(.+)$/i);
  const body = m ? m[1] : raw;
  // user:pass@host:port
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
  // host:port:user:pass (split on first 3 colons only — password may contain ':')
  const parts = body.split(':');
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

function broadcast(jobId, payload) {
  const clients = sseClients.get(jobId);
  if (!clients || clients.size === 0) return;
  const msg = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of clients) { try { res.write(msg); } catch (_) {} }
}

// ── Job runner (sliding-window concurrency) ──────────────────────────────────
async function runJob(jobId, proxies, concurrency, timeout) {
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
        libAddResults(job.results);
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

// ── VPN API routes ─────────────────────────────────────────────────────────────
function requireVpnToken(req, res, next) {
  const token = req.headers['x-vpn-token'] || req.query.token;
  if (token !== VPN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

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
  CN: { u1: 'https://dns.alidns.com/dns-query',  u2: 'https://doh.pub/dns-query',         fallback: '223.5.5.5' },
  HK: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  TW: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  JP: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  KR: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  SG: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  RU: { u1: 'https://dns.google/dns-query',      u2: 'https://dns.quad9.net/dns-query',   fallback: '8.8.8.8'   },
  IR: { u1: 'https://dns.google/dns-query',      u2: 'https://dns.quad9.net/dns-query',   fallback: '8.8.8.8'   },
  TR: { u1: 'https://dns.google/dns-query',      u2: 'https://1.1.1.1/dns-query',         fallback: '8.8.8.8'   },
  VN: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  TH: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  ID: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  MY: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  IN: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  US: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  GB: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  DE: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  FR: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  NL: { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },
  _:  { u1: 'https://1.1.1.1/dns-query',         u2: 'https://dns.google/dns-query',      fallback: '1.1.1.1'   },  // default
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
    const vpnGwIp = `10.${100 + vpnIdx}.0.1`;
    fs.writeFileSync(path.join(gwPath, 'dnsmasq-gw.env'),
      `VPN_GW_IP=${vpnGwIp}\nDNS_PORT=${dnsPort}\nDNS_FALLBACK=${dnsCfg.fallback}\n`);

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
keepalive 10 30
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
      // Persist marker so up.sh can restore the rule after an openvpn restart
      fs.writeFileSync(markerFile, '1\n');
      gw.mitm_enabled = true;
      gateways[name] = gw; gwSave(gateways);
      return res.json({ ok: true, name, mitm_active: true, mitm_port: gw.mitm_port });
    }
    if (action === 'stop') {
      // Remove redirect first so clients fail-open back to direct (no MITM hijack)
      try { execSync(`iptables -t nat -D PREROUTING ${redirectRuleArgs} 2>/dev/null || true`, { shell:'/bin/bash' }); } catch(_){}
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

  const jobId = randomUUID();
  jobs.set(jobId, { total: clean.length, done: 0, results: [] });
  sseClients.set(jobId, new Set());

  res.json({ jobId, total: clean.length });

  const c = Math.max(1, Math.min(50, Number(concurrency) || 5));
  const t = Math.max(5000, Math.min(120000, Number(timeout) || 30000));
  runJob(jobId, clean, c, t);
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

const PORT = process.env.PORT || 3000;
// Use raw http server so we can attach WebSocket upgrade handler for /ws/captures
const server = http.createServer(app);
captures.attach(app, server, requireVpnToken);

// ─────────────────────────────────────────────────────────────
// PUBLIC per-gateway endpoints (NO TOKEN)
// Anyone who knows the gateway name can: see status, toggle MITM,
// download .ovpn (creates a new client cert), download CA cert.
// Mounted AFTER captures.attach so /api/public/g/:name/captures (defined in captures.js) takes precedence.
// ─────────────────────────────────────────────────────────────
app.get('/api/public/g/:name/info', (req, res) => {
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

app.post('/api/public/g/:name/mitm/:action(start|stop)', (req, res) => {
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

app.post('/api/public/g/:name/client', (req, res) => {
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

server.listen(PORT, '0.0.0.0', () => console.log(`[INFO] Proxy Checker → http://0.0.0.0:${PORT}`));

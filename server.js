'use strict';

const express = require('express');
const axios   = require('axios');
const cheerio = require('cheerio');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { randomUUID } = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
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

// ── SSE broadcast ────────────────────────────────────────────────────────────
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
        setTimeout(() => { jobs.delete(jobId); sseClients.delete(jobId); }, 600_000);
      }
    }
  };

  const workers = Math.min(concurrency, proxies.length);
  await Promise.allSettled(Array.from({ length: workers }, worker));
}

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
app.listen(PORT, '0.0.0.0', () => console.log(`[INFO] Proxy Checker → http://0.0.0.0:${PORT}`));

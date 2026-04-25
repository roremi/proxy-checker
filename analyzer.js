// analyzer.js — phát hiện hệ thống đang theo dõi/thu thập gì từ flows đã capture.
//
// Hai chế độ:
//   1) Rule-based (mặc định): scan DB bằng pattern, KHÔNG cần internet/API key.
//      Trả về trackers, fingerprint signals, risk endpoints, mismatches, top hosts.
//   2) AI (optional): nếu env LLM_API_KEY được set, gọi LLM để diễn giải report
//      thành cảnh báo bằng tiếng Việt. Hỗ trợ OpenAI, Anthropic, Groq, OpenRouter
//      thông qua biến LLM_PROVIDER (mặc định: openai-compat).
//
// Endpoint:
//   GET  /api/public/g/:name/analyze           -> rule-based JSON report
//   POST /api/public/g/:name/analyze/ai        -> { summary, risk_score, advice } (nếu có key)

const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'captures.db'), { readonly: false });

// ─── Catalog tracker / SDK / fingerprint hosts ───
// (host substring → { category, vendor, what })
const TRACKER_HOSTS = [
  // Fraud / device intelligence
  { m: 'threatmetrix',           cat: 'fraud',       vendor: 'LexisNexis ThreatMetrix', what: 'Device fingerprint (canvas, fonts, IP/ASN, proxy/VPN detection)' },
  { m: 'h.online-metrix.net',    cat: 'fraud',       vendor: 'ThreatMetrix',            what: 'TMX profiling endpoint' },
  { m: 'fpjs.io',                cat: 'fraud',       vendor: 'FingerprintJS',           what: 'Browser/device fingerprinting' },
  { m: 'fingerprint.com',        cat: 'fraud',       vendor: 'FingerprintJS',           what: 'Visitor ID + bot/incognito detection' },
  { m: 'sift.com',               cat: 'fraud',       vendor: 'Sift',                    what: 'Account/payment fraud scoring' },
  { m: 'siftscience.com',        cat: 'fraud',       vendor: 'Sift Science',            what: 'Risk scoring' },
  { m: 'forter.com',             cat: 'fraud',       vendor: 'Forter',                  what: 'Fraud prevention' },
  { m: 'iovation.com',           cat: 'fraud',       vendor: 'Iovation/TransUnion',     what: 'Device reputation' },
  { m: 'arkoselabs',             cat: 'fraud',       vendor: 'Arkose Labs',             what: 'Bot/captcha challenge' },
  { m: 'datadome',               cat: 'fraud',       vendor: 'DataDome',                what: 'Bot detection' },
  { m: 'perimeterx',             cat: 'fraud',       vendor: 'PerimeterX/HUMAN',        what: 'Bot mitigation' },
  { m: 'akamai.net',             cat: 'fraud',       vendor: 'Akamai',                  what: 'Bot Manager / Edge fingerprint (sensor_data)' },
  { m: 'incapsula',              cat: 'fraud',       vendor: 'Imperva',                 what: 'Bot/WAF challenge' },
  { m: 'recaptcha',              cat: 'fraud',       vendor: 'Google reCAPTCHA',        what: 'Bot/risk scoring' },
  { m: 'hcaptcha',               cat: 'fraud',       vendor: 'hCaptcha',                what: 'Bot challenge' },
  { m: 'cloudflarechallenge',    cat: 'fraud',       vendor: 'Cloudflare Turnstile',    what: 'Bot detection' },
  // Mobile attribution
  { m: 'appsflyer',              cat: 'attribution', vendor: 'AppsFlyer',               what: 'Mobile install attribution + device ID linking' },
  { m: 'adjust.com',             cat: 'attribution', vendor: 'Adjust',                  what: 'Install attribution' },
  { m: 'app.adjust.com',         cat: 'attribution', vendor: 'Adjust',                  what: 'Attribution + fraud signals' },
  { m: 'branch.io',              cat: 'attribution', vendor: 'Branch',                  what: 'Deep link attribution' },
  { m: 'singular.net',           cat: 'attribution', vendor: 'Singular',                what: 'Attribution' },
  { m: 'kochava',                cat: 'attribution', vendor: 'Kochava',                 what: 'Attribution' },
  { m: 'tenjin.com',             cat: 'attribution', vendor: 'Tenjin',                  what: 'Attribution' },
  // Analytics
  { m: 'google-analytics.com',   cat: 'analytics',   vendor: 'Google Analytics',        what: 'Page/event tracking' },
  { m: 'analytics.google.com',   cat: 'analytics',   vendor: 'Google Analytics',        what: 'GA4 events' },
  { m: 'googletagmanager',       cat: 'analytics',   vendor: 'Google Tag Manager',      what: 'Tag loader' },
  { m: 'doubleclick.net',        cat: 'ads',         vendor: 'Google Ads/DoubleClick',  what: 'Ad targeting + remarketing' },
  { m: 'facebook.com/tr',        cat: 'ads',         vendor: 'Meta Pixel',              what: 'Ad attribution' },
  { m: 'connect.facebook.net',   cat: 'ads',         vendor: 'Meta SDK',                what: 'Pixel/SDK loader' },
  { m: 'segment.com',            cat: 'analytics',   vendor: 'Segment',                 what: 'Event pipeline (CDP)' },
  { m: 'segment.io',             cat: 'analytics',   vendor: 'Segment',                 what: 'Event ingest' },
  { m: 'mixpanel',               cat: 'analytics',   vendor: 'Mixpanel',                what: 'Behavioural analytics' },
  { m: 'amplitude',              cat: 'analytics',   vendor: 'Amplitude',               what: 'Product analytics' },
  { m: 'heap.io',                cat: 'analytics',   vendor: 'Heap',                    what: 'Auto-capture analytics' },
  { m: 'hotjar.com',             cat: 'analytics',   vendor: 'Hotjar',                  what: 'Session recording' },
  { m: 'fullstory.com',          cat: 'analytics',   vendor: 'FullStory',               what: 'Session recording (DOM replay)' },
  { m: 'logrocket',              cat: 'analytics',   vendor: 'LogRocket',               what: 'Session replay' },
  { m: 'clarity.ms',             cat: 'analytics',   vendor: 'Microsoft Clarity',       what: 'Session recording + heatmap' },
  // Crash / error
  { m: 'sentry.io',              cat: 'crash',       vendor: 'Sentry',                  what: 'Error reporting (gửi stack trace + device info)' },
  { m: 'bugsnag.com',            cat: 'crash',       vendor: 'Bugsnag',                 what: 'Crash reporting' },
  { m: 'crashlytics',            cat: 'crash',       vendor: 'Firebase Crashlytics',    what: 'Crash reporting' },
  // Push / firebase
  { m: 'firebaseinstallations',  cat: 'identity',    vendor: 'Firebase',                what: 'Install instance ID (FID)' },
  { m: 'firebase-settings',      cat: 'identity',    vendor: 'Firebase',                what: 'Remote config + instance' },
  { m: 'fcm.googleapis.com',     cat: 'push',        vendor: 'FCM',                     what: 'Push token registration' },
  { m: 'app-measurement.com',    cat: 'analytics',   vendor: 'Firebase Analytics',      what: 'GA4 mobile events' },
  // CDN / edge bot fingerprint
  { m: 'cloudfront.net',         cat: 'cdn',         vendor: 'AWS CloudFront',          what: 'CDN — có thể có bot signals trong header' },
  { m: 'fastly.net',             cat: 'cdn',         vendor: 'Fastly',                  what: 'CDN' },
  // eBay-specific
  { m: 'mobiletelemetry.ebay',   cat: 'telemetry',   vendor: 'eBay Telemetry',          what: 'Continuous device + behaviour reporting' },
  { m: 'identity-api.ebay',      cat: 'auth',        vendor: 'eBay Identity',           what: 'Login + step-up auth + risk' },
  { m: 'mobifts.ebay',           cat: 'feature',     vendor: 'eBay Feature Toggle',     what: 'Feature flag service (gửi device JWT)' },
];

// Header patterns that indicate fingerprint/tracking
const FP_HEADER_RX = [
  { rx: /^x-.*device.*/i,           why: 'Device fingerprint header' },
  { rx: /^x-.*fingerprint.*/i,      why: 'Explicit fingerprint header' },
  { rx: /^x-fp$/i,                  why: 'Fingerprint token' },
  { rx: /^x-tmx.*/i,                why: 'ThreatMetrix session ID' },
  { rx: /^x-distil.*/i,             why: 'Distil/Imperva bot token' },
  { rx: /^x-px.*/i,                 why: 'PerimeterX/HUMAN token' },
  { rx: /^x-datadome.*/i,           why: 'DataDome bot token' },
  { rx: /^x-akamai.*/i,             why: 'Akamai sensor/bot manager' },
  { rx: /^_abck$/i,                 why: 'Akamai Bot Manager cookie/header' },
  { rx: /^x-.*advertising.*/i,      why: 'IDFA/GAID advertising ID' },
  { rx: /^x-.*idfa.*/i,             why: 'iOS advertising ID' },
  { rx: /^x-.*idfv.*/i,             why: 'iOS vendor ID' },
  { rx: /^x-.*-(rlogid|tracking|correlation|enduser).*/i, why: 'Correlation/tracking ID' },
  { rx: /^x-(client|app)-(id|version|build).*/i, why: 'App build identification' },
  { rx: /^user-agent$/i,            why: 'User-Agent (OS/version/device)' },
];

// Body field names that look like PII / fingerprint data
const FP_BODY_FIELDS = [
  'deviceguid','deviceid','device_id','dna','idfa','idfv','advertisingid','gaid','aaid',
  'androidid','android_id','imei','meid','serialnumber','wifimac','bssid','ssid',
  'sessionguid','session_id','sessionid','installid','install_id','vendorid','appsflyer_id',
  'appsflyerid','firebase_instance_id','fcm_token','pushtoken','push_token',
  'manufacturer','model','osname','osversion','os_version','platform','locale',
  'language','timezone','timezonename','screenwidth','screenheight','carrier',
  'networkoperator','operatorname','batterylevel','isjailbroken','rooted','emulator',
  'physicalmemory','processorcount','sdkversion','appversion','appbuildidentifier',
  'latitude','longitude','geo','geolocation','ipaddress','clientip','userip',
  'fingerprint','hwfingerprint','canvashash','webglhash','audiohash',
];

// Path patterns indicating risk / fraud / auth challenge
const RISK_PATH_RX = [
  { rx: /\/risk/i,         why: 'Risk scoring endpoint' },
  { rx: /\/fraud/i,        why: 'Fraud check' },
  { rx: /\/threatmetrix/i, why: 'ThreatMetrix profiling' },
  { rx: /\/fingerprint/i,  why: 'Fingerprint collection' },
  { rx: /\/captcha/i,      why: 'Captcha challenge' },
  { rx: /\/challenge/i,    why: 'Anti-bot challenge' },
  { rx: /\/step.?up/i,     why: 'Step-up authentication (2FA forced)' },
  { rx: /\/2fa|\/mfa/i,    why: 'Multi-factor authentication' },
  { rx: /\/verify/i,       why: 'Verification endpoint' },
  { rx: /\/sensor_data/i,  why: 'Akamai Bot Manager sensor' },
  { rx: /\/_px\//i,        why: 'PerimeterX collector' },
  { rx: /\/dd-rum|\/datadome/i, why: 'DataDome' },
  { rx: /\/telemetry|\/aplsio|\/otel/i, why: 'Telemetry/observability ingest' },
  { rx: /\/batchtrack|\/track\b|\/collect\b|\/event\b|\/events\b/i, why: 'Generic event tracker' },
];

function safeJSON(s) { try { return JSON.parse(s || '{}'); } catch(_) { return {}; } }

function decodeBody(b64, max = 8000) {
  if (!b64) return '';
  try {
    const buf = Buffer.from(b64, 'base64');
    return buf.slice(0, max).toString('utf8');
  } catch(_) { return ''; }
}

function jwtPeek(tok) {
  try {
    const parts = String(tok).split('.');
    if (parts.length < 2) return null;
    const pad = parts[1] + '='.repeat((4 - parts[1].length % 4) % 4);
    const json = Buffer.from(pad.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch(_) { return null; }
}

function categorizeHost(host) {
  const h = (host || '').toLowerCase();
  for (const t of TRACKER_HOSTS) if (h.includes(t.m)) return t;
  return null;
}

// ─── Main analyzer ───
function analyzeGateway(name, opts = {}) {
  const since = opts.since || (Date.now() - 24 * 3600_000);
  const limit = Math.min(parseInt(opts.limit, 10) || 5000, 20000);

  const flows = db.prepare(`
    SELECT id, ts, method, host, path, url, status, req_headers, res_headers,
           req_body_b64, res_body_b64, req_size, res_size
      FROM flows
     WHERE gateway = ? AND ts >= ?
     ORDER BY ts DESC LIMIT ?`).all(name, since, limit);

  const report = {
    gateway: name,
    window: { since, until: Date.now(), flows_analyzed: flows.length },
    summary: { total_flows: flows.length, unique_hosts: 0, errors: 0 },
    trackers: {},          // key: vendor → { vendor, category, what, hits, sample_path, hosts:Set }
    fp_headers: {},        // key: header_name → { count, why, sample_value, sample_host }
    fp_body_fields: {},    // key: field → { count, sample_host, sample_value }
    risk_endpoints: [],    // [{host, path, why, status}]
    jwt_tokens: [],        // decoded JWT payloads (capped)
    cookies_set: {},       // name → {host, sample}
    auth_chain: [],        // sequence of auth/login calls
    geo_signals: { timezones:{}, locales:{}, countries:{}, marketplaces:{} },
    geo_mismatches: [],    // human-readable warnings
    top_hosts: {},         // host → count
    auth_bearer_seen: 0,
    pii_in_url: [],
  };

  for (const f of flows) {
    const host = f.host || '';
    report.top_hosts[host] = (report.top_hosts[host] || 0) + 1;
    if ((f.status || 0) >= 400) report.summary.errors++;

    // 1) tracker host catalog
    const cat = categorizeHost(host);
    if (cat) {
      const k = cat.vendor;
      const t = report.trackers[k] || (report.trackers[k] = {
        vendor: cat.vendor, category: cat.cat, what: cat.what, hits: 0,
        hosts: [], sample_paths: [],
      });
      t.hits++;
      if (!t.hosts.includes(host)) t.hosts.push(host);
      if (t.sample_paths.length < 3) t.sample_paths.push(f.path?.slice(0, 120));
    }

    // 2) headers
    const reqH = safeJSON(f.req_headers);
    for (const [hk, hv] of Object.entries(reqH)) {
      const lk = hk.toLowerCase();
      // fingerprint header patterns
      for (const p of FP_HEADER_RX) {
        if (p.rx.test(lk)) {
          const e = report.fp_headers[lk] || (report.fp_headers[lk] = {
            header: lk, count: 0, why: p.why,
            sample_value: String(hv).slice(0, 200), sample_host: host,
          });
          e.count++;
          break;
        }
      }
      // JWT in any header containing 'signature' or 'authorization' or 'jwt'
      if (/signature|jwt|bearer|authorization/i.test(lk) && typeof hv === 'string' && hv.includes('.')) {
        const tok = hv.replace(/^Bearer\s+/i, '');
        const peek = jwtPeek(tok);
        if (peek && report.jwt_tokens.length < 8) {
          report.jwt_tokens.push({ host, header: lk, payload: peek });
        }
        if (lk === 'authorization') report.auth_bearer_seen++;
      }
      // geo signals
      if (lk.includes('cultural-pref') || lk.includes('marketplace') || lk === 'accept-language') {
        const v = String(hv);
        const tz = v.match(/Timezone=([\w/+-]+)/i);
        if (tz) report.geo_signals.timezones[tz[1]] = (report.geo_signals.timezones[tz[1]] || 0) + 1;
        const cur = v.match(/Currency=(\w+)/i);
        if (cur) report.geo_signals.marketplaces['Currency:' + cur[1]] = (report.geo_signals.marketplaces['Currency:' + cur[1]] || 0) + 1;
        if (lk === 'accept-language') {
          const lang = v.split(',')[0].trim();
          if (lang) report.geo_signals.locales[lang] = (report.geo_signals.locales[lang] || 0) + 1;
        }
        if (lk.includes('marketplace')) {
          report.geo_signals.marketplaces[v] = (report.geo_signals.marketplaces[v] || 0) + 1;
        }
      }
    }

    // 3) PII in URL query
    if (f.url && /[?&](email|phone|tel|ssn|card|cvv|pin|password|token)=/i.test(f.url)) {
      report.pii_in_url.push({ host, path: f.path?.slice(0, 200) });
    }

    // 4) Risk endpoint paths
    for (const r of RISK_PATH_RX) {
      if (r.rx.test(f.path || '')) {
        if (report.risk_endpoints.length < 50) {
          report.risk_endpoints.push({ host, path: (f.path || '').slice(0, 180), why: r.why, status: f.status });
        }
        break;
      }
    }

    // 5) Auth chain (login/auth/verify/step_up)
    if (/identity|authhub|signin|login|auth|verify_creds|step_up/i.test(f.path || '') ||
        /identity-api/i.test(host)) {
      if (report.auth_chain.length < 30) {
        report.auth_chain.push({
          ts: f.ts, host, method: f.method,
          path: (f.path || '').slice(0, 180), status: f.status,
        });
      }
    }

    // 6) Set-Cookie names
    const resH = safeJSON(f.res_headers);
    for (const [hk, hv] of Object.entries(resH)) {
      if (hk.toLowerCase() === 'set-cookie') {
        const list = Array.isArray(hv) ? hv : String(hv).split(/,(?=[^,]+=)/);
        for (const c of list) {
          const nm = c.split('=', 1)[0].trim();
          if (nm && !report.cookies_set[nm]) {
            report.cookies_set[nm] = { host, sample: c.trim().slice(0, 120) };
          }
        }
      }
    }

    // 7) Body field scan (only if body is small JSON)
    const reqBody = decodeBody(f.req_body_b64, 4000);
    if (reqBody.startsWith('{') || reqBody.startsWith('[')) {
      const lc = reqBody.toLowerCase();
      for (const fld of FP_BODY_FIELDS) {
        if (lc.includes(`"${fld}"`)) {
          const e = report.fp_body_fields[fld] || (report.fp_body_fields[fld] = { field: fld, count: 0, sample_host: host });
          e.count++;
          if (!e.sample_value) {
            const m = reqBody.match(new RegExp(`"${fld}"\\s*:\\s*("[^"]{0,80}"|[^,}\\]]{0,40})`, 'i'));
            if (m) e.sample_value = m[1].slice(0, 100);
          }
        }
      }
      // timezone from telemetry
      const tzm = reqBody.match(/"timeZone"\s*:\s*"([^"]+)"/);
      if (tzm) report.geo_signals.timezones[tzm[1]] = (report.geo_signals.timezones[tzm[1]] || 0) + 1;
      const lcm = reqBody.match(/"localeIdentifier"\s*:\s*"([^"]+)"/);
      if (lcm) report.geo_signals.locales[lcm[1]] = (report.geo_signals.locales[lcm[1]] || 0) + 1;
      const cm = reqBody.match(/"countryCode"\s*:\s*"([^"]+)"/i);
      if (cm) report.geo_signals.countries[cm[1].toUpperCase()] = (report.geo_signals.countries[cm[1].toUpperCase()] || 0) + 1;
    }
  }

  report.summary.unique_hosts = Object.keys(report.top_hosts).length;

  // Convert maps to arrays sorted by hits
  report.trackers = Object.values(report.trackers).sort((a, b) => b.hits - a.hits);
  report.fp_headers = Object.values(report.fp_headers).sort((a, b) => b.count - a.count);
  report.fp_body_fields = Object.values(report.fp_body_fields).sort((a, b) => b.count - a.count);
  report.cookies_set = Object.entries(report.cookies_set).map(([name, v]) => ({ name, ...v }));
  report.top_hosts = Object.entries(report.top_hosts)
    .sort((a, b) => b[1] - a[1]).slice(0, 30)
    .map(([host, count]) => ({ host, count }));
  report.auth_chain.sort((a, b) => a.ts - b.ts);

  // ─── Geo mismatch detection ───
  const tzKeys = Object.keys(report.geo_signals.timezones);
  const localeKeys = Object.keys(report.geo_signals.locales);
  const countryKeys = Object.keys(report.geo_signals.countries);
  const mpKeys = Object.keys(report.geo_signals.marketplaces);
  const TZ_TO_REGION = {
    'Asia/Ho_Chi_Minh': 'VN', 'Asia/Bangkok': 'TH/VN', 'Asia/Jakarta': 'ID',
    'Asia/Manila': 'PH', 'Asia/Tokyo': 'JP', 'Asia/Seoul': 'KR',
    'America/Los_Angeles': 'US', 'America/New_York': 'US', 'America/Chicago': 'US',
    'Europe/London': 'GB', 'Europe/Berlin': 'DE', 'Europe/Paris': 'FR',
  };
  for (const tz of tzKeys) {
    const region = TZ_TO_REGION[tz];
    if (!region) continue;
    for (const mp of mpKeys) {
      if (/EBAY-US|US$|Currency:USD/i.test(mp) && !/US/.test(region)) {
        report.geo_mismatches.push(`Timezone ${tz} (${region}) khác marketplace ${mp} → red flag fraud engine`);
      }
      if (/EBAY-(GB|DE|FR|JP|AU)/i.test(mp) && !mp.includes(region)) {
        report.geo_mismatches.push(`Timezone ${tz} không khớp marketplace ${mp}`);
      }
    }
    for (const c of countryKeys) {
      if (c === 'US' && !/US/.test(region)) {
        report.geo_mismatches.push(`Telemetry countryCode=US nhưng device timezone=${tz} (${region})`);
      }
    }
  }
  for (const loc of localeKeys) {
    if (/_VN|^vi/i.test(loc) && (mpKeys.some(m => /US|Currency:USD/i.test(m)) || countryKeys.includes('US'))) {
      report.geo_mismatches.push(`Locale ${loc} (Việt Nam) trên account US → mismatch`);
    }
  }
  // Dedupe
  report.geo_mismatches = [...new Set(report.geo_mismatches)];

  // ─── Risk score (0-100) ───
  let score = 0;
  const reasons = [];
  if (report.trackers.find(t => /threatmetrix|fingerprintjs|sift|forter|iovation|arkose|datadome|perimeterx/i.test(t.vendor))) {
    score += 25; reasons.push('Có engine fraud detection chuyên nghiệp đang fingerprint');
  }
  if (report.trackers.find(t => t.category === 'attribution')) {
    score += 10; reasons.push('SDK attribution đang gắn install với device ID');
  }
  if (report.fp_headers.length >= 3) {
    score += 15; reasons.push(`${report.fp_headers.length} loại header fingerprint khác nhau đang gửi đi`);
  }
  if (report.fp_body_fields.find(f => /idfa|idfv|advertisingid|deviceguid|deviceid/i.test(f.field))) {
    score += 15; reasons.push('Device/Advertising ID gửi trong body request');
  }
  if (report.risk_endpoints.find(r => /step.?up|2fa|mfa|verify_creds/i.test(r.path))) {
    score += 15; reasons.push('Server đã trigger step-up auth/2FA trong session này');
  }
  if (report.geo_mismatches.length > 0) {
    score += Math.min(20, report.geo_mismatches.length * 7);
    reasons.push(`${report.geo_mismatches.length} mâu thuẫn geo/locale (IP vs timezone/locale)`);
  }
  if (report.pii_in_url.length) {
    score += 5; reasons.push('PII (email/phone/token) xuất hiện trong URL');
  }
  report.risk_score = Math.min(100, score);
  report.risk_reasons = reasons;

  // ─── Quick Vietnamese advice ───
  const advice = [];
  if (report.geo_mismatches.length) advice.push('Đồng bộ Timezone + Locale + Region của thiết bị với quốc gia của account/proxy IP.');
  if (report.trackers.find(t => t.category === 'attribution')) advice.push('Cài lại app khi thiết bị đã ở đúng IP/timezone target để AppsFlyer/Adjust ghi nhận install country đúng.');
  if (report.fp_body_fields.find(f => /idfa|advertisingid|gaid/i.test(f.field))) advice.push('IDFA/GAID = 0 sẽ bị xem là "thiếu trust". Bật Allow Tracking nếu muốn trông giống user thật.');
  if (report.trackers.find(t => /threatmetrix/i.test(t.vendor))) advice.push('ThreatMetrix có hồ sơ device persistent — reset device/clear app data trước khi đổi account.');
  if (report.risk_endpoints.find(r => /step.?up|2fa/i.test(r.path))) advice.push('Đã bị step-up auth — risk score account này đã cao, đổi proxy + reset device fingerprint trước khi thao tác tiếp.');
  if (report.pii_in_url.length) advice.push('PII trong URL sẽ vào access log của tracker → đổi sang body POST.');
  if (!advice.length) advice.push('Không phát hiện tín hiệu fingerprint/risk rõ rệt trong cửa sổ phân tích.');
  report.advice = advice;

  return report;
}

// ─── Optional: AI summarization ───
async function aiSummarize(report) {
  const apiKey = process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.GROQ_API_KEY;
  if (!apiKey) return { error: 'LLM_API_KEY chưa cấu hình. Set biến môi trường LLM_API_KEY (OpenAI/Groq/OpenRouter compatible) rồi restart service.' };

  const baseURL = process.env.LLM_BASE_URL || 'https://api.openai.com/v1';
  const model = process.env.LLM_MODEL || 'gpt-4o-mini';

  // Trim report so it fits in token budget
  const compact = {
    gateway: report.gateway,
    window: report.window,
    summary: report.summary,
    risk_score: report.risk_score,
    risk_reasons: report.risk_reasons,
    trackers: report.trackers.slice(0, 20),
    fp_headers: report.fp_headers.slice(0, 30).map(h => ({ h: h.header, n: h.count, sample: h.sample_value?.slice(0, 60) })),
    fp_body_fields: report.fp_body_fields.slice(0, 20),
    risk_endpoints: report.risk_endpoints.slice(0, 15),
    cookies_set: report.cookies_set.slice(0, 20).map(c => c.name),
    auth_chain: report.auth_chain,
    geo_signals: report.geo_signals,
    geo_mismatches: report.geo_mismatches,
    top_hosts: report.top_hosts.slice(0, 15),
    jwt_payload_samples: report.jwt_tokens.slice(0, 3).map(j => j.payload),
  };

  const sys = `Bạn là chuyên gia bảo mật/forensic phân tích traffic mobile/web đã capture qua MITM proxy.
Trả lời bằng tiếng Việt, ngắn gọn, có cấu trúc Markdown:
1) **Tóm tắt**: hệ thống nào đang theo dõi (vendor + category)
2) **Dữ liệu bị thu thập**: liệt kê PII/device data cụ thể
3) **Tín hiệu rủi ro**: tại sao server có thể đã flag user (mismatch, step-up, fingerprint persistent...)
4) **Khuyến nghị giảm thiểu**: hướng dẫn thực tế cho user
Tránh đưa hướng dẫn vi phạm pháp luật/ToS. Tập trung vào awareness và privacy hygiene.`;

  const body = {
    model,
    temperature: 0.3,
    messages: [
      { role: 'system', content: sys },
      { role: 'user', content: 'Đây là report rule-based:\n```json\n' + JSON.stringify(compact, null, 2) + '\n```\nHãy phân tích.' },
    ],
  };

  try {
    const r = await fetch(baseURL.replace(/\/$/, '') + '/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
    const text = j.choices?.[0]?.message?.content || '(LLM trả về rỗng)';
    return { ok: true, model, text };
  } catch(e) {
    return { error: 'LLM call failed: ' + e.message };
  }
}

module.exports = { analyzeGateway, aiSummarize };

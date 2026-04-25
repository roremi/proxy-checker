// captures.js — HTTP(S) flow ingest from mitmproxy + storage + realtime broadcast.
//
// Architecture:
//   mitmproxy addon  ──POST──▶  /api/_internal/capture  ──┐
//                                                         ├──▶ ring buffer (last N in-memory, fast for UI scroll)
//                                                         ├──▶ SQLite (durable history, query by filter)
//                                                         └──▶ WebSocket broadcast to /ws/captures clients
//   UI ──GET──▶  /api/captures            (filter + paginate from SQLite)
//   UI ──GET──▶  /api/captures/:id        (full headers + body, base64 → user decodes client-side)
//   UI ──WS──▶   /ws/captures?token=...   (live stream of new flows)

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { WebSocketServer } = require('ws');

const RING_MAX = 1000;
const DB_FILE  = path.join(__dirname, 'captures.db');
const TOKEN_FILE = '/etc/openvpn/mitm-ca/.capture-token';

let CAPTURE_TOKEN = '';
try { CAPTURE_TOKEN = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); }
catch(_) { console.warn('[captures] no token file at', TOKEN_FILE, '— /api/_internal/capture will reject all'); }

const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS flows (
    id           TEXT PRIMARY KEY,
    ts           INTEGER NOT NULL,
    gateway      TEXT NOT NULL,
    method       TEXT NOT NULL,
    scheme       TEXT,
    host         TEXT,
    port         INTEGER,
    path         TEXT,
    url          TEXT,
    http_version TEXT,
    client_ip    TEXT,
    status       INTEGER,
    elapsed_ms   INTEGER,
    req_size     INTEGER,
    res_size     INTEGER,
    req_truncated INTEGER,
    res_truncated INTEGER,
    error        TEXT,
    req_headers  TEXT,   -- JSON
    res_headers  TEXT,   -- JSON
    req_body_b64 TEXT,
    res_body_b64 TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_flows_ts        ON flows(ts DESC);
  CREATE INDEX IF NOT EXISTS idx_flows_gw_ts     ON flows(gateway, ts DESC);
  CREATE INDEX IF NOT EXISTS idx_flows_host      ON flows(host);
  CREATE INDEX IF NOT EXISTS idx_flows_status    ON flows(status);
`);

// Auto-prune older than 24h every 5 min so disk doesn't blow up
setInterval(() => {
  try {
    const cutoff = Date.now() - 24 * 3600_000;
    const r = db.prepare('DELETE FROM flows WHERE ts < ?').run(cutoff);
    if (r.changes > 0) console.log('[captures] pruned', r.changes, 'old flows');
  } catch(e) { console.warn('[captures] prune err', e.message); }
}, 5 * 60_000);

const insertStmt = db.prepare(`
  INSERT OR REPLACE INTO flows
    (id, ts, gateway, method, scheme, host, port, path, url, http_version, client_ip,
     status, elapsed_ms, req_size, res_size, req_truncated, res_truncated, error,
     req_headers, res_headers, req_body_b64, res_body_b64)
  VALUES (@id, @ts, @gateway, @method, @scheme, @host, @port, @path, @url, @http_version, @client_ip,
          @status, @elapsed_ms, @req_size, @res_size, @req_truncated, @res_truncated, @error,
          @req_headers, @res_headers, @req_body_b64, @res_body_b64)
`);

// In-memory ring (lightweight summaries, no body — for the live grid)
const ring = [];
function pushRing(summary) {
  ring.unshift(summary);
  if (ring.length > RING_MAX) ring.length = RING_MAX;
}

// WebSocket clients (admin: see all flows; public: per-gateway scoped)
const wsClients = new Set();                    // admin /ws/captures
const wsPublicByGw = new Map();                 // gateway -> Set<ws>
function broadcast(summary) {
  const msg = JSON.stringify({ type: 'flow', flow: summary });
  for (const ws of wsClients) {
    if (ws.readyState === 1) {
      try { ws.send(msg); } catch(_){}
    }
  }
  const pubSet = wsPublicByGw.get(summary.gateway);
  if (pubSet) {
    for (const ws of pubSet) {
      if (ws.readyState === 1) {
        try { ws.send(msg); } catch(_){}
      }
    }
  }
}

function summarize(f) {
  return {
    id: f.id, ts: f.ts, gateway: f.gateway, method: f.method,
    host: f.host, path: f.path, url: f.url, status: f.status,
    scheme: f.scheme, elapsed_ms: f.elapsed_ms,
    req_size: f.req_size, res_size: f.res_size,
    client_ip: f.client_ip, error: f.error || null,
  };
}

// Express + WS plumbing
function attach(app, server, requireVpnToken) {
  // Internal ingest from mitmproxy addon (no auth except shared token; bound 127.0.0.1)
  app.post('/api/_internal/capture', (req, res) => {
    const tok = req.headers['x-capture-token'] || '';
    if (!CAPTURE_TOKEN || tok !== CAPTURE_TOKEN) return res.status(401).json({ error: 'bad token' });
    const f = req.body || {};
    if (!f.id || !f.method) return res.status(400).json({ error: 'missing fields' });
    const row = {
      id: String(f.id),
      ts: Number(f.ts) || Date.now(),
      gateway: String(f.gateway || 'unknown'),
      method: String(f.method),
      scheme: f.scheme || '',
      host: f.host || '',
      port: f.port || 0,
      path: f.path || '',
      url: f.url || '',
      http_version: f.http_version || '',
      client_ip: f.client_ip || '',
      status: Number(f.status) || 0,
      elapsed_ms: Number(f.elapsed_ms) || 0,
      req_size: Number(f.req_size) || 0,
      res_size: Number(f.res_size) || 0,
      req_truncated: f.req_truncated ? 1 : 0,
      res_truncated: f.res_truncated ? 1 : 0,
      error: f.error || null,
      req_headers: JSON.stringify(f.req_headers || {}),
      res_headers: JSON.stringify(f.res_headers || {}),
      req_body_b64: f.req_body_b64 || '',
      res_body_b64: f.res_body_b64 || '',
    };
    try { insertStmt.run(row); } catch(e) { console.warn('[captures] insert err', e.message); }
    const summary = summarize(row);
    pushRing(summary);
    broadcast(summary);
    res.json({ ok: true });
  });

  // GET history (filterable, paginated)
  // Query params: gateway, method, host_like, path_like, status_min, status_max, q (full-text url+host), limit, before_ts
  app.get('/api/captures', requireVpnToken, (req, res) => {
    const q = req.query;
    const where = [];
    const params = [];
    if (q.gateway)   { where.push('gateway = ?');             params.push(String(q.gateway)); }
    if (q.method)    { where.push('method = ?');              params.push(String(q.method).toUpperCase()); }
    if (q.host_like) { where.push('host LIKE ?');             params.push('%' + String(q.host_like) + '%'); }
    if (q.path_like) { where.push('path LIKE ?');             params.push('%' + String(q.path_like) + '%'); }
    if (q.status_min){ where.push('status >= ?');             params.push(parseInt(q.status_min, 10) || 0); }
    if (q.status_max){ where.push('status <= ?');             params.push(parseInt(q.status_max, 10) || 999); }
    if (q.q)         { where.push('(url LIKE ? OR host LIKE ?)'); const v = '%'+q.q+'%'; params.push(v, v); }
    if (q.before_ts) { where.push('ts < ?');                  params.push(parseInt(q.before_ts, 10)); }
    const lim = Math.min(parseInt(q.limit, 10) || 200, 1000);
    const sql = `SELECT id, ts, gateway, method, scheme, host, port, path, url, status,
                        elapsed_ms, req_size, res_size, client_ip, error
                 FROM flows
                 ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                 ORDER BY ts DESC LIMIT ?`;
    params.push(lim);
    try {
      const rows = db.prepare(sql).all(...params);
      res.json({ flows: rows, count: rows.length });
    } catch(e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET full flow detail (headers + base64 bodies). id can be UUID-like (mitmproxy) or numeric.
  app.get('/api/captures/:id([a-zA-Z0-9_-]+)', requireVpnToken, (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM flows WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ error: 'not found' });
      row.req_headers = JSON.parse(row.req_headers || '{}');
      row.res_headers = JSON.parse(row.res_headers || '{}');
      res.json(row);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // DELETE all flows (clear history)
  app.delete('/api/captures', requireVpnToken, (req, res) => {
    try {
      db.prepare('DELETE FROM flows').run();
      ring.length = 0;
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Stats: counts per gateway last 1h
  app.get('/api/captures/_stats', requireVpnToken, (req, res) => {
    try {
      const cutoff = Date.now() - 3600_000;
      const rows = db.prepare(`SELECT gateway, COUNT(*) AS n,
                                       SUM(res_size) AS bytes,
                                       SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS err
                                FROM flows WHERE ts >= ? GROUP BY gateway`).all(cutoff);
      res.json({ stats: rows });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Public: download CA cert for client install (no auth — cert itself is public)
  app.get('/api/mitm/cert.pem', (req, res) => {
    try {
      const pem = fs.readFileSync('/etc/openvpn/mitm-ca/mitmproxy-ca-cert.pem');
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Content-Disposition', 'attachment; filename="proxy-checker-ca.pem"');
      res.send(pem);
    } catch(e) { res.status(404).send('CA not generated yet'); }
  });
  app.get('/api/mitm/cert.cer', (req, res) => {
    try {
      const cer = fs.readFileSync('/etc/openvpn/mitm-ca/mitmproxy-ca-cert.cer');
      res.setHeader('Content-Type', 'application/x-x509-ca-cert');
      res.setHeader('Content-Disposition', 'attachment; filename="proxy-checker-ca.cer"');
      res.send(cer);
    } catch(e) { res.status(404).send('CA not generated yet'); }
  });

  // ─── PUBLIC per-gateway endpoints (no auth) ───
  // Build WHERE clause shared by list + export (only safe whitelisted filters)
  function buildPublicWhere(name, q) {
    const where = ['gateway = ?'];
    const params = [name];
    if (q.method)    { where.push('method = ?');                  params.push(String(q.method).toUpperCase()); }
    if (q.host_like) { where.push('host LIKE ?');                 params.push('%' + String(q.host_like) + '%'); }
    if (q.path_like) { where.push('path LIKE ?');                 params.push('%' + String(q.path_like) + '%'); }
    if (q.status_min){ where.push('status >= ?');                 params.push(parseInt(q.status_min, 10) || 0); }
    if (q.status_max){ where.push('status <= ?');                 params.push(parseInt(q.status_max, 10) || 999); }
    if (q.q)         { where.push('(url LIKE ? OR host LIKE ?)'); const v='%'+q.q+'%'; params.push(v, v); }
    if (q.before_ts) { where.push('ts < ?');                      params.push(parseInt(q.before_ts, 10)); }
    if (q.after_ts)  { where.push('ts > ?');                      params.push(parseInt(q.after_ts, 10)); }
    return { where: 'WHERE ' + where.join(' AND '), params };
  }

  // List captures with filters + pagination (no bodies, summary only)
  app.get('/api/public/g/:name/captures', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    if (!name) return res.status(400).json({ error: 'bad name' });
    const lim = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
    const { where, params } = buildPublicWhere(name, req.query);
    try {
      const sql = `SELECT id, ts, gateway, method, scheme, host, port, path, url, status,
                          elapsed_ms, req_size, res_size, client_ip, error
                   FROM flows ${where} ORDER BY ts DESC LIMIT ?`;
      const rows = db.prepare(sql).all(...params, lim);
      const total = db.prepare(`SELECT COUNT(*) AS n FROM flows ${where}`).get(...params).n;
      res.json({ flows: rows, count: rows.length, total });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Detail of a single flow — only if it belongs to that gateway
  app.get('/api/public/g/:name/captures/:id', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    try {
      const row = db.prepare('SELECT * FROM flows WHERE id = ? AND gateway = ?').get(req.params.id, name);
      if (!row) return res.status(404).json({ error: 'not found' });
      row.req_headers = JSON.parse(row.req_headers || '{}');
      row.res_headers = JSON.parse(row.res_headers || '{}');
      res.json(row);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Public: clear all flows for this gateway (no auth, scoped to single gateway)
  app.delete('/api/public/g/:name/captures', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    try {
      const r = db.prepare('DELETE FROM flows WHERE gateway = ?').run(name);
      // Also drop matching ring entries so the live UI doesn't re-show them
      for (let i = ring.length - 1; i >= 0; i--) if (ring[i].gateway === name) ring.splice(i, 1);
      res.json({ ok: true, deleted: r.changes });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ─── Analyzer (rule-based + optional AI) ───
  let analyzer = null;
  try { analyzer = require('./analyzer'); }
  catch(e) { console.warn('[captures] analyzer not loaded:', e.message); }

  // Quick info — does AI work?
  app.get('/api/public/g/:name/analyze/info', (req, res) => {
    const hasKey = !!(process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.GROQ_API_KEY);
    res.json({
      rule_based: !!analyzer,
      ai_available: hasKey,
      ai_model: process.env.LLM_MODEL || (hasKey ? 'gpt-4o-mini' : null),
    });
  });

  // Rule-based analysis
  app.get('/api/public/g/:name/analyze', (req, res) => {
    if (!analyzer) return res.status(500).json({ error: 'analyzer module not loaded' });
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!name) return res.status(400).json({ error: 'bad name' });
    try {
      const sinceMin = parseInt(req.query.since_minutes, 10);
      const opts = {
        limit: parseInt(req.query.limit, 10) || 5000,
        since: Number.isFinite(sinceMin) && sinceMin > 0 ? Date.now() - sinceMin * 60_000 : undefined,
      };
      res.json(analyzer.analyzeGateway(name, opts));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // AI summary (optional)
  app.post('/api/public/g/:name/analyze/ai', async (req, res) => {
    if (!analyzer) return res.status(500).json({ error: 'analyzer module not loaded' });
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!name) return res.status(400).json({ error: 'bad name' });
    try {
      const sinceMin = parseInt(req.query.since_minutes, 10);
      const report = analyzer.analyzeGateway(name, {
        limit: 5000,
        since: Number.isFinite(sinceMin) && sinceMin > 0 ? Date.now() - sinceMin * 60_000 : undefined,
      });
      const ai = await analyzer.aiSummarize(report);
      res.json({ report_summary: { risk_score: report.risk_score, risk_reasons: report.risk_reasons }, ai });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Stats per gateway (last 1h)
  app.get('/api/public/g/:name/stats', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    try {
      const cutoff = Date.now() - 3600_000;
      const r = db.prepare(`SELECT COUNT(*) AS n,
                                   SUM(res_size) AS bytes,
                                   SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS err
                            FROM flows WHERE gateway = ? AND ts >= ?`).get(name, cutoff);
      const total = db.prepare('SELECT COUNT(*) AS n FROM flows WHERE gateway = ?').get(name).n;
      res.json({ last_1h: r, total });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Export: NDJSON streamed (one flow per line, full headers + base64 bodies). Best for big exports.
  app.get('/api/public/g/:name/export.ndjson', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    const { where, params } = buildPublicWhere(name, req.query);
    const lim = Math.min(parseInt(req.query.limit, 10) || 100000, 100000);
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="captures-${name}-${Date.now()}.ndjson"`);
    try {
      const stmt = db.prepare(`SELECT * FROM flows ${where} ORDER BY ts DESC LIMIT ?`);
      let n = 0;
      for (const row of stmt.iterate(...params, lim)) {
        try { row.req_headers = JSON.parse(row.req_headers || '{}'); } catch(_){ row.req_headers = {}; }
        try { row.res_headers = JSON.parse(row.res_headers || '{}'); } catch(_){ row.res_headers = {}; }
        res.write(JSON.stringify(row) + '\n');
        n++;
      }
      res.end();
      console.log(`[captures] exported ${n} flows (ndjson) for ${name}`);
    } catch(e) {
      try { res.end('{"error":' + JSON.stringify(e.message) + '}\n'); } catch(_){}
    }
  });

  // Export: HAR 1.2 (compatible with Chrome DevTools, Postman, Insomnia, etc.)
  app.get('/api/public/g/:name/export.har', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    const { where, params } = buildPublicWhere(name, req.query);
    const lim = Math.min(parseInt(req.query.limit, 10) || 10000, 50000);
    try {
      const rows = db.prepare(`SELECT * FROM flows ${where} ORDER BY ts ASC LIMIT ?`).all(...params, lim);
      const entries = rows.map(r => {
        let reqH = {}, resH = {};
        try { reqH = JSON.parse(r.req_headers || '{}'); } catch(_){}
        try { resH = JSON.parse(r.res_headers || '{}'); } catch(_){}
        const reqHeadersArr = Object.entries(reqH).map(([n,v]) => ({ name:n, value:String(v) }));
        const resHeadersArr = Object.entries(resH).map(([n,v]) => ({ name:n, value:String(v) }));
        // Decode bodies (best-effort UTF-8) for HAR readability
        let reqText = '', resText = '';
        try { if (r.req_body_b64) reqText = Buffer.from(r.req_body_b64, 'base64').toString('utf8'); } catch(_){}
        try { if (r.res_body_b64) resText = Buffer.from(r.res_body_b64, 'base64').toString('utf8'); } catch(_){}
        const ct = (resH['content-type'] || resH['Content-Type'] || 'application/octet-stream');
        const reqCt = (reqH['content-type'] || reqH['Content-Type'] || '');
        return {
          startedDateTime: new Date(r.ts).toISOString(),
          time: r.elapsed_ms || 0,
          request: {
            method: r.method, url: r.url || `${r.scheme}://${r.host}${r.path||''}`,
            httpVersion: r.http_version || 'HTTP/1.1',
            headers: reqHeadersArr, queryString: [], cookies: [],
            headersSize: -1, bodySize: r.req_size || 0,
            postData: reqText ? { mimeType: reqCt || 'text/plain', text: reqText } : undefined,
          },
          response: {
            status: r.status || 0, statusText: '', httpVersion: r.http_version || 'HTTP/1.1',
            headers: resHeadersArr, cookies: [],
            content: { size: r.res_size || 0, mimeType: ct, text: resText },
            redirectURL: resH.location || resH.Location || '',
            headersSize: -1, bodySize: r.res_size || 0,
          },
          cache: {},
          timings: { send: 0, wait: r.elapsed_ms || 0, receive: 0 },
          serverIPAddress: '', _gateway: r.gateway, _client_ip: r.client_ip || '',
          _truncated_req: !!r.req_truncated, _truncated_res: !!r.res_truncated, _error: r.error || '',
        };
      });
      const har = {
        log: {
          version: '1.2',
          creator: { name: 'proxy-checker mitm', version: '1.0' },
          browser: { name: 'mitmproxy', version: '11' },
          pages: [],
          entries,
        },
      };
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="captures-${name}-${Date.now()}.har"`);
      res.send(JSON.stringify(har, null, 2));
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Export: CSV (summary only, no bodies)
  app.get('/api/public/g/:name/export.csv', (req, res) => {
    const name = String(req.params.name).replace(/[^a-zA-Z0-9_-]/g,'');
    const { where, params } = buildPublicWhere(name, req.query);
    const lim = Math.min(parseInt(req.query.limit, 10) || 50000, 100000);
    try {
      const rows = db.prepare(`SELECT ts, method, status, host, path, url, elapsed_ms, req_size, res_size, client_ip, error
                               FROM flows ${where} ORDER BY ts DESC LIMIT ?`).all(...params, lim);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="captures-${name}-${Date.now()}.csv"`);
      const csvEsc = v => { const s = (v==null?'':String(v)); return /[",\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s; };
      res.write('time_iso,method,status,host,path,url,elapsed_ms,req_size,res_size,client_ip,error\n');
      for (const r of rows) {
        res.write([new Date(r.ts).toISOString(), r.method, r.status, r.host, r.path, r.url, r.elapsed_ms, r.req_size, r.res_size, r.client_ip, r.error].map(csvEsc).join(',') + '\n');
      }
      res.end();
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // WebSocket upgrade handler — supports both admin /ws/captures and public /ws/g/<name>
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/ws/captures') {
      const tok = url.searchParams.get('token') || '';
      if (tok !== process.env.VPN_ADMIN_TOKEN && tok !== 'vpnadmin2026') {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        wsClients.add(ws);
        ws.send(JSON.stringify({ type: 'hello', recent: ring.slice(0, 200) }));
        ws.on('close', () => wsClients.delete(ws));
        ws.on('error', () => wsClients.delete(ws));
      });
      return;
    }
    const m = url.pathname.match(/^\/ws\/g\/([a-zA-Z0-9_-]+)$/);
    if (m) {
      const gw = m[1];
      wss.handleUpgrade(req, socket, head, (ws) => {
        if (!wsPublicByGw.has(gw)) wsPublicByGw.set(gw, new Set());
        wsPublicByGw.get(gw).add(ws);
        // Send only this gateway's recent
        const recent = ring.filter(f => f.gateway === gw).slice(0, 200);
        ws.send(JSON.stringify({ type: 'hello', recent }));
        ws.on('close', () => {
          const s = wsPublicByGw.get(gw); if (s) { s.delete(ws); if (!s.size) wsPublicByGw.delete(gw); }
        });
        ws.on('error', () => {
          const s = wsPublicByGw.get(gw); if (s) { s.delete(ws); if (!s.size) wsPublicByGw.delete(gw); }
        });
      });
      return;
    }
    // Unknown ws path — let other handlers (or none) deal with it
  });
}

module.exports = { attach };

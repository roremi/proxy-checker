# API Reference

Comprehensive API map for all web features in this project.

Base URL: `http://<host>:3000`

## 1) Authentication

- Admin token header: `x-vpn-token: <admin_password_or_VPN_TOKEN>`
- Customer key header: `x-api-key: <pk_xxx>`
- Some routes also accept query params:
  - `?token=<admin_token>`
  - `?api_key=<customer_api_key>`

## 2) Response Conventions

- Success: JSON object or file stream
- Error shape: `{ "error": "message" }`
- Common status codes:
  - `200` OK
  - `201` Created
  - `400` Invalid input
  - `401` Unauthorized
  - `403` Forbidden
  - `404` Not found
  - `409` Conflict
  - `429` Quota exceeded
  - `500` Server error

## 3) Route Index (All Features)

### 3.1 Admin Auth + Dashboard + Settings

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/admin/login` | none | Admin login, returns token |
| GET | `/api/admin/stats` | admin | Dashboard summary stats |
| GET | `/api/admin/system` | admin | Server resources (CPU/RAM/swap/disk/uptime) |
| GET | `/api/admin/settings` | admin | Get brand + server info |
| POST | `/api/admin/settings` | admin | Update brand and/or admin password |

### 3.2 Admin API Key Management

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/admin/keys` | admin | List customer keys |
| POST | `/api/admin/keys` | admin | Create customer key |
| PUT | `/api/admin/keys/:id` | admin | Update customer key |
| DELETE | `/api/admin/keys/:id` | admin | Delete customer key |
| POST | `/api/admin/keys/:id/reset` | admin | Regenerate key value |
| POST | `/api/admin/keys/:id/reset-usage` | admin | Reset bandwidth/check counters |

### 3.3 Admin Gateway Management

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/gateways` | admin | List gateways + runtime status |
| POST | `/api/gateways` | admin | Create gateway |
| DELETE | `/api/gateways/:name` | admin | Delete gateway |
| POST | `/api/gateways/:name/:action(start|stop|restart)` | admin | Control gateway services |
| POST | `/api/gateways/:name/mitm/:action(start|stop|status)` | admin | Control MITM service |
| GET | `/api/gateways/:name/clients` | admin | List OpenVPN clients of gateway |
| POST | `/api/gateways/:name/client` | admin | Create OpenVPN client + return ovpn |
| DELETE | `/api/gateways/:name/client/:client` | admin | Revoke OpenVPN client |
| GET | `/api/gateways/:name/client/:client/ovpn` | admin | Download OpenVPN profile |
| POST | `/api/gateways/:name/test` | admin | Test proxy/gateway egress |
| GET | `/api/gateways/:name/l2tp` | admin | L2TP users scoped to gateway |
| POST | `/api/gateways/:name/l2tp/reset` | admin | Reset L2TP users on gateway |
| PUT | `/api/gateways/:name/proxy` | admin | Update upstream proxy |

### 3.4 Admin VPN (WireGuard / OpenVPN / Shadowsocks / L2TP)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/vpn/wg/clients` | admin | List WireGuard clients |
| POST | `/api/vpn/wg/client` | admin | Create WireGuard client |
| DELETE | `/api/vpn/wg/client/:name` | admin | Delete WireGuard client |
| GET | `/api/vpn/wg/client/:name/conf` | admin | Get WireGuard config |
| GET | `/api/vpn/wg/client/:name/qr` | admin | Get WireGuard QR |
| GET | `/api/vpn/wg/status` | admin | WireGuard service status |
| GET | `/api/vpn/ov/status` | admin | OpenVPN server status |
| GET | `/api/vpn/ov/clients` | admin | OpenVPN clients |
| POST | `/api/vpn/ov/client` | admin | Create OpenVPN client |
| GET | `/api/vpn/ov/client/:name/ovpn` | admin | OpenVPN profile |
| DELETE | `/api/vpn/ov/client/:name` | admin | Delete OpenVPN client |
| GET | `/api/vpn/ss/info` | admin | Shadowsocks config summary |
| POST | `/api/vpn/ss/reset` | admin | Reset Shadowsocks password |
| GET | `/api/l2tp` | admin | L2TP/IPSec global status |
| PUT | `/api/l2tp/psk` | admin | Update L2TP PSK |
| GET | `/api/l2tp/users` | admin | List L2TP users |
| POST | `/api/l2tp/user` | admin | Add L2TP user |
| DELETE | `/api/l2tp/user/:key` | admin | Delete L2TP user |
| POST | `/api/l2tp/:action(start|stop|restart)` | admin | Control L2TP services |

### 3.5 Customer API (x-api-key)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/key/me` | customer | Current key profile, quotas, permissions |
| GET | `/api/customer/gateways` | customer | Accessible gateways |
| GET | `/api/customer/proxies` | customer | Owned proxy gateways |
| POST | `/api/customer/proxy` | customer | Create customer-owned proxy gateway |
| PUT | `/api/customer/proxy/:name` | customer | Update owned proxy gateway |
| DELETE | `/api/customer/proxy/:name` | customer | Delete owned proxy gateway |
| GET | `/api/customer/usage` | customer | Usage counters |
| GET | `/api/customer/gateway/:name/ip` | customer | Get gateway egress IP |
| POST | `/api/customer/gateway/:name/:action(start|stop|restart)` | customer | Control owned gateway |
| POST | `/api/customer/gateway/:name/mitm/:action(start|stop)` | customer | Toggle MITM |
| GET | `/api/customer/gateway/:name/clients` | customer | List owned OpenVPN clients for gateway |
| POST | `/api/customer/gateway/:name/client` | customer | Create owned OpenVPN client |
| GET | `/api/customer/vpn/clients` | customer | List all owned OpenVPN clients |
| GET | `/api/customer/vpn/client/:certName/ovpn` | customer | Re-download OpenVPN profile |
| DELETE | `/api/customer/vpn/client/:certName` | customer | Revoke owned OpenVPN client |
| GET | `/api/customer/gateway/:name/wg-clients` | customer | List owned WireGuard clients in gateway |
| POST | `/api/customer/gateway/:name/wg-client` | customer | Create owned WireGuard client |
| GET | `/api/customer/wg/client/:wgName` | customer | Get owned WireGuard client |
| DELETE | `/api/customer/wg/client/:wgName` | customer | Delete owned WireGuard client |
| GET | `/api/customer/l2tp` | customer | List own L2TP creds |
| POST | `/api/customer/l2tp/gateway/:name` | customer | Create/get own L2TP cred for owned gateway |

### 3.6 Proxy Checker Jobs + SSE

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/check` | optional customer key | Start proxy check batch job |
| GET | `/api/stream/:jobId` | none | SSE stream for job results |

Notes:
- If `x-api-key` is provided, endpoint enforces permission `check_proxy` and quota.

### 3.7 Proxy Libraries

Global/public library routes:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/library` | none | List global saved proxies |
| DELETE | `/api/library/:proxy` | none | Delete one global proxy |
| DELETE | `/api/library` | none | Clear global library |
| GET | `/api/library/export` | none | Export global library as text |

Per-customer library routes:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/customer/library` | customer | List own library |
| DELETE | `/api/customer/library/:proxy` | customer | Delete one proxy |
| DELETE | `/api/customer/library` | customer | Clear own library |
| GET | `/api/customer/library/export` | customer | Export own library |

### 3.8 Capture Ingest/Admin APIs (captured traffic)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/_internal/capture` | internal token `x-capture-token` | mitmproxy flow ingest |
| GET | `/api/captures` | admin | Query capture history |
| GET | `/api/captures/:id` | admin | Capture full detail |
| DELETE | `/api/captures` | admin | Delete all captures |
| GET | `/api/captures/_stats` | admin | Capture stats (last 1h) |

### 3.9 Public Gateway APIs (g page + customer/admin scoped access)

These require gateway access validation (admin token OR customer key with gateway access):

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/public/g/:name/info` | gateway access | Gateway health + metadata |
| POST | `/api/public/g/:name/mitm/:action(start|stop)` | gateway access | Toggle MITM |
| POST | `/api/public/g/:name/client` | gateway access | Create OpenVPN client and download ovpn |
| GET | `/api/public/g/:name/captures` | gateway access | List captures |
| GET | `/api/public/g/:name/captures/:id` | gateway access | Capture detail |
| DELETE | `/api/public/g/:name/captures` | gateway access | Clear gateway captures |
| GET | `/api/public/g/:name/stats` | gateway access | Capture stats for gateway |
| GET | `/api/public/g/:name/export.ndjson` | gateway access | Export captures NDJSON |
| GET | `/api/public/g/:name/export.har` | gateway access | Export captures HAR |
| GET | `/api/public/g/:name/export.csv` | gateway access | Export captures CSV |
| GET | `/api/public/g/:name/logs/stream` | gateway access | SSE live logs |
| GET | `/api/public/g/:name/analyze/info` | gateway access | Analyzer/provider info |
| GET | `/api/public/g/:name/analyze` | gateway access | Rule-based analysis |
| POST | `/api/public/g/:name/analyze/models` | gateway access | List AI provider models |
| POST | `/api/public/g/:name/analyze/auto-suggest` | gateway access | Auto model suggestion |
| POST | `/api/public/g/:name/analyze/ai` | gateway access | AI analysis summary |
| POST | `/api/public/g/:name/analyze/ai/stream` | gateway access | AI analysis SSE streaming |

### 3.10 Certificate Download APIs

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/mitm/cert.pem` | none | Download PEM CA cert |
| GET | `/api/mitm/cert.cer` | none | Download CER CA cert |

### 3.11 WebSocket APIs

| Path | Auth | Purpose |
|---|---|---|
| `/ws/captures?token=...` | admin token | Live capture stream (admin) |
| `/ws/g/:name?token=...` | gateway access | Live stream for one gateway |
| `/ws/g/:name?api_key=...` | gateway access | Live stream for one gateway |

## 4) Core Request/Response Examples

### 4.1 Admin login

Request:

```http
POST /api/admin/login
Content-Type: application/json

{ "password": "your-admin-password" }
```

Response:

```json
{ "ok": true, "token": "..." }
```

### 4.2 Start proxy check job

Request:

```http
POST /api/check
Content-Type: application/json
x-api-key: pk_xxx   # optional

{
  "proxies": ["socks5://1.2.3.4:1080", "host:port:user:pass"],
  "concurrency": 5,
  "timeout": 30000
}
```

Response:

```json
{ "jobId": "uuid", "total": 2 }
```

Then subscribe:

```http
GET /api/stream/<jobId>
Accept: text/event-stream
```

### 4.3 Get server resource metrics (dashboard)

Request:

```http
GET /api/admin/system
x-vpn-token: <token>
```

Response:

```json
{
  "at": "2026-06-04T04:00:00.000Z",
  "uptime_seconds": 12345,
  "loadavg": [0.08, 0.15, 0.21],
  "cpu": { "cores": 1, "usage_percent": 11.4 },
  "memory": { "total": 1879048192, "used": 345000000, "free": 1534048192, "used_percent": 18.4 },
  "swap": { "total": 524288000, "used": 120000000, "free": 404288000, "used_percent": 22.9 },
  "disk": { "mount": "/", "total": 20300431360, "used": 17000000000, "free": 3300431360, "used_percent": 83.7 }
}
```

### 4.4 Create WireGuard client (admin)

Request:

```http
POST /api/vpn/wg/client
x-vpn-token: <token>
Content-Type: application/json

{ "name": "alice_phone", "gateway": "gw1" }
```

### 4.5 Gateway captures (public scoped)

Request:

```http
GET /api/public/g/gw1/captures?limit=100&status_min=400&q=login
x-api-key: pk_xxx
```

### 4.6 AI analyze stream (SSE)

Request:

```http
POST /api/public/g/gw1/analyze/ai/stream
x-api-key: pk_xxx
Content-Type: application/json

{
  "provider": "openai",
  "apiKey": "sk-...",
  "model": "gpt-4o-mini",
  "limit": 5000,
  "since_minutes": 60,
  "wantReasoning": true
}
```

Response stream events (`data:` JSON):
- `report_summary`
- `meta`
- `auto_select`
- `thinking`
- `text`
- `usage`
- `note`
- `done`
- `error`

## 5) Query Filters (captures/export)

Supported query params on capture listing/export routes:

- `method`
- `host_like`
- `path_like`
- `status_min`
- `status_max`
- `q` (search in url/host)
- `before_ts`
- `after_ts` (public capture routes)
- `limit`

## 6) Frontend Coverage

This API map covers web pages and their features:

- Admin pages: login, dashboard, gateways, keys, settings, captures, l2tp
- Proxy checker page
- Customer portal pages
- Public gateway page (`/g`)
- Live streams (SSE + WebSocket)

## 7) Security Notes

- Do not expose internal ingest route `/api/_internal/capture` publicly.
- Prefer headers over query params for tokens in production.
- Rotate admin password/token and customer API keys regularly.
- Keep HTTPS enabled in front of this service.

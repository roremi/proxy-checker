# proxy-checker

Self-hosted SOCKS/HTTP proxy checker + multi-tenant VPN gateway manager
(OpenVPN + tun2socks → upstream SOCKS, transparent MITM via mitmproxy,
realtime traffic capture & AI analysis, customer self-service portal).

> ⚠️ This is a **server-side ops tool**. It expects a clean Ubuntu 22.04+
> host where it controls `openvpn`, `mitmproxy`, `tun2socks`, `dnsproxy`,
> `dnsmasq`, `xl2tpd` and `iptables`. Do **not** install it on a shared
> machine.

---

## Features

- **Proxy Checker** — bulk-test SOCKS5/HTTP proxies (IP, geo, ASN, leak, score).
- **VPN Gateways** — per-gateway OpenVPN server forwarding through a SOCKS
  upstream via `tun2socks` + per-gateway `dnsproxy`/`dnsmasq`.
- **L2TP/IPsec users** — managed pool with shared PSK.
- **Transparent MITM** (optional, per-gateway) — captures every HTTP(S)
  request the VPN client makes; SQLite store + WS live feed + HAR/NDJSON/CSV
  export.
- **AI traffic analysis** — rule-based + BYOK LLM (OpenAI / Anthropic /
  Groq / Ollama) summarising tracker/risk/auth findings.
- **Admin web UI** + **customer portal** + **per-gateway self-service page**
  (`/g?name=<gw>`).
- **Auth model**
  - Admin: password → `x-vpn-token` header (stored in `localStorage`).
  - Customer: `x-api-key` (provisioned by admin); each key has its own
    gateway scope, proxy-check quota, and proxy library.
  - Per-gateway page (`/g`) requires either admin token or a customer key
    whose `vpn_clients` / `allowed_gateways` includes that gateway.

---

## Quick links

- [INSTALL.md](INSTALL.md) — full step-by-step server install.
- [API.md](API.md) — complete API reference for all web features.
- `.env.example` — runtime env vars.
- `settings.example.json`, `api-keys.example.json`, `gateways.example.json`,
  `l2tp-users.example.json` — initial-state templates.
- `systemd/` — unit templates installed under `/etc/systemd/system/`.
- `scripts/` — privileged helpers installed under `/usr/local/sbin/` and
  `/usr/local/bin/`.
- `mitm/capture-addon.py` — mitmproxy addon installed under
  `/etc/openvpn/gateways/`.

---

## Repository layout

```
.
├── server.js               # Express HTTP/WS server (admin + customer + public APIs)
├── captures.js             # MITM capture store, WS feed, exports, AI hooks
├── analyzer.js             # Rule-based + LLM traffic analyzer
├── aiProviders.js          # OpenAI / Anthropic / Groq / Ollama clients
├── public/                 # All UI pages (login, dashboard, gateways, keys,
│                           # captures, portal, g.html …)
├── systemd/                # *.service templates (see INSTALL.md)
├── scripts/                # dnsproxy-prestart, tun2socks-watchdog
├── mitm/capture-addon.py   # mitmproxy traffic forwarder
└── *.example.json          # initial-state templates (real ones gitignored)
```

---

## Security notes

- All `*.json` runtime data (api-keys, gateways, settings, customer
  libraries, l2tp users, vpn-clients) **is gitignored**. Never commit real
  data — use the `.example.json` templates as a starting point.
- Pretty URLs only; `*.html`, `*.bak`, `*.old`, `*.swp`, `*.map`, `*.env`
  are blocked at the static layer.
- `/g` and `/api/public/g/:name/*` enforce per-gateway access (admin
  bypass). The WebSocket `/ws/g/<name>` validates `token` / `api_key` from
  the query string.
- `/api/_internal/capture` requires the local `CAPTURE_TOKEN` and is meant
  to be reachable only from `127.0.0.1`.

See [INSTALL.md](INSTALL.md) for the full bring-up procedure on a fresh
server.

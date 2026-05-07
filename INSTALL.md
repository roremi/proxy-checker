# INSTALL — proxy-checker on a fresh Ubuntu 22.04 / 24.04 server

This document walks through bringing the whole stack up from a clean VM.
Run every command as **root** (or with `sudo`). Adjust paths if you don't
deploy under `/root/proxy-checker`.

---

## 0. Prerequisites

- Ubuntu 22.04 LTS or 24.04 LTS, x86_64.
- Public IPv4 with `iptables` (legacy or nft, both fine).
- A domain name pointed at the server is recommended (for HTTPS / nicer
  customer links), but not required.
- Open ports:
  - **TCP 3000** — admin/customer web UI (put behind nginx/Caddy + TLS in
    production).
  - **UDP 1194–1199** (or whichever range you assign to gateways) —
    OpenVPN.
  - **UDP 500 / 4500** — IPsec (L2TP).
  - Per-gateway MITM port (auto-allocated, exposed only to the VPN client
    transparently — usually you don't need to publish it).

---

## 1. Install system dependencies

```bash
apt update
apt install -y \
    git curl ca-certificates iproute2 iptables iptables-persistent \
    openvpn easy-rsa \
    dnsmasq \
    xl2tpd strongswan strongswan-pki libcharon-extra-plugins \
    python3 python3-pip python3-venv \
    build-essential
```

### Node.js 20 LTS

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
node -v   # → v20.x
```

### tun2socks (xjasonlyu/tun2socks)

```bash
TUN2SOCKS_VER=v2.5.2
curl -L -o /tmp/t2s.zip \
  "https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VER}/tun2socks-linux-amd64.zip"
( cd /tmp && unzip -o t2s.zip && install -m 0755 tun2socks-linux-amd64 /usr/local/bin/tun2socks )
tun2socks -version
```

### dnsproxy (AdguardTeam/dnsproxy)

```bash
DNSPROXY_VER=v0.73.4
curl -L -o /tmp/dnsproxy.tgz \
  "https://github.com/AdguardTeam/dnsproxy/releases/download/${DNSPROXY_VER}/dnsproxy-linux-amd64-${DNSPROXY_VER}.tar.gz"
( cd /tmp && tar -xzf dnsproxy.tgz && install -m 0755 linux-amd64/dnsproxy /usr/local/bin/dnsproxy )
dnsproxy --version
```

### mitmproxy (for transparent capture, optional but enables the Captures
feature)

```bash
pip3 install --upgrade mitmproxy        # installs mitmdump to /usr/local/bin
mitmdump --version
```

> Disable the host's stub resolver if it grabs port 53 (`systemd-resolved`):
> ```bash
> systemctl disable --now systemd-resolved
> rm -f /etc/resolv.conf
> echo 'nameserver 1.1.1.1' > /etc/resolv.conf
> ```

---

## 2. Clone the repo

```bash
cd /root
git clone https://github.com/roremi/proxy-checker.git
cd proxy-checker
npm install --omit=dev
```

---

## 3. Initialise OpenVPN PKI (easy-rsa)

```bash
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
openvpn --genkey secret /etc/openvpn/server/ta.key
```

Server certs are issued by the app on demand via `./easyrsa gen-req` /
`sign-req` (see `server.js` lines around 860). Confirm easy-rsa is in
`/etc/openvpn/easy-rsa` (the path is hard-coded).

---

## 4. Install systemd unit templates and helper scripts

```bash
cp systemd/*.service systemd/*.timer /etc/systemd/system/
cp scripts/dnsproxy-prestart            /usr/local/sbin/dnsproxy-prestart
cp scripts/tun2socks-watchdog           /usr/local/bin/tun2socks-watchdog
chmod +x /usr/local/sbin/dnsproxy-prestart /usr/local/bin/tun2socks-watchdog

systemctl daemon-reload
```

Templates installed (instantiated per gateway as `<unit>@<gw_name>`):

| Unit                              | What it does                                  |
|-----------------------------------|-----------------------------------------------|
| `openvpn-server@<gw>.service`     | OpenVPN server (Ubuntu's stock unit).         |
| `tun2socks@<gw>.service`          | Per-gateway TUN → upstream SOCKS bridge.      |
| `dnsproxy@<gw>.service`           | DNS over TUN → SOCKS via dnsproxy.            |
| `dnsmasq-gw@<gw>.service`         | dnsmasq listener on the VPN gateway IP.       |
| `mitmproxy@<gw>.service`          | Transparent MITM (only when MITM is ON).      |
| `tun2socks-watchdog@<gw>.timer`   | 30s health-check + auto-restart of the chain. |

---

## 5. Set up MITM (optional)

```bash
mkdir -p /etc/openvpn/mitm-ca /var/lib/mitmproxy
chown nobody:nogroup /var/lib/mitmproxy

# Generate the shared MITM CA (one-time)
mitmdump --set confdir=/etc/openvpn/mitm-ca -q &
sleep 5; pkill -f "mitmdump.*confdir=/etc/openvpn/mitm-ca"

# Internal ingest token shared between mitmproxy addon and the Node app
openssl rand -hex 16 > /etc/openvpn/mitm-ca/.capture-token
chmod 600 /etc/openvpn/mitm-ca/.capture-token

# Install the addon mitmproxy@<gw>.service launches
mkdir -p /etc/openvpn/gateways
cp mitm/capture-addon.py /etc/openvpn/gateways/capture-addon.py
```

The `mitmproxy@.service` unit runs as a per-gateway user `mitm-<gw>`. The
node app creates that user automatically when MITM is first turned on.

---

## 6. Seed runtime data files

```bash
cp settings.example.json     settings.json
cp api-keys.example.json     api-keys.json
cp gateways.example.json     gateways.json
cp l2tp-users.example.json   l2tp-users.json
echo '{}' > customer-libraries.json
echo '{}' > proxy-library.json
echo '{}' > ovpn-clients.json
echo '{}' > vpn-clients.json
chmod 600 settings.json api-keys.json l2tp-users.json
```

Then edit `settings.json` and put a strong admin password:

```json
{ "admin_password": "REPLACE-WITH-A-LONG-RANDOM-STRING" }
```

Optional `.env`:

```bash
cp .env.example .env
# edit PORT / VPN_TOKEN / LLM_* if needed
```

---

## 7. Install the app as a systemd service

```bash
cat >/etc/systemd/system/proxy-checker.service <<'EOF'
[Unit]
Description=Proxy Checker Web App
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/proxy-checker
EnvironmentFile=-/root/proxy-checker/.env
ExecStart=/usr/bin/node /root/proxy-checker/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now proxy-checker.service
systemctl status proxy-checker.service --no-pager
```

Browse to `http://<server-ip>:3000/login` and log in with the
`admin_password` from `settings.json`.

---

## 8. (Recommended) Put it behind nginx + TLS

```bash
apt install -y nginx
cat >/etc/nginx/sites-available/proxy-checker <<'EOF'
server {
    listen 80;
    server_name vpn.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # WebSocket support (live captures + /ws/g/<name>)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
ln -sf /etc/nginx/sites-available/proxy-checker /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# TLS (Let's Encrypt)
apt install -y certbot python3-certbot-nginx
certbot --nginx -d vpn.example.com
```

---

## 9. First-time admin walkthrough

1. Open `https://vpn.example.com/login` → enter `admin_password`.
2. **Settings** → optionally rotate the admin password.
3. **Gateways** → "Tạo gateway" → enter name, paste a SOCKS5 URL
   (`socks5://user:pass@host:port`). The app will:
   - allocate a `/30` TUN subnet, OpenVPN `/24`, UDP port, MITM port,
   - issue OpenVPN server cert via easy-rsa,
   - render config files into `/etc/openvpn/gateways/<name>/`,
   - `systemctl enable --now openvpn-server@<name> tun2socks@<name>
     dnsproxy@<name> dnsmasq-gw@<name> tun2socks-watchdog@<name>.timer`.
4. **API Keys** → create a customer key. Tick `check_proxy` permission and
   set quota / expiry. Optional `allowed_gateways` to pre-grant access to
   gateways the customer doesn't own client certs for.
5. **L2TP Users** → create per-gateway L2TP/IPsec accounts (PSK is in
   `l2tp-users.json`).

### Customer side

1. Customer opens `https://vpn.example.com/portal`, pastes their key.
2. From the portal they can run the proxy checker, manage their proxy
   library, and (for each VPN account) click **🌐 Manage** which opens
   `/g?name=<gw>&api_key=<key>`. The page auto-strips `api_key` from the
   URL into `sessionStorage` after first load.

### Per-gateway page (`/g`)

- **Install OVPN** — download `.ovpn` config.
- **Install CA** — download mitmproxy CA so HTTPS isn't broken when MITM is
  enabled.
- **MITM** — toggle transparent capture for that gateway only.
- **Captures** — live HTTP(S) feed with filters, export, AI analysis.

---

## 10. Backups

What to back up regularly:

| Path                                  | Why                                  |
|---------------------------------------|--------------------------------------|
| `/root/proxy-checker/*.json`          | All runtime state (keys, gateways…). |
| `/root/proxy-checker/captures.db*`    | Captured traffic SQLite store.       |
| `/etc/openvpn/easy-rsa/pki/`          | OpenVPN CA + issued client certs.    |
| `/etc/openvpn/gateways/`              | Per-gateway env files & OVPN configs.|
| `/etc/openvpn/mitm-ca/`               | Shared MITM CA + capture token.      |
| `/etc/systemd/system/{openvpn-server,tun2socks,dnsproxy,dnsmasq-gw,mitmproxy,tun2socks-watchdog}@*.{service,timer}` | Per-gateway systemd state. |

Simple snapshot:

```bash
tar -czf /root/pc-backup-$(date +%F).tgz \
  /root/proxy-checker/*.json \
  /root/proxy-checker/captures.db* \
  /etc/openvpn/easy-rsa/pki \
  /etc/openvpn/gateways \
  /etc/openvpn/mitm-ca
```

---

## 11. Restore on a new server

```bash
# 1. Repeat sections 1, 3, 4, 5, 7 above (system + units, NO data files).
# 2. Drop the backup in place:
tar -xzf pc-backup-YYYY-MM-DD.tgz -C /
# 3. Re-enable per-gateway units (names are inside gateways.json):
for gw in $(jq -r 'keys[]' /root/proxy-checker/gateways.json); do
  systemctl enable --now openvpn-server@$gw tun2socks@$gw \
    dnsproxy@$gw dnsmasq-gw@$gw tun2socks-watchdog@$gw.timer
done
# 4. Restart the app:
systemctl restart proxy-checker
```

---

## 12. Updating

```bash
cd /root/proxy-checker
git pull
npm install --omit=dev
# Re-copy any changed unit/script if the repo updated them:
cp systemd/*.service systemd/*.timer /etc/systemd/system/
cp scripts/dnsproxy-prestart  /usr/local/sbin/
cp scripts/tun2socks-watchdog /usr/local/bin/
cp mitm/capture-addon.py      /etc/openvpn/gateways/
systemctl daemon-reload
systemctl restart proxy-checker
```

---

## 13. Troubleshooting

- **`systemctl status proxy-checker`** — Node-side errors.
- **`journalctl -u tun2socks@<gw> -f`** — TUN issues / SOCKS auth.
- **`journalctl -u dnsproxy@<gw> -f`** — DNS resolution problems.
- **`journalctl -u mitmproxy@<gw> -f`** — TLS/CA issues, addon errors.
- **`/api/public/g/<gw>/info` returns 401** — your `x-api-key` doesn't have
  access to that gateway. Either add the gateway to the key's
  `allowed_gateways` or issue a VPN client cert for it from the **Gateways**
  page.
- **`/g?name=…` shows access-denied** — no admin token in `localStorage`
  AND no `api_key` in URL/sessionStorage. Open the page from the customer
  portal's "Manage" button.
- **Port 53 conflicts** — `systemd-resolved` or another stub. Disable it
  (see section 1).
- **iptables rules vanish after reboot** — `apt install iptables-persistent`
  and `netfilter-persistent save`.

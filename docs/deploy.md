# Deploying airgap-browser on a server

**English** · [Português](deploy.pt-BR.md)

How to run all three modes (isolated, rendered and remote) on a Linux server with
HTTPS. No port of the app is exposed to the internet: everything listens on
`127.0.0.1`, and a tunnel or reverse proxy in front publishes it.

```
browser ──HTTPS──▶ front proxy (TLS + login) ──▶ 127.0.0.1:18082  the app
                                  └── /remoto/* ──▶ 127.0.0.1:18085  remote-mode gate
```

Requirements: Docker with the `compose` plugin, about 4 GB of RAM (2 GB for the app
with the rendered-mode Chromium, 2 GB for the remote-mode Chromium) and a domain.

## 1. Clone and configure

```bash
sudo git clone https://github.com/tropeks/airgap-browser /opt/qp && cd /opt/qp
sudo cp .env.example .env
sudo $EDITOR .env
```

In `.env`, pick **one** way to log in:

- **App password:** `SAFEBROWSE_AUTH_PASSWORD=<a long password>`. The app and the
  remote mode ask for a username (`SAFEBROWSE_AUTH_USER`, default `qp`) and this
  password. Works with any front proxy.
- **Login at the front proxy** (e.g. Cloudflare Access): leave
  `SAFEBROWSE_AUTH_PASSWORD` empty. Only do this if the proxy covers the whole hostname.

If ports 18082 and 18085 are taken (`ss -ltn`), change `QP_PORT` and `QP_REMOTE_PORT`.

## 2. Start on boot

```bash
sudo cp deploy/safebrowse.service /etc/systemd/system/
# if you did not clone into /opt/qp, fix WorkingDirectory in the copied file
sudo systemctl daemon-reload
sudo systemctl enable --now safebrowse       # docker compose -f docker-compose.prod.yml up -d --build
curl -fsS http://127.0.0.1:18082/healthz     # {"ok":true}
```

The first build downloads the Playwright image (about 2 GB) and takes a few minutes.

## 3. Front proxy

The front proxy must terminate HTTPS, send `/remoto/*` to the gate and everything
else to the app, keep the original `Host` header (the gate compares `Origin` with
it) and pass WebSockets through. Two options:

### Option A: Cloudflare Tunnel + Access

No open ports on the server and no certificates to manage.

1. Install `cloudflared` and create a tunnel: `cloudflared tunnel login`, then
   `cloudflared tunnel create qp`.
2. In the ingress config (`/etc/cloudflared/config.yml`), add the snippet from
   `deploy/cloudflared-ingress.yml` with your hostname, before the catch-all
   `http_status:404`.
3. DNS: `cloudflared tunnel route dns qp <your hostname>`.
4. Validate and restart:
   ```bash
   sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
   sudo systemctl restart cloudflared
   ```
5. Login: in Zero Trust → Access → Applications, create a *Self-hosted* app for
   the whole hostname, with an *allow* policy for the e-mails that may sign in.
   With Access in front, the app password can stay empty.

### Option B: Caddy with the app password

Caddy gets the certificate by itself. Open ports 80 and 443 and use this `Caddyfile`:

```
qp.example.com {
    handle /remoto* {
        reverse_proxy 127.0.0.1:18085
    }
    handle {
        reverse_proxy 127.0.0.1:18082
    }
}
```

Here the login is the app password, so `SAFEBROWSE_AUTH_PASSWORD` must be set.
Nginx or Traefik work the same way, as long as they pass `Host`, `Upgrade` and
`Connection` through and send `X-Forwarded-For`.

## 4. Check and operate

```bash
curl -sI https://<your hostname>/healthz | head -1   # 200, or 302 to the Access login
curl -sI https://<your hostname>/ | head -1          # 401 with the app password; 302 with Access
cd /opt/qp && sudo git pull && sudo systemctl restart safebrowse   # update
sudo docker compose -f docker-compose.prod.yml logs -f              # logs
```

Static files are versioned by hash (`/static/app.js?v=<hash>`), so a CDN in front
never keeps serving an old UI.

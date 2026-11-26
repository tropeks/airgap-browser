# airgap-browser

**English** · [Português](README.pt-BR.md)

Open untrusted links without letting them touch your machine.

airgap-browser is a self-hosted isolation browser. You type a URL, your server
fetches the page, strips everything that can run code or leak information, and
sends back a clean copy inside a sandboxed `iframe`. The page's JavaScript never
reaches your browser, no cookies are sent or stored, and every image, stylesheet,
font and video goes through the proxy.

When a page really needs JavaScript, a login or a captcha, it can run on the
server instead, in a disposable Chromium, while you only see the result.

> Internally the project is still called QP (and SafeBrowse): you will see that
> name in the code and in the `QP_*` / `SAFEBROWSE_*` settings.

## Three modes

| mode | what runs where | good for |
|---|---|---|
| **Isolated** | The server downloads the HTML and sanitizes it. No script runs anywhere. | Articles, docs, suspicious links, anything mostly static. Light enough for any machine. |
| **Isolated, rendered** | The page's JavaScript runs in a headless Chromium on the server. Only the final DOM, sanitized the same way, reaches you. | Pages that build their content with JavaScript, still with zero scripts in your browser. |
| **Remote** | A full Chromium runs on the server, streamed to you as video. | Logins, captchas, pop-ups, sites that need real interaction. Optional. |

The isolated mode tells you when a page looks empty without JavaScript or is
behind an anti-bot wall, and offers the next mode with one click.

## Quick start

You need Docker with the `compose` plugin and about 2 GB of free RAM.

```bash
git clone https://github.com/tropeks/airgap-browser && cd airgap-browser
cp .env.example .env          # optional: password and ports
docker compose up --build     # then open http://127.0.0.1:8000
```

The port is bound to `127.0.0.1` by default. To use it from another machine, set
`SAFEBROWSE_AUTH_PASSWORD` and `QP_BIND=0.0.0.0` in `.env`. Without a password,
anyone who can reach the port can use your server as a proxy.

Without Docker (needs [uv](https://docs.astral.sh/uv/)):

```bash
uv sync
uv run playwright install chromium    # only for the rendered mode
uv run uvicorn app.main:app --reload  # http://127.0.0.1:8000
```

To run it on a server with HTTPS and the remote mode, follow
[docs/deploy.md](docs/deploy.md) (Cloudflare Tunnel + Access, or Caddy with a
password). The deploy guide is in Portuguese for now.

## How it protects you

Defense in depth, from the network inward:

1. **URL guard (SSRF).** Only `http`/`https`, no `user:pass@`, no `localhost` or
   internal names, service ports blocked. The host is resolved *before*
   connecting and every returned IP must be public (no loopback, private ranges,
   link-local or cloud metadata, CGNAT). The socket connects only to the checked
   IP, so DNS rebinding does not work, and each redirect is checked again.
2. **Fetcher.** Per-operation and total timeouts, a byte limit enforced while
   streaming, a redirect limit, no cookie jar, no environment proxy.
3. **HTML sanitizer.** A real HTML5 parser (Lexbor, the same WHATWG algorithm
   browsers use, so there is no parsing differential). Scripts, `object`,
   `embed`, `base`, `meta`, templates, MathML, comments and every `on*`
   attribute are removed. Links are rewritten to stay inside the isolated
   browser, resources go through `/asset`, and `javascript:`, `data:text/html`
   and `blob:` URLs are dropped. GET forms keep working; POST is disabled.
4. **CSS sanitizer.** `url()`, `@import`, `image-set()` and `src()` are
   rewritten to the proxy; `expression()`, `behavior` and `-moz-binding` are
   removed.
5. **Browser sandbox.** The page is shown in an `iframe` sandbox without
   scripts or pop-ups and served with a strict Content-Security-Policy, so
   even if something slipped past the sanitizer, your browser would not run it.
   `/asset` only serves images, CSS, fonts and media, always with `nosniff`.
6. **Optional password** (`SAFEBROWSE_AUTH_PASSWORD`, HTTP Basic, constant-time
   comparison) on every route except `/healthz`, shared with the remote mode.
7. **Rate limits** per IP, with a separate, larger bucket for page resources.

### The remote mode

```
you ─▶ front proxy (HTTPS + login) ─▶ gate (nginx, 127.0.0.1 only)
                                         │  "isolada" network: internal, no route out
                                         ▼
                                      Chromium + Selkies (video over WebSocket)
                                         │  --proxy-server
                                         ▼
                                      egress proxy (same SSRF guard) ─▶ internet
```

- **Egress:** the remote Chromium lives on an internal Docker network with no
  gateway. Its only way out is the guarded egress proxy, which refuses private
  IPs, loopback and metadata. QUIC and WebRTC UDP are disabled.
- **Ingress:** only through the gate, bound to `127.0.0.1` and published by your
  front proxy. The gate rejects requests whose `Origin` differs from the
  request's own `Host`, so another site cannot hijack the WebSocket with your login.
- **Container:** hardened desktop (no terminal, sudo, uploads or printing),
  `no-new-privileges`, all capabilities dropped except the few the init system
  needs, profile on tmpfs (wiped on every restart), 2 GB RAM cap.
- **Downloads:** files saved by the remote Chromium can be pulled to your
  computer from the Files panel. Only server → you is enabled, and the files are
  served with a sandbox CSP. Treat them like any download from the internet.

## Configuration

Everything is set with environment variables, usually through `.env`
(see [.env.example](.env.example)). The main ones:

| variable | default | what it does |
|---|---|---|
| `SAFEBROWSE_AUTH_PASSWORD` | empty | password for the app and the remote mode; empty disables it (only safe on localhost or behind a login) |
| `SAFEBROWSE_AUTH_USER` | `qp` | username for that password |
| `QP_BIND` / `QP_PORT` | `127.0.0.1` / `8000` | where `docker-compose.yml` publishes the app |
| `QP_PORT` / `QP_REMOTE_PORT` | `18082` / `18085` | local ports of the app and the remote gate in `docker-compose.prod.yml` |
| `SAFEBROWSE_RENDER` | `1` | enables the rendered mode |
| `SAFEBROWSE_REMOTE_SCREEN_URL` | empty | URL of the remote mode; empty hides the Remote button |
| `SAFEBROWSE_MAX_BYTES` | `5242880` | max size of a page or resource |
| `SAFEBROWSE_TIMEOUT` / `_TOTAL_TIMEOUT` | `15` / `30` | network timeouts in seconds |
| `SAFEBROWSE_RATE_LIMIT` | `120` | page requests per minute per IP |
| `SAFEBROWSE_TRUST_PROXY` | `0` | trust `X-Forwarded-For` (only behind a reverse proxy) |

The full list is in [README.pt-BR.md](README.pt-BR.md#configuração-variáveis-de-ambiente).

## Known limits

- In the isolated modes there are no cookies, so no logins, and POST is disabled.
- Sites with anti-bot protection may block the server or ask for a captcha.
  The captcha can be solved in the remote mode, but some sites refuse datacenter IPs.
- Passkeys do not work in the remote mode, because the browser runs on the server.
- The remote mode is a single shared browser: everyone who opens it sees and
  controls the same screen.
- The page cache lives in memory, so more than one replica needs sticky sessions.

## Development

```bash
uv sync
uv run playwright install chromium     # once, for the rendered-mode tests
uv run pytest                          # -m "not remote" skips the Chromium tests
uv run ruff check app tests && uv run ruff format app tests
```

Contributions are welcome, in English or Portuguese: see
[CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability privately, see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

# Publicar o QP num servidor

[English](deploy.md) · **Português**

Receita para subir os três modos (isolado, renderizado e remoto) num servidor Linux
com HTTPS. Nenhuma porta do QP fica exposta na internet: tudo escuta em `127.0.0.1`,
e quem publica é um túnel ou reverse proxy na frente.

```
navegador ──HTTPS──▶ proxy da frente (TLS + login) ──▶ 127.0.0.1:18082  app do QP
                                    └── /remoto/* ──▶ 127.0.0.1:18085  portão do modo remoto
```

Requisitos: Docker com o plugin `compose`, uns 4 GB de RAM (2 GB do app com o
Chromium do modo renderizado, 2 GB do Chromium do modo remoto) e um domínio.

## 1. Clonar e configurar

```bash
sudo git clone https://github.com/tropeks/airgap-browser /opt/qp && cd /opt/qp
sudo cp .env.example .env
sudo $EDITOR .env
```

No `.env`, escolha **uma** forma de login:

- **Senha do QP:** `SAFEBROWSE_AUTH_PASSWORD=<senha longa>`. O app e o modo remoto
  pedem usuário (`SAFEBROWSE_AUTH_USER`, padrão `qp`) e senha. Serve com qualquer
  proxy da frente.
- **Login no proxy da frente** (ex.: Cloudflare Access): deixe
  `SAFEBROWSE_AUTH_PASSWORD` vazio. Só faça isso se o proxy cobrir o hostname inteiro.

Se as portas 18082 e 18085 estiverem ocupadas (`ss -ltn`), troque `QP_PORT` e
`QP_REMOTE_PORT`.

## 2. Subir no boot

```bash
sudo cp deploy/safebrowse.service /etc/systemd/system/
# se não clonou em /opt/qp, ajuste WorkingDirectory no arquivo copiado
sudo systemctl daemon-reload
sudo systemctl enable --now safebrowse       # docker compose -f docker-compose.prod.yml up -d --build
curl -fsS http://127.0.0.1:18082/healthz     # {"ok":true}
```

O primeiro build baixa a imagem do Playwright (cerca de 2 GB) e demora alguns minutos.

## 3. Proxy da frente

O proxy precisa: terminar o HTTPS, mandar `/remoto/*` para o portão e o resto para o
app, manter o `Host` original (o portão compara o `Origin` com ele) e repassar
WebSocket. Duas opções testadas no desenho:

### Opção A: Cloudflare Tunnel + Access

Sem abrir porta no servidor nem cuidar de certificado.

1. Instale o `cloudflared` e crie um túnel: `cloudflared tunnel login`, depois
   `cloudflared tunnel create qp`.
2. No ingress (`/etc/cloudflared/config.yml`), inclua o trecho de
   `deploy/cloudflared-ingress.yml` com o seu hostname, antes do catch-all
   `http_status:404`.
3. DNS: `cloudflared tunnel route dns qp <seu hostname>`.
4. Valide e reinicie:
   ```bash
   sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
   sudo systemctl restart cloudflared
   ```
5. Login: em Zero Trust → Access → Applications, crie um app *Self-hosted* para o
   hostname inteiro, com uma policy *allow* para os e-mails que podem entrar.
   Com o Access na frente, a senha do QP pode ficar vazia.

### Opção B: Caddy com senha do QP

Caddy pega o certificado sozinho. Abra as portas 80 e 443 e use, no `Caddyfile`:

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

Aqui o login é a senha do QP: `SAFEBROWSE_AUTH_PASSWORD` precisa estar preenchido.
Nginx ou Traefik servem do mesmo jeito, desde que repassem `Host`, `Upgrade` e
`Connection` e mandem `X-Forwarded-For`.

## 4. Conferir e operar

```bash
curl -sI https://<seu hostname>/healthz | head -1    # 200, ou 302 para o login do Access
curl -sI https://<seu hostname>/ | head -1           # 401 com senha do QP; 302 com Access
cd /opt/qp && sudo git pull && sudo systemctl restart safebrowse   # atualizar
sudo docker compose -f docker-compose.prod.yml logs -f              # logs
```

Os estáticos já saem versionados por hash (`/static/app.js?v=<hash>`), então uma
CDN na frente não prende a interface antiga.

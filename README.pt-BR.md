# airgap-browser

[English](README.md) · **Português**

Antes chamado QP (e SafeBrowse); o nome segue no código e nas variáveis (`QP_*`, `SAFEBROWSE_*`).

Navegador isolado no estilo do antigo Surfola: você digita uma URL, o servidor
busca a página, remove tudo que executa ou vaza, e devolve o resultado num
`iframe` sandbox. O JavaScript da página nunca chega ao seu navegador, nenhum
cookie é enviado ou guardado, e todo recurso (imagem, CSS, fonte, mídia) passa
pelo proxy.

Três modos:

- **Isolado**: HTML sanitizado, sem nenhum script. Leve, roda em qualquer máquina.
- **Isolado renderizado**: o JavaScript roda num Chromium no servidor e só o DOM
  final, sanitizado, chega a você.
- **Remoto**: um Chromium completo no servidor, transmitido como vídeo, para login,
  captcha e sites que precisam de interação. Opcional, só no `docker-compose.prod.yml`.

## Início rápido

Precisa de Docker (com o plugin `compose`) e de uns 2 GB de RAM livres.

```bash
git clone https://github.com/tropeks/airgap-browser && cd airgap-browser
cp .env.example .env          # opcional: senha e portas
docker compose up --build     # abre http://127.0.0.1:8000
```

Por padrão a porta fica presa em `127.0.0.1`. Para usar de outra máquina, defina
`SAFEBROWSE_AUTH_PASSWORD` e `QP_BIND=0.0.0.0` no `.env`: sem senha, qualquer um
que alcance a porta usa o seu servidor como proxy.

Sem Docker (precisa de [uv](https://docs.astral.sh/uv/)):

```bash
uv sync
uv run playwright install chromium   # só para o modo renderizado
uv run uvicorn app.main:app --reload # http://127.0.0.1:8000
```

Para publicar num servidor com HTTPS e o modo remoto, siga [docs/deploy.pt-BR.md](docs/deploy.pt-BR.md).

## Segurança e uso responsável

- O QP é um proxy: quem tiver acesso a ele navega com o IP do seu servidor. Nunca
  o exponha sem senha (`SAFEBROWSE_AUTH_PASSWORD`) ou sem algo que autentique na
  frente (Cloudflare Access, reverse proxy com login).
- O modo remoto é um navegador de verdade, que guarda sessão enquanto o contêiner
  estiver de pé. Quem entra nele vê e controla o mesmo navegador.
- O isolamento reduz o risco, mas não o zera. Para reportar uma falha, veja
  [SECURITY.md](SECURITY.md).

## Como protege

Camadas, de fora para dentro:

1. **Guard de URL (SSRF)** — `app/urlguard.py`. Só `http`/`https`, sem
   `user:pass@`, sem `localhost`/`*.internal`/`*.local`, portas de serviços
   (redis, postgres, docker, …) bloqueadas. O host é resolvido **antes** da
   conexão e todos os IPs da resposta precisam ser públicos (nada de
   loopback, RFC1918, link-local/metadata `169.254.169.254`, CGNAT, IPv6
   mapeado). O socket só é aberto para o IP verificado (`GuardedBackend`,
   pinning no backend de rede do httpcore): a URL mantém o hostname, então
   SNI, certificado e pool de conexões são por host, e DNS rebinding não passa.
   Redirects são seguidos manualmente e cada salto passa pelo guard de novo.
   Respostas de DNS ficam 60 s em cache (a verificação de IP roda a cada uso).
2. **Fetcher** — `app/fetcher.py`. Timeout por operação e teto total por
   requisição, limite de bytes (streaming, aborta ao estourar), máximo de
   redirects, sem cookie jar, sem proxy de ambiente. A sanitização roda fora do
   event loop (thread), para uma página grande não congelar o servidor.
3. **Sanitizador HTML** — `app/sanitizer.py`, parser HTML5 (Lexbor via
   `selectolax`, em C, o mesmo algoritmo WHATWG dos navegadores, sem
   diferencial de parsing; a árvore é copiada para lxml). Remove `script`,
   `noscript`, `object`, `embed`, `applet`, `base`, `meta`, `template`, MathML,
   comentários e todo atributo `on*`; `iframe` vira um placeholder com link
   para abrir o frame isolado. `href` de link vira `/?u=<url>` (navega o
   navegador isolado); `src`/`srcset`/`poster`/`xlink:href` viram
   `/asset?url=`; `javascript:`/`data:text/html`/`blob:` somem. Formulários
   GET continuam funcionando (`/go` mescla os campos na URL alvo); POST é
   desativado.
4. **Sanitizador CSS** — `app/cssrewrite.py` (`tinycss2`). `url()`, `@import`,
   `image-set()` e `src()` reescritos para o proxy; `expression()`,
   `behavior` e `-moz-binding` removidos. Vale para `<style>`, `style=""` e
   folhas via `/asset`.
5. **Sandbox no cliente** — a página vai num
   `<iframe sandbox="allow-same-origin allow-forms allow-top-navigation-by-user-activation">`
   (sem scripts, sem popups; `allow-same-origin` é obrigatório para o cookie
   do Cloudflare Access ir junto nos requests de `/view` e `/asset`) e é servida com
   `Content-Security-Policy: default-src 'none'; img-src 'self' data:;
   style-src 'self' 'unsafe-inline'; … ; sandbox …` — mesmo que algo
   escapasse do sanitizador, o navegador não executa. `/asset` só serve
   imagem, CSS, fonte e mídia; HTML/JS retornam 415 e tudo sai com
   `X-Content-Type-Options: nosniff` e CSP `sandbox`.
6. **Senha** opcional (`SAFEBROWSE_AUTH_PASSWORD`, HTTP Basic, comparação em
   tempo constante) em todas as rotas menos `/healthz`. No modo remoto, o nginx
   do Selkies pede a mesma senha.
7. **Rate limit** por IP nos endpoints de busca (`SAFEBROWSE_RATE_LIMIT`) e,
   num balde separado e maior, nos recursos (`SAFEBROWSE_ASSET_RATE_LIMIT`).

## Modo isolado renderizado

Meio-termo entre os dois modos, para páginas que montam o conteúdo com
JavaScript. Quando o modo isolado avisa que a página depende de JS (ou de um
desafio anti-bot), o botão **renderizar com JS (continua isolado)** pede
`/api/page?render=1`: o Chromium da VPS carrega a página num contexto
descartável, atrás do proxy de saída guardado (`app/egress.py`), sem service
worker, sem download e sem WebAuthn, espera a rede assentar (até 4 s) e o DOM
final passa pelo mesmo sanitizador. O seu navegador recebe HTML estático, sem
nenhum script, como no modo isolado; interações que dependem de JS continuam
pedindo o modo remoto. Limites: `SAFEBROWSE_RENDER_CONCURRENCY` (2) e
`SAFEBROWSE_RENDER_TIMEOUT` (20 s); `SAFEBROWSE_RENDER=0` desliga (`app/render.py`).

## Modo Remoto

Para sites que dependem de JavaScript, login ou captcha (o modo isolado mostra
o aviso e oferece **abrir em modo remoto**). O botão **Remoto** abre
`SAFEBROWSE_REMOTE_SCREEN_URL` (no `docker-compose.prod.yml`, `/remoto/`); sem essa
variável o botão não aparece. Se havia uma página aberta, o endereço vai para a
área de transferência e basta `Ctrl+L`, `Ctrl+V` no Chromium remoto.

Roda um Chromium **completo** numa tela virtual e
transmite a tela inteira pelo [Selkies](https://docs.linuxserver.io/images/docker-chromium)
(imagem `linuxserver/chromium`, vídeo H.264 por WebSocket). Pop-ups, login
federado (FedCM), diálogos e abas aparecem como num desktop, sem código no QP
para cada caso.

```
você ─▶ proxy da frente (HTTPS + login) ─▶ remoto-portao (nginx, 127.0.0.1:18085)
                                          │  rede "isolada" (internal: sem rota para fora)
                                          ▼
                                       navegador (Chromium + Selkies)
                                          │  --proxy-server
                                          ▼
                                       saida:3128 (python -m app.egress) ─▶ internet
```

- **Saída:** o contêiner `navegador` só está na rede `isolada`, que não tem
  gateway. Nela só existem o contêiner `saida` (o mesmo proxy guardado do modo
  remoto, `python -m app.egress`, porta 3128 não publicada) e o portão. O app
  do QP fica fora dessa rede. O proxy recusa IP privado, loopback e metadata. `--proxy-bypass-list=<-loopback>`
  manda até `localhost` pelo proxy; QUIC e UDP do WebRTC desligados.
- **Entrada:** só pelo `remoto-portao`, preso em `127.0.0.1`, com uma regra de
  path no proxy da frente (exemplo do cloudflared em `deploy/cloudflared-ingress.yml`).
  Quem protege é a senha (`SAFEBROWSE_AUTH_PASSWORD`, repassada ao Selkies) ou o
  login do proxy da frente. O portão recusa requisição com `Origin` diferente do
  próprio `Host` (outro site não abre o WebSocket com o seu login).
- **Contêiner:** `HARDEN_DESKTOP` + `HARDEN_OPENBOX` (sem terminal, sudo,
  transferência de arquivos, impressão; o Chromium reabre se fechado),
  compartilhamento de sessão desligado, `no-new-privileges`, `cap_drop ALL`
  com só as capacidades que o s6 precisa para trocar de usuário, perfil em
  tmpfs (some a cada restart do contêiner), 2 GB de RAM.
- **Tamanho da tela:** acompanha a janela do seu navegador (inclusive ao
  redimensionar ou trocar de monitor) e a escala do sistema. A resolução manual
  do Selkies fica travada (`SELKIES_MANUAL_RESOLUTION=false|locked`).
- **Limites:** uma tela só (quem abre `/remoto/` vê e controla o
  mesmo navegador); downloads vêm pelo painel Arquivos (abaixo); passkeys continuam
  sem funcionar (o navegador está na VPS).
- **Downloads:** o Chromium remoto salva em `~/Downloads` (na VPS, em tmpfs:
  some a cada restart). Para trazer ao seu computador, abra o menu lateral do
  Selkies → **Arquivos**, ou use o botão **📥 Arquivos** na barra do QP (lista
  a pasta e baixa com um clique; partes `.crdownload` ficam de fora). Só o sentido VPS → você está
  ligado (`SELKIES_FILE_TRANSFERS=download`); upload segue desligado. O portão
  serve `/remoto/api/files/` e `/remoto/api/file-manager/` só com GET, com
  `Content-Security-Policy: sandbox` e `nosniff`: um `.html` baixado não roda
  script com a origem do QP. O arquivo em si continua não confiável,
  trate como qualquer download da internet.

## URLs ofuscadas

Os links que o app gera (`/?u=`, `/asset?url=`, o campo `url` dos formulários
GET e a lista de recentes) carregam o destino como `~<base64url(xor)>` em vez
de texto puro — `app/obfuscate.py` e o espelho `obf` em `app/static/app.js`.
Não é criptografia: serve para o destino não ficar legível no histórico do
navegador, nos logs da CDN/proxy e para quem olha a tela. Os endpoints ainda
aceitam URL em texto puro. A barra de endereço interna mostra sempre a URL
real.

## Endpoints

| rota | função |
|---|---|
| `GET /?u=<url>` | UI do navegador |
| `GET /api/page?url=[&render=1]` | busca (ou renderiza com JS no Chromium) + sanitiza; devolve `{id, url, title, status, kind, report, rendered}` |
| `GET /view/<id>` | HTML sanitizado (cache curto em memória) |
| `GET /asset?url=` | imagem, CSS (reescrito), fonte, mídia |
| `GET /go?url=&_form=1&campo=…` | destino dos formulários GET; redireciona para `/?u=` |
| `GET /healthz` | healthcheck |

## Configuração (variáveis de ambiente)

| variável | padrão | descrição |
|---|---|---|
| `SAFEBROWSE_MAX_BYTES` | `5242880` | tamanho máximo de página/recurso |
| `SAFEBROWSE_TIMEOUT` | `15` | timeout por operação de rede (s) |
| `SAFEBROWSE_TOTAL_TIMEOUT` | `30` | teto da requisição inteira, com redirects e corpo (s) |
| `SAFEBROWSE_MAX_REDIRECTS` | `5` | redirects seguidos |
| `SAFEBROWSE_RATE_LIMIT` | `120` | `/api/*` e `/go`: requisições por minuto por IP |
| `SAFEBROWSE_ASSET_RATE_LIMIT` | `2000` | `/asset`: requisições por minuto por IP |
| `SAFEBROWSE_SANITIZE_CONCURRENCY` | `2` | sanitizações simultâneas (CPU) |
| `SAFEBROWSE_TRUST_PROXY` | `0` | usa `X-Forwarded-For` como IP do cliente (só atrás de reverse proxy) |
| `SAFEBROWSE_ALLOW_PRIVATE` | `0` | permite alvos em IP privado — **só dev/teste** |
| `SAFEBROWSE_USER_AGENT` | Chrome/Linux | User-Agent enviado ao site alvo |
| `SAFEBROWSE_PAGE_TTL` / `_MAX` | `600` / `500` | cache de páginas sanitizadas |
| `SAFEBROWSE_RENDER` | `1` | liga o modo isolado renderizado (Chromium headless) |
| `SAFEBROWSE_RENDER_CONCURRENCY` | `2` | renderizações simultâneas (modo isolado renderizado) |
| `SAFEBROWSE_RENDER_TIMEOUT` | `20` | teto para carregar a página no Chromium (s) |
| `SAFEBROWSE_REMOTE_SCREEN_URL` | vazio | endereço do modo remoto (Chromium com tela); vazio esconde o botão Remoto |
| `SAFEBROWSE_AUTH_USER` | `qp` | usuário da senha (HTTP Basic) |
| `SAFEBROWSE_AUTH_PASSWORD` | vazio | senha do app e do modo remoto; vazio desliga (só com a porta em localhost ou login na frente) |
| `SAFEBROWSE_EGRESS_LISTEN` | `0.0.0.0:3128` | endereço do proxy de saída quando roda sozinho (`python -m app.egress`, contêiner `saida`) |

## Limites conhecidos

- No modo isolado, páginas que dependem de JavaScript aparecem vazias e sites
  com anti-bot devolvem 403 — o app avisa e oferece o modo remoto.
- No modo isolado não há cookies (sem login) e POST é desativado.
- No modo remoto, sites com anti-bot podem pedir captcha (resolvível na tela)
  ou recusar IP de datacenter; downloads passam pelo painel Arquivos do Selkies e passkeys não funcionam.
- O cache de páginas é em memória: com mais de uma réplica, use sticky
  sessions ou troque `PageCache` por Redis.

## Publicar num servidor

`docker-compose.prod.yml` sobe os três modos com as portas presas em
`127.0.0.1` (`QP_PORT`, padrão 18082, e `QP_REMOTE_PORT`, padrão 18085), e
`deploy/safebrowse.service` sobe tudo no boot. Na frente vai um túnel ou reverse
proxy com HTTPS que manda `/remoto/*` para o portão e o resto para o app. O passo
a passo, com Cloudflare Tunnel + Access ou com Caddy e senha, está em
[docs/deploy.pt-BR.md](docs/deploy.pt-BR.md).

## Desenvolvimento

```bash
uv run playwright install chromium   # uma vez, para os testes do modo renderizado
uv run pytest                        # -m "not remote" pula os testes com Chromium
uv run ruff check app tests && uv run ruff format app tests
```

Contribuições: veja [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[MIT](LICENSE).

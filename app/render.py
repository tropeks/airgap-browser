"""Modo isolado renderizado: Chromium headless na VPS executa o JS da página.

Só o DOM final sai daqui, e ainda passa pelo sanitizador do modo isolado: o
navegador do usuário nunca recebe script. O modo remoto interativo é o
navegador com tela (Selkies), fora deste processo; veja o README.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from urllib.parse import urlsplit

from playwright.async_api import Browser, Playwright, Route, async_playwright

from .config import Settings
from .egress import EgressProxy
from .urlguard import (
    BlockedURL,
    CachingResolver,
    Resolver,
    check_hostname,
    normalize_url,
    resolve_checked,
    system_resolver,
)

log = logging.getLogger("safebrowse.render")

CHROMIUM_ARGS = [
    "--no-sandbox",  # container já é o sandbox (cap_drop ALL, no-new-privileges, read-only)
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-quic",  # QUIC não passa pelo proxy de saída
    "--lang=pt-BR",
    # Sem isso o Chromium expõe navigator.webdriver=true e o Google (entre outros)
    # recusa login com "esse navegador ou app pode não ser seguro".
    "--disable-blink-features=AutomationControlled",
]
# Flags padrão do Playwright que denunciam automação e que não fazem falta aqui.
IGNORE_DEFAULT_ARGS = ["--enable-automation"]

# O Chromium remoto não tem autenticador (biometria, chave USB, celular pareado).
# Sem isto, sites que pedem passkey abrem um diálogo nativo que nunca resolve e
# engole o input; anunciando "sem WebAuthn", o site oferece as outras opções.
DISABLE_WEBAUTHN_JS = """
(() => {
  const unsupported = () => Promise.reject(new DOMException('WebAuthn indisponível', 'NotSupportedError'));
  try {
    Object.defineProperty(window, 'PublicKeyCredential', { value: undefined, configurable: true });
    if (navigator.credentials) {
      navigator.credentials.get = unsupported;
      navigator.credentials.create = unsupported;
    }
  } catch (e) {}
})();
"""


class RenderError(Exception):
    pass


class Renderer:
    def __init__(self, settings: Settings, *, resolver: Resolver | None = None) -> None:
        self.settings = settings
        self.resolver = resolver or CachingResolver(system_resolver)
        self._egress: EgressProxy | None = None
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._user_agent: str = settings.user_agent
        self._lock = asyncio.Lock()
        self._dns_cache: dict[str, tuple[float, bool]] = {}
        self._slots = asyncio.Semaphore(max(1, settings.render_concurrency))

    async def _ensure_browser(self) -> Browser:
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            if self._pw is None:
                self._pw = await async_playwright().start()
            if self._egress is None:
                self._egress = EgressProxy(self.resolver, allow_private=self.settings.allow_private)
                await self._egress.start()
            # Tudo que o Chromium abre (HTTP, HTTPS, WebSocket) sai pelo proxy guardado;
            # ``<-loopback>`` tira a exceção implícita de localhost.
            proxy = {"server": self._egress.url, "bypass": "<-loopback>"}
            # Chromium completo (headless "new"), não o headless_shell: o shell é
            # detectado como bot pelo Google mesmo com as flags acima.
            try:
                self._browser = await self._pw.chromium.launch(
                    headless=True,
                    channel="chromium",
                    args=CHROMIUM_ARGS,
                    ignore_default_args=IGNORE_DEFAULT_ARGS,
                    proxy=proxy,
                )
            except Exception:  # noqa: BLE001 - sem o channel instalado, cai no padrão
                log.warning("chromium completo indisponível; usando headless_shell")
                self._browser = await self._pw.chromium.launch(
                    headless=True,
                    args=CHROMIUM_ARGS,
                    ignore_default_args=IGNORE_DEFAULT_ARGS,
                    proxy=proxy,
                )
            major = self._browser.version.split(".")[0]
            # UA coerente com a versão real (client hints entregam a versão de verdade;
            # divergência é sinal de bot).
            self._user_agent = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{major}.0.0.0 Safari/537.36"
            )
            log.info("chromium iniciado")
            return self._browser

    async def aclose(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()
        if self._egress is not None:
            await self._egress.aclose()

    # ---- guard SSRF para tudo que o Chromium pedir --------------------------

    async def _route_guard(self, route: Route) -> None:
        url = route.request.url
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            await route.abort("blockedbyclient")
            return
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not await self._host_allowed(host, port):
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def _host_allowed(self, host: str, port: int) -> bool:
        key = f"{host}:{port}"
        cached = self._dns_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        ok = True
        try:
            check_hostname(host, allow_private=self.settings.allow_private)
            await resolve_checked(
                host, port, self.resolver, allow_private=self.settings.allow_private
            )
        except BlockedURL:
            ok = False
        if len(self._dns_cache) > 5000:
            self._dns_cache.clear()
        self._dns_cache[key] = (now + 60, ok)
        return ok

    async def render(self, raw_url: str) -> tuple[str, str, int]:
        """Carrega a página com JS num contexto descartável e devolve o DOM final.

        Devolve ``(html, url_final, status)``. O HTML segue para o mesmo
        sanitizador do modo isolado: o cliente continua sem receber JS, só o
        resultado que o JS montou. Barreiras: proxy de saída guardado,
        ``page.route``, sem service worker, sem download, sem WebAuthn.
        """
        url = normalize_url(raw_url, allow_private=self.settings.allow_private)
        timeout_ms = self.settings.render_timeout_seconds * 1000
        async with self._slots:
            browser = await self._ensure_browser()
            context = await browser.new_context(
                viewport={"width": 1280, "height": 900},
                accept_downloads=False,
                locale="pt-BR",
                user_agent=self._user_agent,
                service_workers="block",
            )
            try:
                await context.route("**/*", self._route_guard)
                await context.add_init_script(DISABLE_WEBAUTHN_JS)
                page = await context.new_page()
                page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
                try:
                    response = await page.goto(
                        url, wait_until="domcontentloaded", timeout=timeout_ms
                    )
                except Exception as exc:  # noqa: BLE001
                    msg = str(exc).splitlines()[0][:200]
                    if "ERR_BLOCKED_BY_CLIENT" in msg:
                        raise BlockedURL("destino bloqueado pelo guard") from exc
                    raise RenderError(msg) from exc
                # SPAs montam o conteúdo depois do DOMContentLoaded; espera a rede
                # assentar, com teto curto para páginas que nunca param (polling, ads).
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("networkidle", timeout=4000)
                html = await page.content()
                return html, page.url, response.status if response else 200
            finally:
                with contextlib.suppress(Exception):
                    await context.close()

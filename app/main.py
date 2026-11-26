"""SafeBrowse — endpoints HTTP."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from html import escape
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .cssrewrite import rewrite_css
from .fetcher import BlockedURL, Fetcher, FetchError, FetchResult, TooLarge
from .obfuscate import decode, encode
from .pagecache import PageCache
from .ratelimit import RateLimiter
from .render import Renderer
from .sanitizer import FRAME_CSP_HEADER, sanitize_html, wrap_image, wrap_text
from .urlguard import normalize_url

log = logging.getLogger("safebrowse")
STATIC_DIR = Path(__file__).parent / "static"

ASSET_TYPES_PREFIX = ("image/", "font/", "video/", "audio/")
ASSET_TYPES_EXACT = {
    "text/css",
    "application/font-woff",
    "application/font-woff2",
    "application/x-font-ttf",
    "application/x-font-opentype",
    "application/vnd.ms-fontobject",
    "application/octet-stream",  # fontes servidas sem mime correto
}
APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
    "object-src 'none'; frame-ancestors 'none'"
)


def create_app(
    settings: Settings | None = None,
    *,
    fetcher: Fetcher | None = None,
    renderer: Renderer | None = None,
) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not logging.getLogger("safebrowse").handlers and not logging.getLogger().handlers:
            logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        app.state.settings = settings
        app.state.fetcher = fetcher or Fetcher(settings)
        app.state.cache = PageCache(settings.page_cache_ttl, settings.page_cache_max)
        app.state.limiter = RateLimiter(settings.rate_limit_per_minute)
        app.state.asset_limiter = RateLimiter(settings.asset_rate_limit_per_minute)
        app.state.cpu = asyncio.Semaphore(max(1, settings.sanitize_concurrency))
        app.state.renderer = renderer or (Renderer(settings) if settings.render_enabled else None)
        if not settings.auth_password:
            log.warning(
                "SAFEBROWSE_AUTH_PASSWORD vazio: o app não pede senha. Deixe a porta só em "
                "127.0.0.1 ou ponha algo que autentique na frente."
            )
        try:
            yield
        finally:
            await app.state.fetcher.aclose()
            if app.state.renderer is not None:
                await app.state.renderer.aclose()

    app = FastAPI(title="SafeBrowse", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        path = request.url.path
        if settings.auth_password and path != "/healthz" and not _authorized(request, settings):
            return Response(
                "senha necessária",
                status_code=401,
                media_type="text/plain; charset=utf-8",
                headers={
                    "WWW-Authenticate": 'Basic realm="QP", charset="UTF-8"',
                    "Cache-Control": "no-store",
                },
            )
        limiter = (
            app.state.asset_limiter
            if path.startswith("/asset")
            else app.state.limiter
            if path.startswith(("/api/", "/go"))
            else None
        )
        if limiter is not None and not limiter.allow(_client_key(request, settings)):
            return JSONResponse(
                {
                    "error": "muitas requisições; tente de novo em instantes",
                    "code": "rate_limited",
                },
                status_code=429,
                headers={"Retry-After": "30"},
            )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if path.startswith("/static/"):
            response.headers["Cache-Control"] = (
                "public, max-age=31536000, immutable"
                if request.query_params.get("v")
                else "no-cache"
            )
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if not path.startswith(("/view/", "/asset")):
            response.headers.setdefault("Content-Security-Policy", APP_CSP)
            response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    @app.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        # Estáticos versionados pelo hash do conteúdo: atualização nunca fica presa em cache.
        return HTMLResponse(_index_html(app.state.settings), headers={"Cache-Control": "no-store"})

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        return {"ok": True}

    @app.get("/api/page")
    async def api_page(request: Request, url: str = Query(...), render: int = 0) -> JSONResponse:
        fetcher: Fetcher = app.state.fetcher
        cache: PageCache = app.state.cache
        url = decode(url)
        if render:
            failure, result = await _render(url)
            if failure is not None:
                return failure
        else:
            try:
                result = await fetcher.fetch(
                    url, accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"
                )
            except BlockedURL as exc:
                return _error(403, "blocked", f"URL bloqueada: {exc}")
            except TooLarge as exc:
                return _error(413, "too_large", str(exc))
            except FetchError as exc:
                return _error(502, "fetch_failed", str(exc))

        mime = result.content_type
        report: dict[str, int] = {}
        hints: list[str] = []
        if mime in {"text/html", "application/xhtml+xml"} or (
            mime == "application/octet-stream"
            and result.body[:512].lstrip().lower().startswith(b"<")
        ):
            # Sanitizar uma página de 2 MB ainda leva ~1,5 s de CPU (reescrita de URLs/CSS).
            # No event loop isso congelava o servidor inteiro (assets, modo remoto).
            async with app.state.cpu:
                sanitized = await asyncio.to_thread(
                    sanitize_html, result.body, result.url, result.charset, result.status
                )
            html_out, title, report = sanitized.html, sanitized.title, dict(sanitized.report)
            # Página já renderizada: os scripts removidos já rodaram no servidor.
            hints = [h for h in sanitized.hints if not (render and h == "needs_js")]
            kind = "html"
        elif mime.startswith("image/"):
            asset_src = "/asset?url=" + encode(result.url)
            html_out, title, kind = wrap_image(asset_src, result.url), result.url, "image"
        elif mime.startswith("text/") or mime in {"application/json", "application/xml"}:
            text = result.body.decode(result.charset or "utf-8", errors="replace")
            html_out, title, kind = wrap_text(text), result.url, "text"
        else:
            return _error(
                415,
                "unsupported_type",
                f"tipo de conteúdo não renderizado por segurança: {mime}",
                extra={"url": result.url},
            )
        page_id = cache.put(html_out, result.url, title)
        log.info("page %s -> %s (%s, %d bytes)", url, result.url, mime, len(result.body))
        return JSONResponse(
            {
                "id": page_id,
                "url": result.url,
                "title": title,
                "status": result.status,
                "kind": kind,
                "content_type": mime,
                "bytes": len(result.body),
                "report": report,
                "hints": hints,
                "rendered": bool(render),
            },
            headers={"Cache-Control": "no-store"},
        )

    async def _render(url: str) -> tuple[JSONResponse | None, FetchResult | None]:
        """Modo isolado renderizado: o Chromium executa o JS; o DOM final vira a página."""
        manager: Renderer | None = app.state.renderer
        if manager is None:
            return _error(503, "render_unavailable", "renderização desligada neste servidor"), None
        try:
            html, final_url, status = await manager.render(url)
        except BlockedURL as exc:
            return _error(403, "blocked", f"URL bloqueada: {exc}"), None
        except Exception as exc:  # noqa: BLE001
            log.info("render falhou para %s: %s", url, exc)
            return _error(502, "fetch_failed", f"falha ao renderizar: {exc}"[:300]), None
        body = html.encode("utf-8")
        if len(body) > settings.max_bytes:
            return _error(413, "too_large", "página renderizada excede o limite de tamanho"), None
        return None, FetchResult(
            url=final_url,
            status=status,
            content_type="text/html",
            charset="utf-8",
            body=body,
            headers=httpx.Headers(),
        )

    @app.get("/view/{page_id}", include_in_schema=False)
    async def view(page_id: str) -> Response:
        page = app.state.cache.get(page_id)
        if page is None:
            body = wrap_text("Página expirou. Recarregue no navegador.")
            return HTMLResponse(body, status_code=410, headers=_frame_headers())
        return HTMLResponse(page.html, headers=_frame_headers())

    @app.get("/asset")
    async def asset(url: str = Query(...)) -> Response:
        fetcher: Fetcher = app.state.fetcher
        try:
            result = await fetcher.fetch(decode(url), accept="image/*,text/css,font/*,*/*;q=0.5")
        except BlockedURL:
            return Response(status_code=403)
        except TooLarge:
            return Response(status_code=413)
        except FetchError:
            return Response(status_code=502)
        mime = result.content_type
        if not (mime.startswith(ASSET_TYPES_PREFIX) or mime in ASSET_TYPES_EXACT):
            return Response(status_code=415)
        if mime == "image/svg+xml":
            # SVG pode carregar scripts; só serve como imagem, com CSP sandbox no header.
            pass
        headers = {
            "Cache-Control": "public, max-age=3600",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "Content-Disposition": "inline",
        }
        if mime == "text/css":
            css = result.body.decode(result.charset or "utf-8", errors="replace")
            async with app.state.cpu:
                css = await asyncio.to_thread(rewrite_css, css, result.url)
            return Response(css, media_type="text/css; charset=utf-8", headers=headers)
        return Response(result.body, media_type=mime, headers=headers)

    @app.get("/go", include_in_schema=False)
    async def go(request: Request) -> Response:
        """Destino dos formulários GET reescritos: mescla os campos na URL alvo."""
        params = list(parse_qsl(request.url.query, keep_blank_values=True))
        target = decode(next((v for k, v in params if k == "url"), "") or "")
        if not target:
            return RedirectResponse("/", status_code=303)
        extra = [(k, v) for k, v in params if k not in {"url", "_form"}]
        try:
            merged = merge_query(normalize_url(target), extra)
        except BlockedURL:
            return RedirectResponse("/", status_code=303)
        return RedirectResponse("/?u=" + encode(merged), status_code=303)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def _static_version(name: str) -> str:
    return hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:10]


def _index_html(settings: Settings) -> str:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    for name in ("app.css", "app.js"):
        html = html.replace(f"/static/{name}", f"/static/{name}?v={_static_version(name)}")
    if settings.remote_screen_url:
        meta = f'<meta name="qp-remote-screen" content="{escape(settings.remote_screen_url)}">'
        html = html.replace("</head>", meta + "\n</head>", 1)
    return html


def merge_query(target: str, extra: list[tuple[str, str]]) -> str:
    parts = urlsplit(target)
    query = urlencode(extra) if extra else ""
    if parts.query and query:
        query = parts.query + "&" + query
    elif parts.query:
        query = parts.query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _frame_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": FRAME_CSP_HEADER,
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
    }


def _error(status: int, code: str, message: str, extra: dict | None = None) -> JSONResponse:
    payload = {"error": message, "code": code}
    if extra:
        payload.update(extra)
    return JSONResponse(payload, status_code=status, headers={"Cache-Control": "no-store"})


def _authorized(request: Request, settings: Settings) -> bool:
    """HTTP Basic com comparação em tempo constante (usuário e senha)."""
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "basic" or not value:
        return False
    try:
        user, sep, password = base64.b64decode(value, validate=True).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    ok_user = secrets.compare_digest(user.encode(), settings.auth_user.encode())
    ok_pass = secrets.compare_digest(password.encode(), settings.auth_password.encode())
    return bool(sep) and ok_user and ok_pass


def _client_key(request: Request, settings: Settings) -> str:
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


app = create_app()

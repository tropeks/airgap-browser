"""Busca remota com IP pinado, limite de tamanho e redirects verificados."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from .config import Settings
from .urlguard import (
    BlockedURL,
    CachingResolver,
    Resolver,
    normalize_url,
    resolve_checked,
    system_resolver,
)

REDIRECT_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """Falha ao buscar o recurso remoto (rede, timeout, status)."""


class TooLarge(FetchError):
    """Resposta maior que o limite configurado."""


@dataclass
class FetchResult:
    url: str  # URL final após redirects
    status: int
    content_type: str  # mime "puro", minúsculo, sem parâmetros
    charset: str | None
    body: bytes
    headers: httpx.Headers


def split_content_type(value: str | None) -> tuple[str, str | None]:
    if not value:
        return "application/octet-stream", None
    mime, _, rest = value.partition(";")
    charset = None
    for param in rest.split(";"):
        key, _, val = param.strip().partition("=")
        if key.strip().lower() == "charset" and val:
            charset = val.strip().strip('"').lower()
    return mime.strip().lower() or "application/octet-stream", charset


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Backend de rede que só abre conexão TCP para IP verificado pelo guard.

    O pinning acontece aqui, na hora de abrir o socket, e não na URL: a URL
    mantém o hostname, então o pool de conexões é separado por host, o SNI e a
    verificação do certificado usam o host certo, e uma conexão aberta para
    ``a.cdn.com`` nunca é reaproveitada para ``b.cdn.com`` só porque os dois
    caem no mesmo IP da CDN (isso gerava 421/403 e recursos que não carregavam).
    """

    def __init__(
        self,
        resolver: Resolver,
        *,
        allow_private: bool,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.resolver = resolver
        self.allow_private = allow_private
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.AsyncNetworkStream:
        ip = await resolve_checked(host, port, self.resolver, allow_private=self.allow_private)
        return await self._inner.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise BlockedURL("socket unix não permitido")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def guarded_transport(resolver: Resolver, *, allow_private: bool) -> httpx.AsyncHTTPTransport:
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=50, keepalive_expiry=30)
    transport = httpx.AsyncHTTPTransport(http2=True, trust_env=False, limits=limits)
    # httpx não expõe ``network_backend``; troca o pool pelo equivalente com o backend guardado.
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(trust_env=False),
        max_connections=limits.max_connections,
        max_keepalive_connections=limits.max_keepalive_connections,
        keepalive_expiry=limits.keepalive_expiry,
        http1=True,
        http2=True,
        network_backend=GuardedBackend(resolver, allow_private=allow_private),
    )
    return transport


class Fetcher:
    def __init__(
        self,
        settings: Settings,
        *,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.resolver = resolver or CachingResolver(system_resolver)
        if transport is None:
            transport = guarded_transport(self.resolver, allow_private=settings.allow_private)
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(
                settings.timeout_seconds, connect=min(5.0, settings.timeout_seconds)
            ),
            http2=True,
            follow_redirects=False,
            # Sem cookie jar: navegação anônima, nada persiste entre requisições.
            cookies=None,
            trust_env=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, raw_url: str, *, accept: str = "*/*") -> FetchResult:
        # O timeout do httpx vale por operação (cada leitura reinicia o relógio): um
        # servidor que pinga 1 byte a cada 10 s segurava a requisição para sempre.
        try:
            async with asyncio.timeout(self.settings.total_timeout_seconds):
                return await self._fetch(raw_url, accept)
        except TimeoutError as exc:
            host = urlsplit(raw_url if "://" in raw_url else "https://" + raw_url).hostname
            raise FetchError(f"tempo total esgotado ao acessar {host or raw_url}") from exc

    async def _fetch(self, raw_url: str, accept: str) -> FetchResult:
        allow_private = self.settings.allow_private
        url = normalize_url(raw_url, allow_private=allow_private)
        for _hop in range(self.settings.max_redirects + 1):
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            # Checagem antecipada (erro claro, sem abrir conexão); o GuardedBackend
            # repete a verificação no momento de conectar e é ele quem pina o IP.
            await resolve_checked(host, port, self.resolver, allow_private=allow_private)
            headers = {
                "User-Agent": self.settings.user_agent,
                "Accept": accept,
                "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate",
            }
            try:
                async with self._client.stream("GET", url, headers=headers) as resp:
                    if resp.status_code in REDIRECT_CODES and "location" in resp.headers:
                        url = normalize_url(
                            urljoin(url, resp.headers["location"]), allow_private=allow_private
                        )
                        continue
                    body = await self._read_limited(resp)
                    mime, charset = split_content_type(resp.headers.get("content-type"))
                    return FetchResult(
                        url=url,
                        status=resp.status_code,
                        content_type=mime,
                        charset=charset,
                        body=body,
                        headers=resp.headers,
                    )
            except httpx.TimeoutException as exc:
                raise FetchError(f"timeout ao acessar {host}") from exc
            except httpx.HTTPError as exc:
                raise FetchError(
                    f"erro de rede ao acessar {host}: {exc.__class__.__name__}"
                ) from exc
        raise FetchError("redirects demais")

    async def _read_limited(self, resp: httpx.Response) -> bytes:
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.settings.max_bytes:
            raise TooLarge("resposta excede o limite de tamanho")
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > self.settings.max_bytes:
                raise TooLarge("resposta excede o limite de tamanho")
            chunks.append(chunk)
        return b"".join(chunks)


__all__ = [
    "BlockedURL",
    "FetchError",
    "FetchResult",
    "Fetcher",
    "GuardedBackend",
    "TooLarge",
    "split_content_type",
]

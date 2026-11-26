"""Validação de URL e proteção contra SSRF.

Toda URL que o proxy vai buscar passa por aqui: só http/https, sem credenciais
embutidas, hostname resolvido e TODOS os IPs resultantes precisam ser públicos.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable
from urllib.parse import quote, urlsplit, urlunsplit

ALLOWED_SCHEMES = {"http", "https"}
# Portas de serviços que não falam HTTP: não há uso legítimo e evita usar o proxy
# como scanner/gatilho (redis, memcached, bancos, docker, k8s, etc.).
BLOCKED_PORTS = {
    1080,
    1433,
    1521,
    2375,
    2376,
    2379,
    2380,
    3306,
    3389,
    4369,
    5000,
    5432,
    5672,
    5900,
    5984,
    6000,
    6379,
    6380,
    7000,
    7001,
    7199,
    8500,
    8600,
    9000,
    9042,
    9092,
    9160,
    9200,
    9300,
    10250,
    11211,
    15672,
    25575,
    27017,
    27018,
    27019,
    50070,
}
ALLOWED_PORTS = ({80, 443} | set(range(1024, 65536))) - BLOCKED_PORTS

# Hostnames que nunca são públicos, independente do que o DNS responda.
BLOCKED_SUFFIXES = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
)
BLOCKED_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}

Resolver = Callable[[str, int], Awaitable[list[str]]]


class BlockedURL(ValueError):
    """URL recusada pelo guard (esquema, host, porta ou IP não permitido)."""


def normalize_url(raw: str, *, allow_private: bool = False) -> str:
    """Normaliza a entrada do usuário para uma URL http(s) absoluta.

    Aceita "example.com" (vira https://example.com/), remove fragmento e
    recusa userinfo (user:pass@host), esquemas fora de http/https e portas
    privilegiadas que não sejam 80/443.
    """
    raw = (raw or "").strip()
    if not raw:
        raise BlockedURL("URL vazia")
    if "://" not in raw:
        raw = ("https:" + raw) if raw.startswith("//") else ("https://" + raw)
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedURL(f"esquema não permitido: {scheme}")
    if parts.username is not None or parts.password is not None:
        raise BlockedURL("credenciais embutidas na URL não são permitidas")
    hostname = parts.hostname
    if not hostname:
        raise BlockedURL("URL sem host")
    try:
        port = parts.port
    except ValueError as exc:
        raise BlockedURL("porta inválida") from exc
    if port is not None and port not in ALLOWED_PORTS:
        raise BlockedURL(f"porta não permitida: {port}")
    check_hostname(hostname, allow_private=allow_private)
    netloc = hostname if ":" not in hostname else f"[{hostname}]"
    if port is not None:
        netloc += f":{port}"
    path = parts.path or "/"
    # Reescapa path/query preservando o que já está escapado.
    path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/%:@!$&'()*+,;=-._~?")
    return urlunsplit((scheme, netloc, path, query, ""))


def check_hostname(hostname: str, *, allow_private: bool = False) -> None:
    host = hostname.lower().rstrip(".")
    if allow_private:
        return
    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
        raise BlockedURL(f"host interno bloqueado: {hostname}")
    literal = _parse_ip(host)
    if literal is not None:
        check_ip(literal)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Recusa qualquer IP que não seja roteável publicamente."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address) and ip.sixtofour is not None:
        ip = ip.sixtofour
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise BlockedURL(f"IP não público bloqueado: {ip}")


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedURL(f"host não resolvido: {host}") from exc
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise BlockedURL(f"host não resolvido: {host}")
    return ips


class CachingResolver:
    """Cache curto de DNS na frente de outro resolver.

    Uma página com 100 recursos no mesmo host fazia 100 ``getaddrinfo`` (cada um
    num thread do executor). Guarda só a resposta crua; a verificação de IP
    continua em ``resolve_checked`` a cada uso.
    """

    def __init__(self, inner: Resolver, ttl: float = 60.0, max_entries: int = 2048) -> None:
        self.inner = inner
        self.ttl = ttl
        self.max_entries = max_entries
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}

    async def __call__(self, host: str, port: int) -> list[str]:
        key = (host.lower(), port)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
        ips = await self.inner(host, port)
        if len(self._cache) >= self.max_entries:
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            if len(self._cache) >= self.max_entries:
                self._cache.clear()
        self._cache[key] = (now + self.ttl, ips)
        return ips


async def resolve_checked(host: str, port: int, resolver: Resolver, *, allow_private: bool) -> str:
    """Resolve o host e devolve um IP para pinar a conexão.

    Todos os IPs retornados são verificados: basta um não público para bloquear.
    """
    ips = await resolver(host, port)
    if not allow_private:
        for ip_text in ips:
            ip = _parse_ip(ip_text)
            if ip is None:
                raise BlockedURL(f"resolução inválida para {host}")
            check_ip(ip)
    # Prefere IPv4 para reduzir surpresas de conectividade.
    for ip_text in ips:
        if ":" not in ip_text:
            return ip_text
    return ips[0]

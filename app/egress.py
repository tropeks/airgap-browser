"""Proxy de saída do Chromium remoto: toda conexão passa pelo guard SSRF.

O ``page.route`` do Playwright não intercepta WebSocket, e mesmo para HTTP o
Chromium resolvia o DNS por conta própria depois do guard ter checado (DNS
rebinding). Com o Chromium apontado para este proxy (``--proxy-server``), ele
não resolve nada: manda ``CONNECT host:porta`` (HTTPS, WSS, WS) ou a URL
absoluta (HTTP), e aqui o host é resolvido, verificado e a conexão é aberta
no IP verificado.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from urllib.parse import urlsplit

from .urlguard import (
    ALLOWED_PORTS,
    BlockedURL,
    CachingResolver,
    Resolver,
    check_hostname,
    resolve_checked,
    system_resolver,
)

log = logging.getLogger("safebrowse.egress")

MAX_HEAD = 64 * 1024
HEAD_TIMEOUT = 30.0
CONNECT_TIMEOUT = 10.0
CHUNK = 64 * 1024
# Cabeçalhos de salto: nunca vão para o site.
HOP_HEADERS = {b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"}


class EgressProxy:
    def __init__(self, resolver: Resolver, *, allow_private: bool = False) -> None:
        self.resolver = resolver
        self.allow_private = allow_private
        self._server: asyncio.base_events.Server | None = None
        self.url = ""

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        self._server = await asyncio.start_server(self._handle, host, port)
        port = self._server.sockets[0].getsockname()[1]
        self.url = f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"
        return self.url

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

    async def _open(self, host: str, port: int):
        if port not in ALLOWED_PORTS:
            raise BlockedURL(f"porta não permitida: {port}")
        check_hostname(host, allow_private=self.allow_private)
        ip = await resolve_checked(host, port, self.resolver, allow_private=self.allow_private)
        return await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream: asyncio.StreamWriter | None = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
                return
            if len(head) > MAX_HEAD:
                return
            lines = head[:-4].split(b"\r\n")
            try:
                method, target, version = lines[0].split(b" ", 2)
            except ValueError:
                await _reply(writer, 400)
                return
            log.debug("egress %s %s", method.decode(errors="replace"), target[:200])
            try:
                if method.upper() == b"CONNECT":
                    host, port = _split_host_port(target.decode("ascii", "strict"), 443)
                    up_reader, upstream = await self._open(host, port)
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                else:
                    parts = urlsplit(target.decode("ascii", "strict"))
                    if parts.scheme != "http" or not parts.hostname:
                        await _reply(writer, 400)
                        return
                    host, port = parts.hostname, parts.port or 80
                    up_reader, upstream = await self._open(host, port)
                    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                    out = [method + b" " + path.encode("ascii") + b" " + version]
                    for line in lines[1:]:
                        name = line.split(b":", 1)[0].strip().lower()
                        if name not in HOP_HEADERS:
                            out.append(line)
                    # Uma requisição por conexão: o próximo pedido do Chromium pode ser
                    # para outro host e precisa passar pelo guard de novo.
                    out.append(b"Connection: close")
                    upstream.write(b"\r\n".join(out) + b"\r\n\r\n")
                    await upstream.drain()
            except BlockedURL as exc:
                log.info("egress bloqueado: %s", exc)
                await _reply(writer, 403)
                return
            except (OSError, TimeoutError, UnicodeError, ValueError):
                await _reply(writer, 502)
                return
            await asyncio.gather(_pipe(reader, upstream), _pipe(up_reader, writer))
        finally:
            for w in (upstream, writer):
                if w is not None:
                    w.close()


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    parts = urlsplit("//" + target)
    if not parts.hostname:
        raise ValueError("alvo sem host")
    return parts.hostname, parts.port or default_port


async def _reply(writer: asyncio.StreamWriter, status: int) -> None:
    reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}[status]
    with contextlib.suppress(Exception):
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while data := await src.read(CHUNK):
            dst.write(data)
            await dst.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if dst.can_write_eof():
                dst.write_eof()


def parse_listen(value: str) -> tuple[str, int]:
    """``host:porta`` ou ``[v6]:porta``; host vazio vira ``0.0.0.0``."""
    host, sep, port = value.strip().rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) < 65536:
        raise ValueError(f"endereço inválido: {value!r} (use host:porta)")
    return host.strip("[]") or "0.0.0.0", int(port)


async def serve(listen: str) -> None:
    """Proxy de saída sozinho, para o contêiner ``saida`` do modo remoto com tela."""
    host, port = parse_listen(listen)
    proxy = EgressProxy(CachingResolver(system_resolver))
    log.info("proxy de saída escutando em %s", await proxy.start(host, port))
    try:
        await asyncio.Event().wait()
    finally:
        await proxy.aclose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(serve(os.environ.get("SAFEBROWSE_EGRESS_LISTEN", "0.0.0.0:3128")))

import asyncio

import httpx
import pytest

from app.egress import EgressProxy


async def _origin(handler_body: bytes = b"ok"):
    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Seen-Head: %d\r\nConnection: close\r\n\r\n"
            % (len(handler_body) + len(head), len(head))
            + handler_body
            + head
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _resolver(table):
    async def resolve(host, port):
        return table.get(host, ["93.184.216.34"])

    return resolve


async def test_http_forwarded_to_checked_ip_with_origin_form():
    server, port = await _origin()
    proxy = EgressProxy(_resolver({"a.test": ["127.0.0.1"]}), allow_private=True)
    url = await proxy.start()
    try:
        async with httpx.AsyncClient(proxy=url, trust_env=False) as c:
            r = await c.get(
                f"http://a.test:{port}/p?x=1", headers={"Proxy-Connection": "keep-alive"}
            )
        assert r.status_code == 200
        assert r.content.startswith(b"ok")
        seen = r.content[2:]
        assert seen.startswith(b"GET /p?x=1 HTTP/1.1\r\n")
        assert b"proxy-connection" not in seen.lower()
        assert b"Connection: close" in seen
    finally:
        await proxy.aclose()
        server.close()


async def test_connect_tunnel():
    server, port = await _origin()
    proxy = EgressProxy(_resolver({"a.test": ["127.0.0.1"]}), allow_private=True)
    url = await proxy.start()
    try:
        host, pport = url.removeprefix("http://").split(":")
        reader, writer = await asyncio.open_connection(host, int(pport))
        writer.write(f"CONNECT a.test:{port} HTTP/1.1\r\nHost: a.test:{port}\r\n\r\n".encode())
        await writer.drain()
        status = await reader.readuntil(b"\r\n\r\n")
        assert status.startswith(b"HTTP/1.1 200")
        writer.write(b"GET /t HTTP/1.1\r\nHost: a.test\r\n\r\n")
        await writer.drain()
        body = await reader.read()
        assert body.startswith(b"HTTP/1.1 200 OK") and b"GET /t" in body
        writer.close()
    finally:
        await proxy.aclose()
        server.close()


@pytest.mark.parametrize(
    "target",
    [
        "CONNECT evil.test:443",  # DNS aponta para rede privada
        "CONNECT rebind.test:443",  # uma das respostas é loopback
        "CONNECT 127.0.0.1:8000",  # o próprio app
        "CONNECT 169.254.169.254:80",
        "CONNECT example.com:6379",  # porta de serviço
        "GET http://localhost/",
        "GET http://10.0.0.1/",
    ],
)
async def test_blocked_targets(target):
    proxy = EgressProxy(
        _resolver({"evil.test": ["10.0.0.5"], "rebind.test": ["93.184.216.34", "127.0.0.1"]}),
        allow_private=False,
    )
    url = await proxy.start()
    try:
        host, pport = url.removeprefix("http://").split(":")
        reader, writer = await asyncio.open_connection(host, int(pport))
        writer.write(f"{target} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        await writer.drain()
        status = await reader.readuntil(b"\r\n\r\n")
        assert status.startswith(b"HTTP/1.1 403"), status
        writer.close()
    finally:
        await proxy.aclose()


async def test_https_absolute_form_refused():
    proxy = EgressProxy(_resolver({}), allow_private=False)
    url = await proxy.start()
    try:
        host, pport = url.removeprefix("http://").split(":")
        reader, writer = await asyncio.open_connection(host, int(pport))
        writer.write(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 400")
        writer.close()
    finally:
        await proxy.aclose()


async def test_listen_address_is_configurable():
    proxy = EgressProxy(_resolver({}))
    url = await proxy.start("127.0.0.1", 0)
    assert url.startswith("http://127.0.0.1:")
    await proxy.aclose()


def test_parse_listen():
    from app.egress import parse_listen

    assert parse_listen("0.0.0.0:3128") == ("0.0.0.0", 3128)
    assert parse_listen(":3128") == ("0.0.0.0", 3128)
    assert parse_listen("[::]:3128") == ("::", 3128)
    for bad in ("3128", "host:", "host:abc", "host:70000"):
        with pytest.raises(ValueError):
            parse_listen(bad)


async def test_serve_blocks_private_targets():
    import socket

    from app.egress import serve

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    task = asyncio.create_task(serve(f"127.0.0.1:{port}"))
    for _ in range(50):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            break
        except OSError:
            await asyncio.sleep(0.02)
    writer.write(b"CONNECT 10.0.0.5:443 HTTP/1.1\r\nHost: 10.0.0.5:443\r\n\r\n")
    await writer.drain()
    assert (await reader.readline()).startswith(b"HTTP/1.1 403")
    writer.close()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

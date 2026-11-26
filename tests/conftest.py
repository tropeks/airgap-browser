from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.fetcher import Fetcher
from app.main import create_app

PUBLIC_IP = "93.184.216.34"


async def fake_resolver(host: str, port: int) -> list[str]:
    table = {
        "evil.internal-dns.test": ["10.0.0.5"],
        "rebind.test": [PUBLIC_IP, "127.0.0.1"],
        "v6.test": ["2606:2800:220:1:248:1893:25c8:1946"],
    }
    return table.get(host, [PUBLIC_IP])


class FakeSite:
    """Servidor remoto simulado; roteia por Host + path."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], httpx.Response] = {}
        self.requests: list[httpx.Request] = []

    def add(
        self,
        host: str,
        path: str,
        body: bytes | str,
        content_type: str = "text/html",
        status: int = 200,
        headers: dict | None = None,
    ):
        h = {"content-type": content_type}
        h.update(headers or {})
        self.routes[(host, path)] = httpx.Response(status, content=body, headers=h)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.headers.get("host", "").split(":")[0]
        key = (
            host,
            request.url.path + (f"?{request.url.query.decode()}" if request.url.query else ""),
        )
        if key in self.routes:
            return self.routes[key]
        key = (host, request.url.path)
        if key in self.routes:
            return self.routes[key]
        return httpx.Response(404, content=b"nope", headers={"content-type": "text/plain"})


@pytest.fixture
def site() -> FakeSite:
    return FakeSite()


@pytest.fixture
def settings() -> Settings:
    return Settings(max_bytes=64 * 1024, rate_limit_per_minute=1000, max_redirects=3)


@pytest.fixture
def fetcher(site: FakeSite, settings: Settings) -> Fetcher:
    return Fetcher(settings, resolver=fake_resolver, transport=httpx.MockTransport(site.handler))


@pytest.fixture
async def client(fetcher: Fetcher, settings: Settings):
    app = create_app(settings, fetcher=fetcher)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

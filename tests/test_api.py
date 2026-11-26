import pytest

from app.main import merge_query
from app.obfuscate import encode as enc

HTML = b"""<html><head><title>Home</title><script>x</script></head>
<body><a href="/next">n</a><img src="/a.png"></body></html>"""


async def test_page_flow(client, site):
    site.add("example.com", "/", HTML)
    r = await client.get("/api/page", params={"url": "example.com"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["title"] == "Home" and data["kind"] == "html"
    assert data["report"]["removed_script"] == 1
    assert data["hints"] == ["needs_js"]  # HTML de teste quase sem texto
    v = await client.get(f"/view/{data['id']}")
    assert v.status_code == 200
    assert "sandbox allow-same-origin allow-forms" in v.headers["content-security-policy"]
    assert "frame-ancestors 'self'" in v.headers["content-security-policy"]
    assert "<script" not in v.text
    assert 'href="/?u=' + enc("https://example.com/next") + '"' in v.text
    # A URL mantém o hostname (o IP é pinado no GuardedBackend) e não vai cookie.
    req = site.requests[0]
    assert req.url.host == "example.com"
    assert req.headers["host"] == "example.com"
    assert "cookie" not in req.headers


async def test_blocked_url(client):
    r = await client.get("/api/page", params={"url": "http://127.0.0.1:8000/admin"})
    assert r.status_code == 403 and r.json()["code"] == "blocked"


async def test_dns_to_private_blocked(client, site):
    r = await client.get("/api/page", params={"url": "http://evil.internal-dns.test/"})
    assert r.status_code == 403
    assert site.requests == []


async def test_redirect_to_private_blocked(client, site):
    site.add("example.com", "/r", b"", status=302, headers={"location": "http://169.254.169.254/"})
    r = await client.get("/api/page", params={"url": "https://example.com/r"})
    assert r.status_code == 403
    assert len(site.requests) == 1


async def test_redirect_followed(client, site):
    site.add("example.com", "/old", b"", status=301, headers={"location": "/new"})
    site.add("example.com", "/new", b"<title>New</title>")
    r = await client.get("/api/page", params={"url": "https://example.com/old"})
    assert r.status_code == 200 and r.json()["url"] == "https://example.com/new"


async def test_redirect_loop(client, site):
    site.add("example.com", "/loop", b"", status=302, headers={"location": "/loop"})
    r = await client.get("/api/page", params={"url": "https://example.com/loop"})
    assert r.status_code == 502


async def test_too_large(client, site):
    site.add("example.com", "/big", b"x" * (70 * 1024))
    r = await client.get("/api/page", params={"url": "https://example.com/big"})
    assert r.status_code == 413


async def test_unsupported_type(client, site):
    site.add("example.com", "/f.pdf", b"%PDF", content_type="application/pdf")
    r = await client.get("/api/page", params={"url": "https://example.com/f.pdf"})
    assert r.status_code == 415


async def test_image_and_text_pages(client, site):
    site.add("example.com", "/i.png", b"\x89PNG", content_type="image/png")
    site.add("example.com", "/t.txt", "<b>não é html</b>", content_type="text/plain; charset=utf-8")
    r = await client.get("/api/page", params={"url": "https://example.com/i.png"})
    assert r.json()["kind"] == "image"
    v = await client.get(f"/view/{r.json()['id']}")
    assert "<img src='/asset?url=" + enc("https://example.com/i.png") + "'" in v.text
    r = await client.get("/api/page", params={"url": "https://example.com/t.txt"})
    assert r.json()["kind"] == "text"
    v = await client.get(f"/view/{r.json()['id']}")
    assert "&lt;b&gt;não é html&lt;/b&gt;" in v.text


async def test_asset_css_rewritten_and_html_refused(client, site):
    site.add("example.com", "/s.css", b"a{background:url(i.png)}", content_type="text/css")
    site.add("example.com", "/x.html", b"<script>1</script>")
    site.add("example.com", "/j.js", b"alert(1)", content_type="application/javascript")
    r = await client.get("/asset", params={"url": "https://example.com/s.css"})
    assert r.status_code == 200
    assert "/asset?url=" + enc("https://example.com/i.png") + "" in r.text
    assert r.headers["content-security-policy"].endswith("sandbox")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert (
        await client.get("/asset", params={"url": "https://example.com/x.html"})
    ).status_code == 415
    assert (
        await client.get("/asset", params={"url": "https://example.com/j.js"})
    ).status_code == 415
    assert (await client.get("/asset", params={"url": "http://10.0.0.1/x.png"})).status_code == 403


async def test_go_merges_form_fields(client):
    r = await client.get(
        "/go", params={"url": "https://example.com/search?lang=pt", "_form": "1", "q": "olá mundo"}
    )
    assert r.status_code == 303
    assert (
        r.headers["location"]
        == "/?u=" + enc("https://example.com/search?lang=pt&q=ol%C3%A1+mundo") + ""
    )


async def test_go_blocked_target(client):
    r = await client.get("/go", params={"url": "http://localhost/x", "_form": "1"})
    assert r.headers["location"] == "/"


def test_merge_query():
    assert merge_query("https://a.test/p", []) == "https://a.test/p"
    assert merge_query("https://a.test/p?x=1", [("y", "2")]) == "https://a.test/p?x=1&y=2"


async def test_index_headers(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "/static/app.js?v=" in r.text and "/static/app.css?v=" in r.text
    assert r.headers["cache-control"] == "no-store"
    v = r.text.split("/static/app.js?v=")[1].split('"')[0]
    js = await client.get(f"/static/app.js?v={v}")
    assert js.status_code == 200 and "immutable" in js.headers["cache-control"]
    assert (await client.get("/static/app.js")).headers["cache-control"] == "no-cache"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert (await client.get("/healthz")).json() == {"ok": True}


async def test_view_unknown_id(client):
    r = await client.get("/view/nope")
    assert r.status_code == 410


async def test_rate_limit(site):
    from httpx import ASGITransport, AsyncClient, MockTransport

    from app.config import Settings
    from app.fetcher import Fetcher
    from app.main import create_app
    from tests.conftest import fake_resolver

    settings = Settings(rate_limit_per_minute=2)
    fetcher = Fetcher(settings, resolver=fake_resolver, transport=MockTransport(site.handler))
    app = create_app(settings, fetcher=fetcher)
    site.add("example.com", "/", b"<p>x</p>")
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/api/page", params={"url": "example.com"})).status_code == 200
            assert (await c.get("/api/page", params={"url": "example.com"})).status_code == 200
            r = await c.get("/api/page", params={"url": "example.com"})
            assert r.status_code == 429 and r.json()["code"] == "rate_limited"


async def test_assets_do_not_consume_page_rate_limit(site):
    from httpx import ASGITransport, AsyncClient, MockTransport

    from app.config import Settings
    from app.fetcher import Fetcher
    from app.main import create_app
    from tests.conftest import fake_resolver

    settings = Settings(rate_limit_per_minute=2, asset_rate_limit_per_minute=1000)
    fetcher = Fetcher(settings, resolver=fake_resolver, transport=MockTransport(site.handler))
    app = create_app(settings, fetcher=fetcher)
    site.add("example.com", "/", b"<p>x</p>")
    site.add("example.com", "/a.png", b"\x89PNG", content_type="image/png")
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            for _ in range(20):
                r = await c.get("/asset", params={"url": "https://example.com/a.png"})
                assert r.status_code == 200
            assert (await c.get("/api/page", params={"url": "example.com"})).status_code == 200


async def test_total_timeout_on_slow_drip(site):
    import asyncio

    import httpx

    from app.config import Settings
    from app.fetcher import Fetcher, FetchError
    from tests.conftest import fake_resolver

    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.05)  # cada leitura chega antes do timeout por operação
                yield b"x"

    async def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, stream=Drip())

    settings = Settings(total_timeout_seconds=0.3)
    fetcher = Fetcher(settings, resolver=fake_resolver, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(FetchError, match="tempo total"):
            await fetcher.fetch("https://example.com/")
    finally:
        await fetcher.aclose()


class _FakeRenderer:
    def __init__(self, html: str, final_url: str = "https://example.com/app"):
        self.html, self.final_url, self.calls = html, final_url, []

    async def render(self, url):
        self.calls.append(url)
        return self.html, self.final_url, 200

    async def aclose(self):
        pass


async def test_render_mode_sanitizes_rendered_dom(site, fetcher, settings):
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    fake = _FakeRenderer(
        "<html><head><title>SPA</title></head><body><h1>montado</h1>"
        '<script>evil()</script><a href="/x" onclick="evil()">x</a></body></html>'
    )
    app = create_app(settings, fetcher=fetcher, renderer=fake)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/page", params={"url": enc("https://example.com/"), "render": "1"})
            assert r.status_code == 200, r.text
            data = r.json()
            assert data["rendered"] is True and data["url"] == "https://example.com/app"
            assert "needs_js" not in data["hints"]
            v = (await c.get(f"/view/{data['id']}")).text
    assert fake.calls == ["https://example.com/"]
    assert "montado" in v and "<script" not in v and "onclick" not in v
    assert 'href="/?u=' + enc("https://example.com/x") + '"' in v
    assert site.requests == []  # nada foi buscado pelo fetcher


async def test_render_unavailable_when_disabled(site):
    from httpx import ASGITransport, AsyncClient, MockTransport

    from app.config import Settings
    from app.fetcher import Fetcher
    from app.main import create_app
    from tests.conftest import fake_resolver

    settings = Settings(render_enabled=False)
    fetcher = Fetcher(settings, resolver=fake_resolver, transport=MockTransport(site.handler))
    app = create_app(settings, fetcher=fetcher)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/page", params={"url": "example.com", "render": "1"})
    assert r.status_code == 503 and r.json()["code"] == "render_unavailable"


def test_index_points_remote_button_to_screen_mode():
    from app.config import Settings
    from app.main import _index_html

    assert "qp-remote-screen" not in _index_html(Settings())
    html = _index_html(Settings(remote_screen_url='/remoto/"><x'))
    assert '<meta name="qp-remote-screen" content="/remoto/&quot;&gt;&lt;x">' in html

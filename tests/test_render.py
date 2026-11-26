from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

from app.config import Settings
from app.render import Renderer
from app.urlguard import BlockedURL

pytestmark = pytest.mark.remote

PAGE = b"""<!doctype html><title>SPA</title><body><div id=app></div>
<script>document.getElementById('app').innerHTML = '<h1>montado pelo JS</h1>'</script>
</body>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):  # silencioso
        pass


@pytest.fixture(scope="module")
def site_url():
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


async def test_render_returns_dom_built_by_js(site_url):
    renderer = Renderer(Settings(allow_private=True))
    try:
        html, final_url, status = await renderer.render(site_url)
    finally:
        await renderer.aclose()
    assert status == 200 and final_url == site_url
    assert "montado pelo JS" in html


async def test_render_refuses_private_target(site_url):
    renderer = Renderer(Settings())
    try:
        with pytest.raises(BlockedURL):
            await renderer.render(site_url)
    finally:
        await renderer.aclose()

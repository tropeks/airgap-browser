import base64

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
async def locked(fetcher):
    settings = Settings(rate_limit_per_minute=1000, auth_user="ana", auth_password="s3nh@:x")
    app = create_app(settings, fetcher=fetcher)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c


async def test_sem_senha_pede_login(locked):
    for path in ("/", "/api/page?url=example.com", "/asset?url=https://example.com/a.png"):
        r = await locked.get(path)
        assert r.status_code == 401, path
        assert r.headers["www-authenticate"].startswith("Basic ")


@pytest.mark.parametrize(
    "headers",
    [
        _basic("ana", "errada"),
        _basic("outro", "s3nh@:x"),
        {"Authorization": "Basic !!!nao-e-base64"},
        {"Authorization": "Bearer s3nh@:x"},
        {"Authorization": "Basic " + base64.b64encode(b"sem-dois-pontos").decode()},
    ],
)
async def test_credencial_errada(locked, headers):
    assert (await locked.get("/", headers=headers)).status_code == 401


async def test_senha_certa_entra(locked, site):
    site.add("example.com", "/", b"<title>Oi</title>")
    ok = _basic("ana", "s3nh@:x")
    assert (await locked.get("/", headers=ok)).status_code == 200
    r = await locked.get("/api/page", params={"url": "example.com"}, headers=ok)
    assert r.status_code == 200 and r.json()["title"] == "Oi"


async def test_healthz_sem_senha(locked):
    assert (await locked.get("/healthz")).status_code == 200


async def test_sem_senha_configurada_fica_aberto(client):
    assert (await client.get("/")).status_code == 200

import ipaddress

import pytest

from app.urlguard import BlockedURL, check_ip, normalize_url, resolve_checked
from tests.conftest import fake_resolver


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "https://example.com/"),
        ("http://example.com/a b?q=1", "http://example.com/a%20b?q=1"),
        ("//example.com/x#frag", "https://example.com/x"),
        ("HTTPS://Example.com:8443/p", "https://example.com:8443/p"),
    ],
)
def test_normalize_ok(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://user:pw@example.com/",
        "http://localhost/",
        "http://foo.localhost/",
        "http://metadata.google.internal/",
        "http://app.internal/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.1.2.3/",
        "http://192.168.0.1/",
        "http://172.16.5.5/",
        "http://[::ffff:127.0.0.1]/",
        "http://example.com:22/",
        "http://example.com:6379/",
        "http://0.0.0.0/",
        "http://100.64.1.1/",
    ],
)
def test_normalize_blocked(raw):
    with pytest.raises(BlockedURL):
        normalize_url(raw)


def test_check_ip_public_ok():
    check_ip(ipaddress.ip_address("93.184.216.34"))
    check_ip(ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"))


async def test_resolve_blocks_private_dns_answer():
    with pytest.raises(BlockedURL):
        await resolve_checked("evil.internal-dns.test", 80, fake_resolver, allow_private=False)


async def test_resolve_blocks_if_any_answer_is_private():
    with pytest.raises(BlockedURL):
        await resolve_checked("rebind.test", 80, fake_resolver, allow_private=False)


async def test_resolve_public():
    assert (
        await resolve_checked("example.com", 443, fake_resolver, allow_private=False)
        == "93.184.216.34"
    )


async def test_resolve_allow_private_for_dev():
    assert (
        await resolve_checked("evil.internal-dns.test", 80, fake_resolver, allow_private=True)
        == "10.0.0.5"
    )


def test_obfuscate_roundtrip():
    from app.obfuscate import decode, encode

    for url in (
        "https://example.com/",
        "https://pt.wikipedia.org/wiki/Proxy?x=1#f",
        "http://a.b/ç ão",
    ):
        token = encode(url)
        assert token.startswith("~") and "example" not in token and "wikipedia" not in token
        assert decode(token) == url
    assert decode("https://plain.test/") == "https://plain.test/"  # compatibilidade
    assert decode("~!!!") == ""


class _FakeInner:
    def __init__(self):
        self.calls = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        return "stream"

    async def sleep(self, seconds):
        pass


async def test_guarded_backend_pins_checked_ip():
    from app.fetcher import GuardedBackend
    from tests.conftest import PUBLIC_IP, fake_resolver

    inner = _FakeInner()
    backend = GuardedBackend(fake_resolver, allow_private=False, inner=inner)
    assert await backend.connect_tcp("example.com", 443) == "stream"
    assert inner.calls == [(PUBLIC_IP, 443)]


async def test_guarded_backend_blocks_private_and_rebinding():
    from app.fetcher import GuardedBackend
    from tests.conftest import fake_resolver

    inner = _FakeInner()
    backend = GuardedBackend(fake_resolver, allow_private=False, inner=inner)
    for host in ("evil.internal-dns.test", "rebind.test"):
        with pytest.raises(BlockedURL):
            await backend.connect_tcp(host, 443)
    assert inner.calls == []


async def test_caching_resolver_reuses_answer():
    from app.urlguard import CachingResolver

    calls = []

    async def inner(host, port):
        calls.append(host)
        return ["93.184.216.34"]

    resolver = CachingResolver(inner, ttl=60)
    assert await resolver("Example.com", 443) == ["93.184.216.34"]
    assert await resolver("example.com", 443) == ["93.184.216.34"]
    assert calls == ["Example.com"]

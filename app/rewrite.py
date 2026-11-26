"""Reescrita de URLs para os endpoints do proxy."""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urljoin, urlsplit

from .obfuscate import encode

SAFE_DATA_PREFIXES = (
    "data:image/",
    "data:font/",
    "data:application/font",
    "data:application/x-font",
)


@lru_cache(maxsize=4096)
def absolutize(base_url: str, raw: str) -> str | None:
    """Resolve ``raw`` contra ``base_url``; devolve None se não for http(s)."""
    raw = raw.strip().replace("\n", "").replace("\r", "").replace("\t", "")
    if not raw:
        return None
    absolute = urljoin(base_url, raw)
    scheme = urlsplit(absolute).scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    return absolute


def asset_url(base_url: str, raw: str) -> str | None:
    """URL do recurso (imagem, CSS, fonte, mídia) passando pelo proxy."""
    lowered = raw.strip().lower()
    if lowered.startswith("data:"):
        return raw.strip() if lowered.startswith(SAFE_DATA_PREFIXES) else None
    absolute = absolutize(base_url, raw)
    if absolute is None:
        return None
    return "/asset?url=" + encode(absolute)


def page_url(base_url: str, raw: str) -> str | None:
    """URL de navegação (link) que abre a página no navegador isolado."""
    absolute = absolutize(base_url, raw)
    if absolute is None:
        return None
    return "/?u=" + encode(absolute)


def rewrite_srcset(base_url: str, srcset: str) -> str:
    parts: list[str] = []
    for candidate in srcset.split(","):
        candidate = candidate.strip()
        if not candidate:
            continue
        pieces = candidate.split(None, 1)
        proxied = asset_url(base_url, pieces[0])
        if proxied is None:
            continue
        parts.append(proxied + (f" {pieces[1]}" if len(pieces) > 1 else ""))
    return ", ".join(parts)

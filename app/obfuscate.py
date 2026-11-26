"""Ofuscação das URLs de destino nos links que o SafeBrowse gera.

Não é criptografia: é só para o destino não ficar legível no histórico do
navegador, em logs de proxy/CDN e para quem olha a tela (estilo Surfola).
Formato: ``~`` + base64url(XOR(utf8(url), chave)). O mesmo algoritmo existe em
``app/static/app.js`` (``obf``).
"""

from __future__ import annotations

import base64

PREFIX = "~"
KEY = b"safebrowse-qp"


def _xor(data: bytes) -> bytes:
    # XOR de inteiros grandes: mesmo resultado do byte a byte, ~20x mais rápido
    # (uma página grande gera dezenas de milhares de links).
    n = len(data)
    stream = (KEY * (n // len(KEY) + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")


def encode(url: str) -> str:
    return PREFIX + base64.urlsafe_b64encode(_xor(url.encode("utf-8"))).decode("ascii").rstrip("=")


def decode(token: str) -> str:
    """Devolve a URL; aceita também URL em texto puro (compatibilidade)."""
    token = (token or "").strip()
    if not token.startswith(PREFIX):
        return token
    raw = token[len(PREFIX) :]
    try:
        padded = raw + "=" * (-len(raw) % 4)
        return _xor(base64.urlsafe_b64decode(padded)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""

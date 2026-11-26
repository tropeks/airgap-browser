"""Configuração via variáveis de ambiente (prefixo SAFEBROWSE_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    max_bytes: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_MAX_BYTES", 5 * 1024 * 1024)
    )
    timeout_seconds: float = field(default_factory=lambda: _env_int("SAFEBROWSE_TIMEOUT", 15))
    # Teto da requisição inteira (DNS + redirects + corpo), além do timeout por operação.
    total_timeout_seconds: float = field(
        default_factory=lambda: _env_int("SAFEBROWSE_TOTAL_TIMEOUT", 30)
    )
    max_redirects: int = field(default_factory=lambda: _env_int("SAFEBROWSE_MAX_REDIRECTS", 5))
    rate_limit_per_minute: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_RATE_LIMIT", 120)
    )
    # Recursos (/asset) têm balde próprio: uma página comum pede 100-300 recursos e
    # dividir o balde com /api/page bloqueava a navegação seguinte por até 1 minuto.
    asset_rate_limit_per_minute: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_ASSET_RATE_LIMIT", 2000)
    )
    # Sanitizações simultâneas (CPU) fora do event loop.
    sanitize_concurrency: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_SANITIZE_CONCURRENCY", 2)
    )
    # Confia em X-Forwarded-For (só ligue atrás de um reverse proxy que sobrescreve o header).
    trust_proxy: bool = field(default_factory=lambda: _env_bool("SAFEBROWSE_TRUST_PROXY", False))
    # Permite alvos em IP privado/loopback. Só para desenvolvimento e testes.
    allow_private: bool = field(
        default_factory=lambda: _env_bool("SAFEBROWSE_ALLOW_PRIVATE", False)
    )
    user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "SAFEBROWSE_USER_AGENT",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/128.0.0.0 Safari/537.36",
        )
    )
    page_cache_ttl: int = field(default_factory=lambda: _env_int("SAFEBROWSE_PAGE_TTL", 600))
    page_cache_max: int = field(default_factory=lambda: _env_int("SAFEBROWSE_PAGE_MAX", 500))
    # Modo isolado renderizado: Chromium headless executa o JS da página na VPS.
    render_enabled: bool = field(default_factory=lambda: _env_bool("SAFEBROWSE_RENDER", True))
    render_concurrency: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_RENDER_CONCURRENCY", 2)
    )
    render_timeout_seconds: int = field(
        default_factory=lambda: _env_int("SAFEBROWSE_RENDER_TIMEOUT", 20)
    )
    # Endereço do modo remoto (Chromium com tela via Selkies, ex.: "/remoto/"). Vazio
    # esconde o botão Remoto.
    remote_screen_url: str = field(
        default_factory=lambda: os.environ.get("SAFEBROWSE_REMOTE_SCREEN_URL", "").strip()
    )
    # Senha do app (HTTP Basic). Vazia: sem login próprio, o que só é seguro com a porta
    # presa em 127.0.0.1 ou atrás de algo que autentique (ex.: Cloudflare Access).
    auth_user: str = field(
        default_factory=lambda: os.environ.get("SAFEBROWSE_AUTH_USER", "qp").strip() or "qp"
    )
    auth_password: str = field(
        default_factory=lambda: os.environ.get("SAFEBROWSE_AUTH_PASSWORD", "")
    )

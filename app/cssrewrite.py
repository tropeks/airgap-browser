"""Sanitização e reescrita de CSS.

Reescreve todo ``url()``/``@import`` para passar pelo proxy e remove construções
que já foram vetor de execução de código (``expression()``, ``behavior``,
``-moz-binding``).
"""

from __future__ import annotations

import re
from collections import Counter

import tinycss2
from tinycss2 import ast

from .rewrite import asset_url

_DANGEROUS_DECLARATIONS = re.compile(
    r"(?<![\w-])(?:behavior|-moz-binding)\s*:[^;}]*;?", re.IGNORECASE
)
_URL_FUNCTIONS = {"url", "src"}
_NESTED_FUNCTIONS = {"image-set", "-webkit-image-set", "image", "cross-fade", "src"}


def rewrite_css(css: str, base_url: str, report: Counter | None = None) -> str:
    """Serve tanto para folhas de estilo quanto para o atributo ``style``."""
    report = report if report is not None else Counter()
    if _is_inert(css):
        return css
    tokens = tinycss2.parse_component_value_list(css, skip_comments=True)
    tokens = _walk(tokens, base_url, report)
    out = tinycss2.serialize(tokens)
    out, n = _DANGEROUS_DECLARATIONS.subn(" ", out)
    if n:
        report["css_dangerous"] += n
    return out


def _is_inert(css: str) -> bool:
    """CSS sem função, sem escape, sem at-rule e sem declaração perigosa.

    Sem ``(`` não existe ``url()``/``expression()``/``image-set()``; sem ``\\``
    não há como escrever um deles escapado; sem ``@`` não há ``@import "x"``.
    É o caso da maioria dos ``style=""`` e evita tokenizar cada um.
    """
    return not any(c in css for c in "(\\@") and not _DANGEROUS_DECLARATIONS.search(css)


def _proxied(raw: str, base_url: str, report: Counter) -> str:
    proxied = asset_url(base_url, raw)
    if proxied is None:
        report["css_urls_dropped"] += 1
        return "about:blank"
    report["css_urls_rewritten"] += 1
    return proxied


def _url_token(tok: ast.URLToken, base_url: str, report: Counter) -> ast.URLToken:
    value = _proxied(tok.value, base_url, report)
    return ast.URLToken(tok.source_line, tok.source_column, value, f'url("{_escape(value)}")')


def _string_token(tok: ast.StringToken, base_url: str, report: Counter) -> ast.StringToken:
    value = _proxied(tok.value, base_url, report)
    return ast.StringToken(tok.source_line, tok.source_column, value, f'"{_escape(value)}"')


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\a ")


def _walk(tokens: list, base_url: str, report: Counter) -> list:
    out: list = []
    pending_import = False
    for tok in tokens:
        if isinstance(tok, ast.AtKeywordToken):
            pending_import = tok.lower_value == "import"
            out.append(tok)
            continue
        if isinstance(tok, ast.URLToken):
            out.append(_url_token(tok, base_url, report))
            pending_import = False
            continue
        if isinstance(tok, ast.StringToken) and pending_import:
            out.append(_string_token(tok, base_url, report))
            pending_import = False
            continue
        if isinstance(tok, ast.FunctionBlock):
            name = tok.lower_name
            if name == "expression":
                report["css_dangerous"] += 1
                continue
            if name in _URL_FUNCTIONS:
                args = [
                    _string_token(a, base_url, report) if isinstance(a, ast.StringToken) else a
                    for a in tok.arguments
                ]
                out.append(ast.FunctionBlock(tok.source_line, tok.source_column, tok.name, args))
                continue
            if name in _NESTED_FUNCTIONS:
                args = [
                    _string_token(a, base_url, report) if isinstance(a, ast.StringToken) else a
                    for a in _walk(tok.arguments, base_url, report)
                ]
                out.append(ast.FunctionBlock(tok.source_line, tok.source_column, tok.name, args))
                continue
            out.append(
                ast.FunctionBlock(
                    tok.source_line,
                    tok.source_column,
                    tok.name,
                    _walk(tok.arguments, base_url, report),
                )
            )
            continue
        if isinstance(tok, (ast.ParenthesesBlock, ast.SquareBracketsBlock, ast.CurlyBracketsBlock)):
            block = type(tok)(
                tok.source_line, tok.source_column, _walk(tok.content, base_url, report)
            )
            out.append(block)
            pending_import = False
            continue
        if not isinstance(tok, ast.WhitespaceToken):
            pending_import = False
        out.append(tok)
    return out

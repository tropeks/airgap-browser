"""Sanitização de HTML: remove tudo que executa ou vaza, reescreve o resto.

O resultado é renderizado num iframe ``sandbox`` sem scripts e com CSP
``default-src 'none'``; a sanitização aqui é a segunda camada.
"""

from __future__ import annotations

import codecs
import html as htmlmod
import re
from collections import Counter
from dataclasses import dataclass, field

import lxml.html
from lxml import etree
from selectolax.lexbor import LexborHTMLParser, LexborNode

from .cssrewrite import rewrite_css
from .obfuscate import encode
from .rewrite import absolutize, asset_url, page_url, rewrite_srcset

# Elementos removidos junto com o conteúdo.
DROP_TAGS = {
    "script",
    "noscript",
    "frame",
    "frameset",
    "object",
    "embed",
    "applet",
    "base",
    "template",
    "meta",
    "param",
    "portal",
    "fencedframe",
    "math",  # MathML já teve bugs de sandbox escape; sem uso legítimo aqui.
}
# Atributos que nunca sobrevivem.
DROP_ATTRS = {
    "target",
    "ping",
    "formaction",
    "formtarget",
    "formmethod",
    "download",
    "srcdoc",
    "manifest",
    "integrity",
    "crossorigin",
    "referrerpolicy",
    "contenteditable",
    "autofocus",
    "http-equiv",
    "nonce",
    "is",
    "slot",
    "usemap",  # mapas de imagem podem apontar para hrefs não reescritos
}
NAV_ATTRS = {"href"}
RESOURCE_ATTRS = {"src", "poster", "background", "data", "lowsrc", "xlink:href"}
NAV_TAGS = {"a", "area"}
DANGEROUS_SCHEMES = ("javascript:", "vbscript:", "data:", "blob:", "file:", "about:")
KEEP_HREF_SCHEMES = ("mailto:", "tel:", "sms:")


@dataclass
class SanitizeResult:
    html: str
    title: str
    report: Counter = field(default_factory=Counter)
    hints: list[str] = field(default_factory=list)


CHALLENGE_MARKERS = (
    "cf-chl",
    "challenge-platform",
    "just a moment",
    "attention required",
    "cf-browser-verification",
    "_cf_chl_opt",
    "px-captcha",
    "captcha-delivery",
    "datadome",
    "are you a human",
    "verify you are human",
)


def detect_hints(raw: bytes, doc: etree._Element, report: Counter, status: int) -> list[str]:
    """Explica por que uma página pode ter vindo vazia ou bloqueada."""
    hints: list[str] = []
    head = raw[:20000].lower()
    if (
        status in {403, 429, 503}
        and any(m.encode() in head for m in CHALLENGE_MARKERS)
        or any(m.encode() in head for m in CHALLENGE_MARKERS[:6])
    ):
        hints.append("challenge")
    body = doc.find("body")
    text = " ".join(body.itertext() if body is not None else doc.itertext()).split()
    if report.get("removed_script", 0) > 0 and len(text) < 40:
        hints.append("needs_js")
    return hints


def sanitize_html(
    body: bytes, base_url: str, charset: str | None = None, status: int = 200
) -> SanitizeResult:
    report: Counter = Counter()
    doc = _parse(body, charset)

    base_url = _effective_base(doc, base_url)
    title = _extract_title(doc)

    for el in list(doc.iter()):
        if not _attached(el, doc):
            continue  # já removido junto com um ancestral
        _process_element(el, base_url, report)

    hints = detect_hints(body, doc, report, status)
    _inject_head(doc)
    out = lxml.html.tostring(doc, encoding="unicode", doctype="<!DOCTYPE html>", method="html")
    return SanitizeResult(html=out, title=title, report=report, hints=hints)


def _parse(body: bytes, charset: str | None) -> etree._Element:
    """Parser HTML5 (mesmo algoritmo dos navegadores) para evitar diferencial de parsing.

    O parse é do Lexbor (C, segue a especificação WHATWG); a árvore resultante é
    copiada para lxml, onde o resto do sanitizador trabalha. Comentários,
    doctype e o conteúdo de ``<template>`` ficam de fora da cópia.
    """
    try:
        source = LexborHTMLParser(decode_html(body, charset)).root
    except Exception:  # noqa: BLE001 - qualquer falha vira documento vazio
        source = None
    if source is None:
        root = lxml.html.Element("html")
        etree.SubElement(root, "head")
        etree.SubElement(root, "body")
        return root
    return _copy_tree(source)


def _copy_tree(source: LexborNode) -> etree._Element:
    root = lxml.html.Element("html")
    _copy_attrs(source, root)
    stack = [(source, root)]
    while stack:
        src, dst = stack.pop()
        last = None
        child = src.child
        while child is not None:
            if child.is_element_node:
                el = _new_child(dst, child.tag or "span")
                _copy_attrs(child, el)
                stack.append((child, el))
                last = el
            elif child.is_text_node:
                text = child.text_content or ""
                if last is None:
                    dst.text = (dst.text or "") + text
                else:
                    last.tail = (last.tail or "") + text
            child = child.next
    return root


def _new_child(parent: etree._Element, tag: str) -> etree._Element:
    try:
        return etree.SubElement(parent, tag)
    except ValueError:  # nome que o lxml não aceita (ex.: "x:y"): vira elemento neutro
        return etree.SubElement(parent, "span")


def _copy_attrs(src: LexborNode, dst: etree._Element) -> None:
    for name, value in src.attributes.items():
        if name == "xlink:href":
            name = "href"  # SVG 2 aceita href puro; o lxml não aceita o prefixo sem namespace
        try:
            dst.set(name, value or "")
        except ValueError:
            continue  # nome inválido (aspas, @, namespace): descartar é seguro


_META_CHARSET = re.compile(
    rb"""<meta[^>]+charset\s*=\s*["']?\s*([a-zA-Z0-9_.:-]+)""", re.IGNORECASE
)
_BOMS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
# Rótulos que a especificação mapeia para windows-1252.
_LATIN1_LABELS = {"iso-8859-1", "iso8859-1", "latin1", "latin-1", "us-ascii", "ascii", "l1"}


def decode_html(body: bytes, charset: str | None) -> str:
    """Decodifica como um navegador: BOM, charset do header, ``<meta>`` e fallback."""
    for bom, encoding in _BOMS:
        if body.startswith(bom):
            return body[len(bom) :].decode(encoding, errors="replace")
    candidates = [charset]
    match = _META_CHARSET.search(body[:1024])
    if match:
        candidates.append(match.group(1).decode("ascii", "ignore"))
    for label in candidates:
        encoding = _encoding(label)
        if encoding:
            return body.decode(encoding, errors="replace")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("windows-1252", errors="replace")


def _encoding(label: str | None) -> str | None:
    if not label:
        return None
    label = label.strip().lower()
    if label in _LATIN1_LABELS:
        return "windows-1252"
    try:
        name = codecs.lookup(label).name
    except LookupError:
        return None
    # utf-16 declarado em <meta> sem BOM é tratado como utf-8 pelos navegadores.
    return "utf-8" if name.startswith("utf-16") else name


def _attached(el: etree._Element, root: etree._Element) -> bool:
    node = el
    while node is not None:
        if node is root:
            return True
        node = node.getparent()
    return False


def _effective_base(doc: lxml.html.HtmlElement, base_url: str) -> str:
    for base in doc.iter("base"):
        href = base.get("href")
        if href:
            resolved = absolutize(base_url, href)
            if resolved:
                return resolved
        break
    return base_url


def _extract_title(doc: lxml.html.HtmlElement) -> str:
    node = doc.find(".//title")
    if node is not None and node.text:
        return " ".join(node.text.split())[:300]
    return ""


def _tag_name(el: lxml.html.HtmlElement) -> str:
    tag = el.tag
    if not isinstance(tag, str):
        return ""
    if "}" in tag:  # namespace (svg etc.)
        tag = tag.rsplit("}", 1)[1]
    return tag.lower()


def _process_element(el: etree._Element, base_url: str, report: Counter) -> None:
    tag = _tag_name(el)
    if not tag:
        # Comentários/PIs residuais.
        _drop(el)
        return

    if tag in DROP_TAGS:
        report[f"removed_{tag}"] += 1
        _drop(el)
        return

    if tag == "iframe":
        report["removed_iframe"] += 1
        _replace_with_frame_placeholder(el, base_url)
        return

    if tag == "link":
        _process_link(el, base_url, report)
        return

    if tag == "style":
        css = "".join(el.itertext())
        for child in list(el):
            el.remove(child)
        el.text = rewrite_css(css, base_url, report)
        _clean_attrs(el, base_url, report)
        return

    if tag == "form":
        _process_form(el, base_url, report)
        if el.tag == "div":
            _clean_attrs(el, base_url, report)
            return

    if tag == "html":
        el.attrib.pop("manifest", None)

    _clean_attrs(el, base_url, report)


def _drop(el: lxml.html.HtmlElement) -> None:
    parent = el.getparent()
    if parent is None:
        return
    # drop_tree preserva o tail (texto após o elemento).
    if el.tail:
        prev = el.getprevious()
        if prev is not None:
            prev.tail = (prev.tail or "") + el.tail
        else:
            parent.text = (parent.text or "") + el.tail
    parent.remove(el)


def _replace_with_frame_placeholder(el: lxml.html.HtmlElement, base_url: str) -> None:
    src = el.get("src", "")
    target = absolutize(base_url, src) if src else None
    box = lxml.html.Element("div")
    box.set("class", "safebrowse-blocked-frame")
    box.set(
        "style",
        "border:1px dashed #999;padding:8px;margin:4px 0;font:12px system-ui;"
        "color:#555;background:#f6f6f6",
    )
    box.text = "frame bloqueado"
    if target:
        link = lxml.html.Element("a")
        link.set("href", page_url(base_url, target) or "#")
        link.set("target", "_top")
        link.text = target[:120]
        box.text += ": "
        box.append(link)
    box.tail = el.tail
    parent = el.getparent()
    if parent is not None:
        parent.replace(el, box)


def _process_link(el: lxml.html.HtmlElement, base_url: str, report: Counter) -> None:
    rels = {r.lower() for r in (el.get("rel") or "").split()}
    href = el.get("href")
    if not href:
        _drop(el)
        return
    if "stylesheet" in rels:
        proxied = asset_url(base_url, href)
        if proxied is None:
            report["removed_link"] += 1
            _drop(el)
            return
        for attr in list(el.attrib):
            if attr not in {"rel", "href", "media", "type", "title"}:
                del el.attrib[attr]
        el.set("rel", "stylesheet")
        el.set("href", proxied)
        report["stylesheets_proxied"] += 1
        return
    if rels & {"icon", "shortcut", "apple-touch-icon"}:
        proxied = asset_url(base_url, href)
        if proxied is None:
            _drop(el)
            return
        for attr in list(el.attrib):
            if attr not in {"rel", "href", "sizes", "type"}:
                del el.attrib[attr]
        el.set("href", proxied)
        return
    # preload, prefetch, dns-prefetch, preconnect, manifest, alternate, canonical...
    report["removed_link"] += 1
    _drop(el)


def _process_form(el: lxml.html.HtmlElement, base_url: str, report: Counter) -> None:
    method = (el.get("method") or "get").lower()
    action = el.get("action") or base_url
    target = absolutize(base_url, action)
    if method != "get" or target is None:
        # Sem POST: o sandbox não deixa passar e não queremos encaminhar corpo.
        report["forms_blocked"] += 1
        el.tag = "div"
        el.set("class", ((el.get("class") or "") + " safebrowse-form-blocked").strip())
        for attr in ("action", "method", "enctype", "accept-charset", "novalidate"):
            el.attrib.pop(attr, None)
        for control in el.iter("input", "button", "select", "textarea"):
            control.set("disabled", "disabled")
        return
    report["forms_rewritten"] += 1
    for attr in ("enctype", "accept-charset"):
        el.attrib.pop(attr, None)
    el.set("method", "get")
    el.set("action", "/go")
    hidden = lxml.html.Element("input")
    hidden.set("type", "hidden")
    hidden.set("name", "url")
    hidden.set("value", encode(target))
    el.insert(0, hidden)
    flag = lxml.html.Element("input")
    flag.set("type", "hidden")
    flag.set("name", "_form")
    flag.set("value", "1")
    el.insert(1, flag)


def _clean_attrs(el: lxml.html.HtmlElement, base_url: str, report: Counter) -> None:
    tag = _tag_name(el)
    for name in list(el.attrib):
        lname = name.lower()
        value = el.attrib[name]
        if lname.startswith("on"):
            report["removed_handlers"] += 1
            del el.attrib[name]
            continue
        if lname in DROP_ATTRS:
            del el.attrib[name]
            continue
        if lname == "style":
            el.attrib[name] = rewrite_css(value, base_url, report)
            continue
        if lname == "srcset" or (lname == "imagesrcset"):
            el.attrib[name] = rewrite_srcset(base_url, value)
            continue
        if lname == "action" and tag != "form":
            del el.attrib[name]
            continue
        if lname in NAV_ATTRS and tag in NAV_TAGS:
            _rewrite_nav_href(el, name, value, base_url, report)
            continue
        if lname in NAV_ATTRS and tag == "form":
            continue
        stripped = value.strip().lower()
        if lname in RESOURCE_ATTRS or lname in NAV_ATTRS or lname.endswith((":href", "}href")):
            if lname == "href" and tag == "link":
                continue  # já tratado
            proxied = asset_url(base_url, value)
            if proxied is None:
                report["removed_resources"] += 1
                del el.attrib[name]
            else:
                el.attrib[name] = proxied
                report["resources_proxied"] += 1
            continue
        if stripped.startswith(DANGEROUS_SCHEMES):
            report["removed_dangerous_attrs"] += 1
            del el.attrib[name]
    if tag in NAV_TAGS and "href" in el.attrib and not el.get("href", "").startswith("#"):
        el.set("target", "_top")


def _rewrite_nav_href(
    el: lxml.html.HtmlElement, name: str, value: str, base_url: str, report: Counter
) -> None:
    stripped = value.strip()
    lowered = stripped.lower()
    if stripped.startswith("#"):
        return
    if lowered.startswith(KEEP_HREF_SCHEMES):
        return
    if lowered.startswith(DANGEROUS_SCHEMES):
        report["removed_dangerous_attrs"] += 1
        del el.attrib[name]
        return
    proxied = page_url(base_url, stripped)
    if proxied is None:
        report["removed_dangerous_attrs"] += 1
        del el.attrib[name]
        return
    el.attrib[name] = proxied
    report["links_rewritten"] += 1


def _inject_head(doc: lxml.html.HtmlElement) -> None:
    head = doc.find("head")
    if head is None:
        head = lxml.html.Element("head")
        doc.insert(0, head)
    charset = lxml.html.Element("meta")
    charset.set("charset", "utf-8")
    referrer = lxml.html.Element("meta")
    referrer.set("name", "referrer")
    referrer.set("content", "no-referrer")
    csp = lxml.html.Element("meta")
    csp.set("http-equiv", "Content-Security-Policy")
    csp.set("content", FRAME_CSP_META)
    head.insert(0, csp)
    head.insert(0, referrer)
    head.insert(0, charset)


# CSP aplicada às páginas dentro do frame (header e meta). ``sandbox`` e
# ``frame-ancestors`` só valem no header; ficam em FRAME_CSP_HEADER.
# ``allow-same-origin`` é necessário: sem ele o frame tem origem opaca e o browser
# trata /view e /asset como terceiros — cookies de autenticação na frente do app
# (Cloudflare Access) não são enviados e nada carrega. Scripts continuam
# bloqueados por três camadas: sanitizador, ``script-src 'none'`` e sandbox
# sem ``allow-scripts``.
FRAME_CSP_META = (
    "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; media-src 'self'; form-action 'self'; base-uri 'none'; "
    "object-src 'none'; script-src 'none'; connect-src 'none'"
)
FRAME_CSP_HEADER = (
    FRAME_CSP_META + "; frame-ancestors 'self'; sandbox allow-same-origin allow-forms "
    "allow-top-navigation-by-user-activation"
)


def wrap_image(asset_src: str, source_url: str) -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<meta http-equiv='Content-Security-Policy' content=\"{FRAME_CSP_META}\">"
        "<style>body{margin:0;background:#111;display:grid;place-items:center;min-height:100vh}"
        "img{max-width:100%;height:auto}</style></head><body>"
        f"<img src='{htmlmod.escape(asset_src)}' alt='{htmlmod.escape(source_url)}'></body></html>"
    )


def wrap_text(text: str) -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<meta http-equiv='Content-Security-Policy' content=\"{FRAME_CSP_META}\">"
        "<style>body{margin:16px;font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap;"
        "word-break:break-word}</style></head><body>"
        f"{htmlmod.escape(text)}</body></html>"
    )


def browse_link(url: str) -> str:
    return "/?u=" + encode(url)

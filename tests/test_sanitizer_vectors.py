"""Vetores conhecidos de XSS/mXSS: a saída, re-parseada como um navegador faria, não executa nada."""

import pytest
from selectolax.lexbor import LexborHTMLParser

from app.sanitizer import decode_html, sanitize_html

VECTORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>',
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
    '<a href="javascript:alert(1)">x</a>',
    '<a href="  JaVaScRiPt:alert(1)">x</a>',
    '<a href="java&#x09;script:alert(1)">x</a>',
    '<a href="&#106;avascript:alert(1)">x</a>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<object data="javascript:alert(1)"></object>',
    '<embed src="javascript:alert(1)">',
    '<base href="javascript:/"><a href="x">x</a>',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<div style="background:url(javascript:alert(1))">x</div>',
    '<div style="width:expression(alert(1))">x</div>',
    "<style>@import 'javascript:alert(1)';</style>",
    '<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>',
    "<svg><animate attributeName=href to=javascript:alert(1) /></svg>",
    "<svg><set attributeName=onload to=alert(1) /></svg>",
    "<template><script>alert(1)</script></template>",
    "<textarea></textarea><script>alert(1)</script>",
    "<title></title><script>alert(1)</script>",
    "<xmp><script>alert(1)</script></xmp>",
    "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
    "<!--><script>alert(1)</script>-->",
    "<![CDATA[><script>alert(1)</script>]]>",
    '<img src="x" srcset="javascript:alert(1) 1x">',
    '<form action="javascript:alert(1)"><button>x</button></form>',
    '<button formaction="javascript:alert(1)">x</button>',
    "<input type=image src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)></video>",
    "<body onload=alert(1)>",
    "<isindex action=javascript:alert(1) type=image>",
    '<a href="data:text/html,<script>alert(1)</script>">x</a>',
    '<link rel=import href="data:text/html,<script>alert(1)</script>">',
    '<p a"b=1 @click="alert(1)" x:onload="alert(1)">x</p>',
    "<x:script>alert(1)</x:script>",
    "<select><style></select><img src=x onerror=alert(1)></style>",
    "<table><td><style></table><img src=x onerror=alert(1)></style>",
]

RISKY_TAGS = {
    "script",
    "iframe",
    "object",
    "embed",
    "frame",
    "frameset",
    "base",
    "meta",
    "template",
    "math",
    "portal",
}


def _assert_inert(html: str) -> None:
    doc = LexborHTMLParser(html)
    for node in doc.root.traverse():
        tag = (node.tag or "").lower()
        assert tag not in RISKY_TAGS or (tag == "meta" and node.parent.tag == "head"), html
        for name, value in node.attributes.items():
            lname = name.lower()
            assert not lname.startswith("on"), (name, html)
            v = "".join((value or "").split()).lower()
            assert not v.startswith(("javascript:", "vbscript:", "data:text")), (name, value)
            assert "expression(" not in v
    for meta in doc.css("meta"):
        assert meta.attributes.get("http-equiv") in (None, "Content-Security-Policy")


@pytest.mark.parametrize("vector", VECTORS)
def test_vector_is_inert(vector):
    r = sanitize_html(vector.encode(), "https://ex.com/")
    _assert_inert(r.html)
    # Idempotência: sanitizar de novo a própria saída não muda a conclusão.
    _assert_inert(sanitize_html(r.html.encode(), "https://ex.com/").html)


@pytest.mark.parametrize(
    ("body", "charset", "expected"),
    [
        ("<p>ação</p>".encode(), "utf-8", "ação"),
        ("<p>ação</p>".encode("cp1252"), "iso-8859-1", "ação"),
        ('<meta charset="windows-1252"><p>ação</p>'.encode("cp1252"), None, "ação"),
        ("<p>ação</p>".encode("cp1252"), None, "ação"),  # não é utf-8 válido: cai em 1252
        ("﻿<p>ação</p>".encode(), "windows-1252", "ação"),  # BOM vence o header
    ],
)
def test_decode_html(body, charset, expected):
    assert expected in decode_html(body, charset)

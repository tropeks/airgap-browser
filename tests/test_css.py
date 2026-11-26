from collections import Counter

from app.cssrewrite import rewrite_css
from app.obfuscate import encode as enc

BASE = "https://s.test/css/main.css"


def test_urls_rewritten():
    out = rewrite_css("a{background:url(../img/a.png) url( 'b.png' ) url(\"c.png\")}", BASE)
    assert out.count("/asset?url=") == 3
    assert enc("https://s.test/img/a.png") in out


def test_import_forms():
    out = rewrite_css("@import 'x.css'; @import url(y.css) screen; @import url(\"z.css\");", BASE)
    assert out.count("/asset?url=") == 3
    assert enc("https://s.test/css/x.css") in out


def test_image_set_and_font_face():
    out = rewrite_css(
        "@font-face{src:url(f.woff2) format('woff2')} a{background:image-set('1.png' 1x, '2.png' 2x)}",
        BASE,
    )
    assert "f.woff2" not in out.replace("%2F", "/").split("format")[0] or "/asset?url=" in out
    assert out.count("/asset?url=") == 3
    assert 'format("woff2")' in out or "format('woff2')" in out


def test_dangerous_removed():
    rep = Counter()
    out = rewrite_css(
        "a{width:expression(alert(1));behavior:url(x.htc);-moz-binding:url(y.xml);color:red}",
        BASE,
        rep,
    )
    assert "expression" not in out
    assert "behavior" not in out and "-moz-binding" not in out
    assert "color:red" in out
    assert rep["css_dangerous"] >= 3


def test_data_and_javascript_urls():
    out = rewrite_css(
        "a{background:url(data:image/png;base64,AA)} b{background:url(javascript:1)}", BASE
    )
    assert "data:image/png;base64,AA" in out
    assert "javascript" not in out
    assert "about:blank" in out


def test_inert_style_kept_and_escaped_url_still_rewritten():
    assert (
        rewrite_css("color: red; margin: 0 auto", "https://ex.com/") == "color: red; margin: 0 auto"
    )
    out = rewrite_css("background: u\\72l(/x.png)", "https://ex.com/")
    assert "/asset?url=" + enc("https://ex.com/x.png") in out
    out = rewrite_css("behavior: x", "https://ex.com/")
    assert "behavior" not in out

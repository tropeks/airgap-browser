from app.obfuscate import encode as enc
from app.sanitizer import sanitize_html

BASE = "https://site.test/dir/page.html"


def san(html: str, base: str = BASE):
    return sanitize_html(html.encode(), base, "utf-8")


def asset(url: str) -> str:
    return "/asset?url=" + enc(url)


def page(url: str) -> str:
    return "/?u=" + enc(url)


def test_scripts_and_handlers_removed():
    r = san(
        '<html><head><script>alert(1)</script></head><body onload="x()">'
        "<p onclick='y()'>hi</p><noscript><img src=/t.gif></noscript></body></html>"
    )
    assert "<script" not in r.html
    assert "onload" not in r.html and "onclick" not in r.html
    assert "t.gif" not in r.html
    assert r.report["removed_script"] == 1
    assert r.report["removed_handlers"] == 2


def test_links_rewritten_to_browser():
    r = san('<a href="../other?x=1">o</a><a href="#top">t</a><a href="mailto:a@b.c">m</a>')
    assert f'href="{page("https://site.test/other?x=1")}"' in r.html
    assert 'target="_top"' in r.html
    assert 'href="#top"' in r.html
    assert 'href="mailto:a@b.c"' in r.html
    # destino não aparece em texto puro no link gerado
    assert "site.test/other" not in r.html


def test_javascript_href_removed():
    r = san('<a href="javascript:alert(1)">x</a><a href=" JaVaScRiPt:1">y</a>')
    assert "javascript" not in r.html.lower()
    assert r.report["removed_dangerous_attrs"] == 2


def test_resources_proxied():
    r = san(
        '<img src="/img/a.png" srcset="/a.png 1x, /b.png 2x"><video poster="p.jpg"><source src="v.mp4"></video>'
    )
    assert f'src="{asset("https://site.test/img/a.png")}"' in r.html
    assert f"{asset('https://site.test/a.png')} 1x, {asset('https://site.test/b.png')} 2x" in r.html
    assert f'poster="{asset("https://site.test/dir/p.jpg")}"' in r.html
    assert f'src="{asset("https://site.test/dir/v.mp4")}"' in r.html


def test_data_image_allowed_but_data_html_not():
    r = san('<img src="data:image/png;base64,AAAA"><img src="data:text/html,<script>1</script>">')
    assert 'src="data:image/png;base64,AAAA"' in r.html
    assert "data:text/html" not in r.html


def test_iframe_becomes_placeholder():
    r = san('<iframe src="https://ads.test/x"></iframe>')
    assert "<iframe" not in r.html
    assert "frame bloqueado" in r.html
    assert f'href="{page("https://ads.test/x")}"' in r.html


def test_dangerous_tags_removed():
    r = san(
        "<object data='x.swf'></object><embed src='x'><base href='https://evil.test/'>"
        "<meta http-equiv='refresh' content='0;url=https://evil.test'>"
        "<link rel=preload href=x.js as=script><link rel=stylesheet href=s.css>"
        "<template><script>1</script></template>"
    )
    for tag in ("<object", "<embed", "<base", 'http-equiv="refresh"', "<template", "preload"):
        assert tag not in r.html
    # base href honrado na resolução
    assert f'href="{asset("https://evil.test/s.css")}"' in r.html


def test_get_form_rewritten_post_form_blocked():
    r = san(
        '<form action="/search" method="get"><input name="q"><button>go</button></form>'
        '<form action="/login" method="post"><input name="p"><button>go</button></form>'
    )
    assert 'action="/go"' in r.html
    assert f'name="url" value="{enc("https://site.test/search")}"' in r.html
    assert 'name="_form" value="1"' in r.html
    assert "/login" not in r.html
    assert '<input name="p" disabled>' in r.html
    assert r.report["forms_rewritten"] == 1 and r.report["forms_blocked"] == 1


def test_inline_style_and_style_tag_rewritten():
    r = san(
        "<style>body{background:url(bg.png)} @import 'x.css';</style>"
        "<div style=\"background-image:url('/i.png');behavior:url(#default#time2)\">a</div>"
    )
    assert f'url("{asset("https://site.test/dir/bg.png")}")' in r.html
    assert f'@import "{asset("https://site.test/dir/x.css")}"' in r.html
    assert asset("https://site.test/i.png") in r.html
    assert "behavior" not in r.html


def test_head_injection_and_title():
    r = san("<html><head><title>  Olá   mundo </title></head><body></body></html>")
    assert r.title == "Olá mundo"
    assert r.html.startswith("<!DOCTYPE html>")
    assert '<meta charset="utf-8">' in r.html
    assert 'http-equiv="Content-Security-Policy"' in r.html
    assert 'content="no-referrer"' in r.html


def test_garbage_input_does_not_crash():
    r = sanitize_html(b"\x00\xff\xfe<<<>>>", BASE, None)
    assert "<html" in r.html
    r = sanitize_html(b"", BASE, None)
    assert "<html" in r.html


def test_svg_use_and_xlink_href():
    r = san('<svg><use xlink:href="sprite.svg#i"/><a href="javascript:1"><text>t</text></a></svg>')
    assert "javascript" not in r.html
    assert asset("https://site.test/dir/sprite.svg#i") in r.html


def test_comments_removed():
    r = san("<!--[if IE]><script>1</script><![endif]--><p>x</p>")
    assert "<script" not in r.html and "<!--" not in r.html


def test_hints_challenge_and_needs_js():
    r = sanitize_html(
        b"<html><head><title>Just a moment...</title>"
        b"<script src='/cdn-cgi/challenge-platform/x.js'></script></head><body></body></html>",
        BASE,
        "utf-8",
        status=403,
    )
    assert "challenge" in r.hints and "needs_js" in r.hints
    r = san("<p>" + "texto " * 100 + "</p><script>1</script>")
    assert r.hints == []

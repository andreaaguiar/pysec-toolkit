from bs4 import BeautifulSoup

from pysec import web_vuln_scanner

MARKER = "pysecXSS31337"
Scanner = web_vuln_scanner.WebVulnScanner


def parse_first_form(scanner, html, page_url):
    form = BeautifulSoup(html, "html.parser").find("form")
    return scanner._parse_form(form, page_url)


def test_base_url_derivation():
    scanner = Scanner("https://example.com/path?a=1")
    assert scanner.base_url == "https://example.com"


def test_base_url_adds_scheme_when_missing():
    scanner = Scanner("example.com")
    assert scanner.base_url == "https://example.com"
    assert scanner.target_url == "https://example.com"


def test_cookie_file_parsing(tmp_path):
    cookie_file = tmp_path / "cookies.txt"
    cookie_file.write_text("session=abc; token=xyz")
    scanner = Scanner("https://example.com", cookies=str(cookie_file))
    assert scanner.cookies == {"session": "abc", "token": "xyz"}


def test_reflects_as_markup_script_element():
    html = "<html><body><script>" + MARKER + "</script></body></html>"
    assert Scanner._reflects_as_markup(html, MARKER)


def test_reflects_as_markup_event_handler():
    html = "<img src=x onerror=" + MARKER + ">"
    assert Scanner._reflects_as_markup(html, MARKER)


def test_encoded_reflection_is_not_flagged():
    html = "prefix &lt;script&gt;" + MARKER + "&lt;/script&gt; suffix"
    assert not Scanner._reflects_as_markup(html, MARKER)


def test_attribute_value_reflection_is_not_flagged():
    html = '<input value="<script>' + MARKER + '</script>">'
    assert not Scanner._reflects_as_markup(html, MARKER)


def test_response_sql_error_detects_and_clears():
    assert Scanner._response_sql_error("... SQL syntax near ...") == "SQL syntax"
    assert Scanner._response_sql_error("all good here") is None


def test_parse_form_get_with_relative_action():
    scanner = Scanner("https://example.com")
    html = '<form action="/search" method="get"><input name="q"><input name="lang" value="en"></form>'
    form = parse_first_form(scanner, html, "https://example.com/page")
    assert form == {
        "action": "https://example.com/search",
        "method": "get",
        "fields": {"q": "test", "lang": "en"},
    }


def test_parse_form_post_defaults_action_to_page():
    scanner = Scanner("https://example.com")
    html = '<form method="POST"><textarea name="comment"></textarea></form>'
    form = parse_first_form(scanner, html, "https://example.com/post")
    assert form["method"] == "post"
    assert form["action"] == "https://example.com/post"
    assert form["fields"] == {"comment": "test"}


def test_parse_form_skips_external_action():
    scanner = Scanner("https://example.com")
    html = '<form action="https://evil.example.net/x"><input name="q"></form>'
    assert parse_first_form(scanner, html, "https://example.com/page") is None


def test_parse_form_skips_form_without_named_fields():
    scanner = Scanner("https://example.com")
    html = '<form action="/x"><input type="submit"></form>'
    assert parse_first_form(scanner, html, "https://example.com/page") is None

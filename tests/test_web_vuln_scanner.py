import web_vuln_scanner

MARKER = "pysecXSS31337"
Scanner = web_vuln_scanner.WebVulnScanner


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

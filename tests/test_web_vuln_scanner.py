from bs4 import BeautifulSoup

from pysec import web_vuln_scanner
from pysec.web_vuln_scanner import load_payloads

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
    errors = ["SQL syntax", "ORA-01756"]
    assert Scanner._response_sql_error("... SQL syntax near ...", errors) == "SQL syntax"
    assert Scanner._response_sql_error("all good here", errors) is None


def test_redirect_targets_host_matches_payload_forms():
    assert Scanner._redirect_targets_host("//example.com", "example.com")
    assert Scanner._redirect_targets_host("https://example.com", "example.com")
    assert Scanner._redirect_targets_host("http://example.com/path?q=1", "example.com")
    assert Scanner._redirect_targets_host("HTTPS://EXAMPLE.COM", "example.com")


def test_redirect_targets_host_rejects_substring_lookalikes():
    assert not Scanner._redirect_targets_host("https://example.com.evil.test", "example.com")
    assert not Scanner._redirect_targets_host("https://evil.test/example.com", "example.com")
    assert not Scanner._redirect_targets_host("https://notexample.com", "example.com")
    assert not Scanner._redirect_targets_host("/local/path", "example.com")
    assert not Scanner._redirect_targets_host("", "example.com")


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


def test_default_payloads_match_previous_inline_sets():
    scanner = Scanner("https://example.com")
    assert scanner.sql_payloads == ["'", "' OR '1'='1", "1' OR '1'='1' --", "' UNION SELECT 1,2,3,4 --"]
    assert scanner.xss_payloads == [
        "<script>pysecXSS31337</script>",
        '"><img src=x onerror=pysecXSS31337>',
        "'><svg onload=pysecXSS31337>",
    ]
    assert scanner.open_redirect_payloads == ["//example.com", "https://example.com", "http://example.com"]
    assert "SQL syntax" in scanner.sql_errors


def test_marker_and_host_are_substituted():
    scanner = Scanner("https://example.com")
    assert all(scanner.XSS_MARKER in p for p in scanner.xss_payloads)
    assert all("__MARKER__" not in p for p in scanner.xss_payloads)
    assert all(scanner.OPEN_REDIRECT_HOST in p for p in scanner.open_redirect_payloads)
    assert all("__HOST__" not in p for p in scanner.open_redirect_payloads)


def test_payloads_dir_overrides_and_falls_back(tmp_path):
    (tmp_path / "sqli_payloads.txt").write_text("' OR sleep(5) --\n' AND 1=1 --\n")
    scanner = Scanner("https://example.com", payloads_dir=str(tmp_path))
    assert scanner.sql_payloads == ["' OR sleep(5) --", "' AND 1=1 --"]
    assert scanner.xss_payloads == [
        "<script>pysecXSS31337</script>",
        '"><img src=x onerror=pysecXSS31337>',
        "'><svg onload=pysecXSS31337>",
    ]


def test_load_payloads_skips_blank_and_comment_lines(tmp_path):
    payload_file = tmp_path / "sqli_payloads.txt"
    payload_file.write_text("# a comment\n\n' OR 1=1 --\n   \n# another\nUNION SELECT NULL\n")
    entries = load_payloads("sqli_payloads.txt", payloads_dir=str(tmp_path))
    assert entries == ["' OR 1=1 --", "UNION SELECT NULL"]


def test_time_payloads_substitute_delay():
    scanner = Scanner("https://example.com")
    assert scanner.sqli_time_payloads
    assert all("__DELAY__" not in p for p in scanner.sqli_time_payloads)
    assert any("SLEEP(5)" in p for p in scanner.sqli_time_payloads)

    custom = Scanner("https://example.com", sqli_delay=7)
    assert any("SLEEP(7)" in p for p in custom.sqli_time_payloads)


def test_time_threshold_scales_with_delay():
    assert Scanner("https://example.com", sqli_delay=5)._time_threshold() == 3.0
    assert Scanner("https://example.com", sqli_delay=10)._time_threshold() == 8.0
    assert Scanner("https://example.com", sqli_delay=2)._time_threshold() == 1.0


def test_time_confirms_injection_flags_consistent_delay():
    assert Scanner._time_confirms_injection(baseline=0.2, elapsed=5.1, confirm=5.0, threshold=3.0)


def test_time_confirms_injection_ignores_slow_but_uninjected_page():
    assert not Scanner._time_confirms_injection(baseline=4.0, elapsed=4.2, confirm=4.2, threshold=3.0)


def test_time_confirms_injection_requires_confirmation():
    assert not Scanner._time_confirms_injection(baseline=0.2, elapsed=5.0, confirm=0.3, threshold=3.0)
    assert not Scanner._time_confirms_injection(baseline=0.2, elapsed=5.0, confirm=None, threshold=3.0)


def test_time_confirms_injection_handles_missing_timing():
    assert not Scanner._time_confirms_injection(baseline=None, elapsed=5.0, confirm=5.0, threshold=3.0)
    assert not Scanner._time_confirms_injection(baseline=0.2, elapsed=None, confirm=5.0, threshold=3.0)


def test_check_sql_time_flags_delayed_parameter(monkeypatch):
    scanner = Scanner("https://example.com")

    def fake_timed(url, params=None, data=None, post=False):
        value = (params or {}).get("id", "")
        if any(marker in value for marker in ("SLEEP", "pg_sleep", "WAITFOR")):
            return 5.2
        return 0.1

    monkeypatch.setattr(scanner, "_timed_request", fake_timed)
    scanner._check_sql_time("https://example.com/item?id=1")

    assert scanner.results["sqli"]
    hit = scanner.results["sqli"][0]
    assert hit["parameter"] == "id"
    assert "Time-based" in hit["details"]


def test_check_sql_time_ignores_fast_responses(monkeypatch):
    scanner = Scanner("https://example.com")
    monkeypatch.setattr(scanner, "_timed_request", lambda *a, **k: 0.1)
    scanner._check_sql_time("https://example.com/item?id=1")
    assert scanner.results["sqli"] == []

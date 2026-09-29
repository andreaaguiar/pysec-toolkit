import requests

from pysec import directory_enumeration


class FakeResponse:
    def __init__(self, status_code, text="", content=b""):
        self.status_code = status_code
        self.text = text
        self.content = content


def test_make_request_returns_result_for_non_404(monkeypatch):
    def fake_get(url, **kwargs):
        return FakeResponse(200, text="<title>Admin</title>", content=b"body")

    monkeypatch.setattr(directory_enumeration.requests, "get", fake_get)

    result = directory_enumeration.make_request("http://example.com/admin", 3, {})
    assert result["status_code"] == 200
    assert result["url"] == "http://example.com/admin"
    assert result["content_length"] == 4
    assert result["title"] == "Admin"


def test_make_request_skips_404(monkeypatch):
    monkeypatch.setattr(directory_enumeration.requests, "get", lambda url, **kw: FakeResponse(404))
    assert directory_enumeration.make_request("http://example.com/missing", 3, {}) is None


def test_make_request_handles_connection_error(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.ConnectionError

    monkeypatch.setattr(directory_enumeration.requests, "get", fake_get)
    assert directory_enumeration.make_request("http://example.com/x", 3, {}) is None


def test_check_directory_builds_urls_per_extension(monkeypatch):
    seen = []

    def fake_make_request(url, timeout, headers):
        seen.append(url)
        return None

    monkeypatch.setattr(directory_enumeration, "make_request", fake_make_request)

    directory_enumeration.check_directory(
        "example.com", "admin", 3, "http", [".php", ""], {}
    )

    assert "http://example.com/admin" in seen
    assert "http://example.com/admin.php" in seen

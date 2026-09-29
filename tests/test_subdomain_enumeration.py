import requests

from pysec import subdomain_enumeration


class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


def test_check_domain_valid(monkeypatch):
    def fake_get(url, **kwargs):
        return FakeResponse(200, text="<title>Blog</title>")

    monkeypatch.setattr(subdomain_enumeration.requests, "get", fake_get)

    result = subdomain_enumeration.check_domain("blog", "example.com", 5, "http")
    assert result["valid"] is True
    assert result["url"] == "http://blog.example.com"
    assert result["status_code"] == 200
    assert result["title"] == "Blog"


def test_check_domain_connection_error(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.ConnectionError

    monkeypatch.setattr(subdomain_enumeration.requests, "get", fake_get)

    result = subdomain_enumeration.check_domain("missing", "example.com", 5, "http")
    assert result["valid"] is False


def test_check_domain_timeout_records_error(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.Timeout

    monkeypatch.setattr(subdomain_enumeration.requests, "get", fake_get)

    result = subdomain_enumeration.check_domain("slow", "example.com", 5, "http")
    assert result["valid"] is False
    assert result["error"] == "Timeout"

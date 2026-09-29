import json
from types import SimpleNamespace

from pysec import port_scanner


def test_parse_ports_range():
    assert port_scanner.parse_ports("1-1000") == (1, 1000)


def test_parse_ports_single():
    assert port_scanner.parse_ports("80") == (80, 80)


def test_parse_ports_full():
    assert port_scanner.parse_ports("1-65535") == (1, 65535)


def test_run_writes_json_and_html_report(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scanner, "probe_port", lambda ip, port, timeout: port in (22, 80))
    report_path = tmp_path / "ports.json"
    args = SimpleNamespace(
        target="10.0.0.1",
        ports="1-100",
        threads=10,
        timeout=0.1,
        verbose=False,
        report=str(report_path),
        report_format="both",
    )
    port_scanner.run(args)

    data = json.loads((tmp_path / "ports.json").read_text())
    assert data["tool"] == "port"
    assert data["summary"]["open_ports"] == 2
    assert sorted(f["port"] for f in data["findings"]) == [22, 80]
    assert "<!doctype html>" in (tmp_path / "ports.html").read_text()

import json
from types import SimpleNamespace

from pysec import network_scanner


def test_run_writes_report(tmp_path, monkeypatch):
    scan_results = {
        "results": [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff"},
        ],
        "scan_time": 1.23,
        "hosts_found": 2,
    }
    monkeypatch.setattr(network_scanner, "scan_network", lambda *a, **k: scan_results)
    monkeypatch.setattr(network_scanner, "display_results", lambda *a, **k: None)

    report_path = tmp_path / "net.json"
    args = SimpleNamespace(
        target="192.168.1.0/24",
        interface="eth0",
        timeout=2,
        verbose=False,
        report=str(report_path),
        report_format=None,
    )
    network_scanner.run(args)

    data = json.loads(report_path.read_text())
    assert data["tool"] == "net"
    assert data["target"] == "192.168.1.0/24"
    assert data["summary"]["hosts_found"] == 2
    assert {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"} in data["findings"]


def test_run_without_report_does_not_write(monkeypatch):
    scan_results = {"results": [], "scan_time": 0.1, "hosts_found": 0}
    monkeypatch.setattr(network_scanner, "scan_network", lambda *a, **k: scan_results)
    monkeypatch.setattr(network_scanner, "display_results", lambda *a, **k: None)

    args = SimpleNamespace(
        target="10.0.0.0/24",
        interface="eth0",
        timeout=2,
        verbose=False,
        report=None,
        report_format=None,
    )
    network_scanner.run(args)

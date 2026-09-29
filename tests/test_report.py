import json
import os

from pysec.report import Report, ReportBuilder, resolve_format, write_report


def make_report(findings=None, summary=None):
    return Report(
        tool="port",
        target="10.0.0.1",
        started_at="2026-09-30T10:00:00",
        finished_at="2026-09-30T10:00:05",
        duration_seconds=5.0,
        summary=summary or {"open_ports": 1},
        findings=findings if findings is not None else [{"port": 22, "service": "SSH"}],
    )


def test_to_json_round_trips():
    data = json.loads(make_report().to_json())
    assert data["tool"] == "port"
    assert data["target"] == "10.0.0.1"
    assert data["summary"] == {"open_ports": 1}
    assert data["findings"] == [{"port": 22, "service": "SSH"}]


def test_to_html_contains_findings_and_escapes():
    report = make_report(findings=[{"url": "<script>x</script>", "status": 200}])
    out = report.to_html()
    assert "<!doctype html>" in out
    assert "10.0.0.1" in out
    assert "&lt;script&gt;" in out
    assert "<script>x</script>" not in out


def test_to_html_handles_no_findings():
    out = make_report(findings=[]).to_html()
    assert "No findings." in out


def test_builder_sets_timestamps_and_duration():
    report = ReportBuilder("hash", "deadbeef").build(summary={"cracked": False}, findings=[])
    assert report.tool == "hash"
    assert report.target == "deadbeef"
    assert report.started_at and report.finished_at
    assert report.duration_seconds >= 0
    assert report.findings == []


def test_resolve_format_infers_from_extension():
    assert resolve_format("out.json") == "json"
    assert resolve_format("out.html") == "html"
    assert resolve_format("out.htm") == "html"
    assert resolve_format("out") == "json"
    assert resolve_format("out.json", "both") == "both"
    assert resolve_format("out.html", "json") == "json"


def test_write_report_json(tmp_path):
    path = tmp_path / "scan.json"
    written = write_report(make_report(), str(path))
    assert written == [str(path)]
    data = json.loads(path.read_text())
    assert data["tool"] == "port"


def test_write_report_html_from_extension(tmp_path):
    path = tmp_path / "scan.html"
    written = write_report(make_report(), str(path))
    assert written == [str(path)]
    assert "<!doctype html>" in path.read_text()


def test_write_report_both_makes_two_files(tmp_path):
    path = tmp_path / "scan.json"
    written = write_report(make_report(), str(path), "both")
    assert sorted(os.path.basename(p) for p in written) == ["scan.html", "scan.json"]
    assert (tmp_path / "scan.json").exists()
    assert (tmp_path / "scan.html").exists()


def test_write_report_appends_extension_when_missing(tmp_path):
    path = tmp_path / "scan"
    written = write_report(make_report(), str(path), "json")
    assert written == [str(path) + ".json"]

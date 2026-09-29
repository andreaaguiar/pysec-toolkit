import html
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class Report:
    tool: str
    target: str
    started_at: str
    finished_at: str
    duration_seconds: float
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def to_html(self):
        columns = []
        for finding in self.findings:
            for key in finding:
                if key not in columns:
                    columns.append(key)

        def esc(value):
            return html.escape("" if value is None else str(value))

        summary_rows = "".join(
            f"<tr><th>{esc(name)}</th><td>{esc(value)}</td></tr>"
            for name, value in self.summary.items()
        ) or '<tr><td class="empty">No summary.</td></tr>'

        if self.findings:
            head = "".join(f"<th>{esc(column)}</th>" for column in columns)
            body = ""
            for finding in self.findings:
                cells = "".join(f"<td>{esc(finding.get(column))}</td>" for column in columns)
                body += f"<tr>{cells}</tr>"
            findings_html = (
                f"<table class='findings'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
            )
        else:
            findings_html = '<p class="empty">No findings.</p>'

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PySec {esc(self.tool)} report</title>
<style>
:root {{ color-scheme: light dark; --bg:#ffffff; --fg:#1a1a1a; --muted:#666; --line:#e3e3e3; --head:#f5f5f5; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#16181d; --fg:#e8e8e8; --muted:#9aa0aa; --line:#2c2f36; --head:#20242b; }} }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:24px; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
h1 {{ font-size:20px; margin:0 0 4px; }}
.meta {{ color:var(--muted); margin-bottom:20px; }}
.meta span {{ margin-right:16px; }}
h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); margin:24px 0 8px; }}
table {{ border-collapse:collapse; width:100%; }}
th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; word-break:break-word; }}
thead th, .summary th {{ background:var(--head); }}
.summary {{ max-width:520px; }}
.summary th {{ width:40%; }}
.empty {{ color:var(--muted); }}
</style>
</head>
<body>
<h1>PySec {esc(self.tool)} report</h1>
<div class="meta">
<span><strong>Target:</strong> {esc(self.target)}</span>
<span><strong>Started:</strong> {esc(self.started_at)}</span>
<span><strong>Finished:</strong> {esc(self.finished_at)}</span>
<span><strong>Duration:</strong> {esc(self.duration_seconds)}s</span>
</div>
<h2>Summary</h2>
<table class="summary"><tbody>{summary_rows}</tbody></table>
<h2>Findings ({len(self.findings)})</h2>
{findings_html}
</body>
</html>
"""


class ReportBuilder:
    """Capture the start time when a run begins, then build a Report at the end."""

    def __init__(self, tool, target):
        self.tool = tool
        self.target = target
        self._start = time.perf_counter()
        self._started_at = datetime.now()

    def build(self, summary=None, findings=None):
        return Report(
            tool=self.tool,
            target=self.target,
            started_at=self._started_at.isoformat(timespec="seconds"),
            finished_at=datetime.now().isoformat(timespec="seconds"),
            duration_seconds=round(time.perf_counter() - self._start, 2),
            summary=dict(summary or {}),
            findings=list(findings or []),
        )


def add_report_arguments(parser):
    parser.add_argument('--report', metavar='PATH',
                        help='Write a JSON and/or HTML report to PATH')
    parser.add_argument('--report-format', choices=['json', 'html', 'both'],
                        help='Report format (default: inferred from the --report extension, else json)')


def resolve_format(path, report_format=None):
    """Return json, html, or both for the given path and optional explicit format."""
    if report_format:
        return report_format
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.html', '.htm'):
        return 'html'
    return 'json'


def _path_for(path, ext):
    base, existing = os.path.splitext(path)
    if existing.lower() in ('.json', '.html', '.htm'):
        return base + ext
    return path + ext


def write_report(report, path, report_format=None):
    """Write the report to disk and return the list of files written."""
    report_format = resolve_format(path, report_format)

    outputs = []
    if report_format in ('json', 'both'):
        outputs.append((_path_for(path, '.json'), report.to_json()))
    if report_format in ('html', 'both'):
        outputs.append((_path_for(path, '.html'), report.to_html()))

    written = []
    for out_path, content in outputs:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)
        written.append(out_path)
    return written

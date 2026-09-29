# Web Vulnerability Scanner

`web_vuln_scanner.py` scans a web application for common vulnerabilities. It crawls the target site and tests each URL it finds.

## Requirements

- Python 3.10+
- requests library (which includes urllib3)
- beautifulsoup4 library

Install the toolkit from the repository root, which pulls in requests and beautifulsoup4:

```bash
pip3 install -e .
```

## Features

- **XSS detection**: Find reflected Cross-Site Scripting in URL parameters and form fields
- **SQL injection detection**: Send test payloads to URL parameters and form fields, then check the response for SQL errors
- **Time-based blind SQL injection detection**: Send payloads that delay the response, then confirm a repeatable delay against a baseline
- **Form testing**: Discover HTML forms during crawling and test each field, using the form GET or POST method
- **Open redirect detection**: Find open redirects in URL parameters
- **Security header analysis**: Check for missing security headers (HSTS, CSP, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options)
- **Directory listing detection**: Find exposed directory listings
- **Website crawling**: Discover and scan pages on the target site up to a set depth
- **Multi-threaded scanning**: Test URLs and forms in parallel

## Usage

```bash
pysec web https://example.com --report results.json
```

Or standalone with `python3 -m pysec.web_vuln_scanner https://example.com --report results.json`.

### Options

- `target`: Target URL to scan (required)
- `-c, --cookies`: File containing cookies (format: name=value; name2=value2)
- `-T, --threads`: Number of threads (default: 5)
- `-a, --user-agent`: Custom User-Agent string
- `-p, --payloads-dir`: Directory of custom payload files. Any file not present there falls back to the bundled default
- `--sqli-delay`: Delay in seconds a time-based SQL injection payload should cause (default: 5)
- `--report`: Write a JSON and/or HTML report to this path
- `--report-format`: Report format: json, html, or both (default: inferred from the path extension, else json)

## Custom Payloads

The scanner ships with a small default payload set as package data. Each detection type reads its entries from a file:

| File | Purpose |
|------|---------|
| `xss_payloads.txt` | XSS payloads to inject |
| `sqli_payloads.txt` | SQL injection payloads to inject |
| `sql_errors.txt` | Response signatures that indicate a SQL error |
| `open_redirect_payloads.txt` | Redirect payloads to inject |
| `sqli_time_payloads.txt` | Time-based blind SQL injection payloads to inject |

To use a larger set, put files with these names in a directory and pass it with `-p/--payloads-dir`. The scanner reads a file from that directory when it exists and falls back to the bundled default otherwise, so you can override one type without redefining the rest.

File format:

- One entry per line
- Blank lines and lines that start with `#` are ignored
- In `xss_payloads.txt`, the token `__MARKER__` is replaced with a unique marker the scanner then looks for in the response, which keeps false positives low. Keep `__MARKER__` where you want that detectable value
- In `open_redirect_payloads.txt`, the token `__HOST__` is replaced with the host the scanner confirms the redirect lands on
- In `sqli_time_payloads.txt`, the token `__DELAY__` is replaced with the `--sqli-delay` value in seconds. Keep `__DELAY__` inside the sleep function so the scanner can measure the expected delay

Larger community payload lists such as [SecLists](https://github.com/danielmiessler/SecLists) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) work well as a source. Add `__MARKER__` to XSS entries so reflection detection still applies.

Example:

```bash
pysec web https://example.com -p ./my-payloads --report results.json
```

### Default Behavior

- Website crawling is performed with a maximum depth of 2 levels from the initial URL
- The tool skips external links and URL fragments (#) during crawling
- Only forms whose action stays on the target host are tested
- Security headers are checked only on the main target URL
- If the target URL has no scheme, the scanner assumes `https://`

## Example

Scan a website with custom cookies and save a report:

```bash
pysec web https://example.com -c cookies.txt --report scan_results.json
```

### Report Format

The tool writes the same report envelope as the other tools. Pass a `.html`
path (or `--report-format html`) to get a self-contained HTML report instead.
The JSON structure is:

```json
{
    "tool": "web",
    "target": "https://example.com",
    "started_at": "2026-09-30T12:34:56",
    "finished_at": "2026-09-30T12:36:10",
    "duration_seconds": 74.0,
    "summary": {
        "xss": 1,
        "sqli": 1,
        "open_redirect": 0,
        "insecure_headers": 1,
        "directory_listing": 0,
        "urls_scanned": 12,
        "forms_tested": 3
    },
    "findings": [
        {
            "type": "xss",
            "url": "https://example.com/page",
            "parameter": "query",
            "payload": "<script>pysecXSS31337</script>",
            "details": "Reflected XSS: payload reflected as unescaped markup"
        },
        {
            "type": "sqli",
            "url": "https://example.com/page",
            "parameter": "id",
            "payload": "' OR '1'='1",
            "error": "SQL syntax",
            "details": "Possible SQL injection detected"
        }
    ]
}
```

## Integration with CTF-Toolkit

This tool can be used alongside the [CTF-Toolkit](https://github.com/andreaaguiar/CTF-Toolkit) repository for a complete security testing workflow:

1. Use the cheatsheets in CTF-Toolkit to understand web vulnerabilities
2. Run this tool to identify potential vulnerabilities in a target website
3. Use the findings as a starting point for manual exploitation with techniques from the cheatsheets

### Example Workflow

```bash
# Discover subdomains and save a JSON report
pysec subdomain example.com --report subdomains.json

# Scan each discovered subdomain URL for vulnerabilities
jq -r '.findings[].url' subdomains.json | while read -r url; do
    host=$(echo "$url" | sed -E 's#https?://##')
    pysec web "$url" --report "vulns-$host.json"
done

# Enumerate directories on a discovered host
pysec dir vulnerable-subdomain.example.com --https --report directories.html
```

## Disclaimer

Use this tool only for authorized security testing. Unauthorized scanning of websites can break laws and terms of service.

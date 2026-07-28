# Web Vulnerability Scanner

`web_vuln_scanner.py` scans a web application for common vulnerabilities. It crawls the target site and tests each URL it finds.

## Requirements

- Python 3.10+
- requests library (which includes urllib3)
- beautifulsoup4 library

Install dependencies with:

```bash
pip3 install requests beautifulsoup4
```

## Features

- **XSS detection**: Find reflected Cross-Site Scripting in URL parameters
- **SQL injection detection**: Send test payloads and check the response for SQL errors
- **Open redirect detection**: Find open redirects in URL parameters
- **Security header analysis**: Check for missing security headers (HSTS, CSP, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options)
- **Directory listing detection**: Find exposed directory listings
- **Website crawling**: Discover and scan pages on the target site up to a set depth
- **Multi-threaded scanning**: Test URLs in parallel

## Usage

```bash
python3 web_vuln_scanner.py -u https://example.com -o results.json
```

### Options

- `-u, --url`: Target URL to scan (required)
- `-o, --output`: Output file for results in JSON format
- `-c, --cookies`: File containing cookies (format: name=value; name2=value2)
- `-t, --threads`: Number of threads (default: 5)
- `-a, --user-agent`: Custom User-Agent string

### Default Behavior

- Website crawling is performed with a maximum depth of 2 levels from the initial URL
- The tool skips external links and URL fragments (#) during crawling
- Security headers are checked only on the main target URL
- If the target URL has no scheme, the scanner assumes `https://`

## Example

Scan a website with custom cookies and save results:

```bash
python3 web_vuln_scanner.py -u https://example.com -c cookies.txt -o scan_results.json
```

### Output Format

The tool saves results in JSON format with the following structure:

```json
{
    "target": "https://example.com",
    "scan_time": "2025-05-07 12:34:56",
    "results": {
        "xss": [
            {
                "url": "https://example.com/page",
                "parameter": "query",
                "payload": "<script>alert('XSS')</script>",
                "details": "Reflected XSS vulnerability detected"
            }
        ],
        "sqli": [
            {
                "url": "https://example.com/page",
                "parameter": "id",
                "payload": "' OR '1'='1",
                "error": "SQL syntax",
                "details": "Possible SQL injection detected"
            }
        ],
        "open_redirect": [...],
        "insecure_headers": [...],
        "directory_listing": [...]
    }
}
```

## Integration with CTF-Toolkit

This tool can be used alongside the [CTF-Toolkit](https://github.com/andreaaguiar/CTF-Toolkit) repository for a complete security testing workflow:

1. Use the cheatsheets in CTF-Toolkit to understand web vulnerabilities
2. Run this tool to identify potential vulnerabilities in a target website
3. Use the findings as a starting point for manual exploitation with techniques from the cheatsheets

### Example Workflow

```bash
# First, discover subdomains
python3 ~/pysec-toolkit/subdomain-enumeration/subdomain_enumeration.py example.com -o subdomains.txt

# Scan each subdomain for vulnerabilities
cat subdomains.txt | while read subdomain; do
    python3 ~/pysec-toolkit/web-vuln-scanner/web_vuln_scanner.py -u "https://$subdomain" -o "${subdomain}-vulns.json"
done

# Use directory enumeration for discovered vulnerable endpoints
python3 ~/pysec-toolkit/directory-enumeration/directory_enumeration.py vulnerable-subdomain.example.com --https -o directories.txt
```

## Disclaimer

Use this tool only for authorized security testing. Unauthorized scanning of websites can break laws and terms of service.

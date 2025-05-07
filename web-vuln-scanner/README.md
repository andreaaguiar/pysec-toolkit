# Web Vulnerability Scanner

A tool for scanning web applications for common security vulnerabilities.

## Features

- **XSS Detection**: Identifies Cross-Site Scripting vulnerabilities in URL parameters
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities by sending malicious payloads
- **Open Redirect Detection**: Identifies open redirect vulnerabilities in web applications
- **Security Header Analysis**: Checks for missing or misconfigured security headers (HSTS, CSP, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options)
- **Directory Listing Detection**: Identifies exposed directory listings
- **Website Crawling**: Automatically discovers and scans all pages on the target website (with configurable depth)
- **Multi-threaded Vulnerability Scanning**: Performs vulnerability scans in parallel for better performance

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
python3 ~/pysec-toolkit/subdomain-enumeration/subdomain_enumeration.py -d example.com -o subdomains.txt

# Scan each subdomain for vulnerabilities
cat subdomains.txt | while read subdomain; do
    python3 ~/pysec-toolkit/web-vuln-scanner/web_vuln_scanner.py -u "https://$subdomain" -o "${subdomain}-vulns.json"
done

# Use directory enumeration for discovered vulnerable endpoints
python3 ~/pysec-toolkit/directory-enumeration/directory_enumeration.py -u https://vulnerable-subdomain.example.com -o directories.txt
```

## Disclaimer

This tool should only be used for legitimate security testing with proper authorization. Unauthorized scanning of websites may violate laws and terms of service.

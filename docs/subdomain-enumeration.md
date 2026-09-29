# Subdomain Enumeration Tool

## Description

`subdomain_enumeration.py` finds valid subdomains of a target domain. It reads subdomain names from a wordlist and sends a request for each name. It uses multiple threads to check the names faster.

## Features

- **Multithreaded** - Check many subdomains at once
- **Protocol options** - Use HTTP, HTTPS, or both
- **Progress tracking** - Show progress and request rate
- **Report output** - Save results as a JSON or HTML report with `--report`
- **Timeout control** - Set the request timeout
- **User-agent customization** - Send a browser user-agent header
- **Title extraction** - Show the page title for each valid subdomain

## Requirements

- Python 3.10+
- Requests library
- BeautifulSoup library (for title extraction)

Install the toolkit from the repository root, which pulls in requests and beautifulsoup4:

```bash
pip3 install -e .
```

## Usage

Basic usage:

```bash
pysec subdomain example.com
```

Extended usage with options:

```bash
pysec subdomain example.com -w wordlist.txt -T 20 --both-protocols --report results.html
```

Or standalone with `python3 -m pysec.subdomain_enumeration example.com`.

## Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Target domain to scan (e.g., example.com) | Required |
| `-w, --wordlist` | Wordlist file containing subdomains to check | Bundled `subdomain_wordlist.txt` |
| `-T, --threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 5 |
| `--https` | Use HTTPS instead of HTTP | False (HTTP) |
| `--both-protocols` | Check both HTTP and HTTPS | False |
| `--report` | Write a JSON and/or HTML report to this path | None (display in terminal) |
| `--report-format` | Report format: json, html, or both | Inferred from the path extension, else json |

## Output Example

During scanning:

```bash
[+] Starting subdomain enumeration for example.com
[+] Loaded 1000 subdomains to check
[+] Progress: 123/1000 (12.3%) - 45.2 domains/sec

[+] Valid domain: http://www.example.com (Status: 200) - Example Website

[+] Valid domain: http://blog.example.com (Status: 200) - Example Blog
```

After completion:

```bash
[+] Enumeration completed in 22.35 seconds
[+] Found 5 valid subdomains
[+] Report written to results.html
```

## Creating a Wordlist

A small starter wordlist is bundled with the package and used by default, so the base command works without extra setup. It is only a sample. For real assessments, pass a large list with `-w`.

For real subdomain discovery, use a large wordlist. You can:

1. Use existing wordlists like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
1. Create your own wordlist based on common naming patterns
1. Combine multiple wordlists for better coverage

Example of a simple wordlist (subdomains.txt):

```text
www
mail
blog
```

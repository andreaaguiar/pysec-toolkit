# Subdomain Enumeration Tool

## Description

`subdomain_enumeration.py` finds valid subdomains of a target domain. It reads subdomain names from a wordlist and sends a request for each name. It uses multiple threads to check the names faster.

## Features

- **Multithreaded** - Check many subdomains at once
- **Protocol options** - Use HTTP, HTTPS, or both
- **Progress tracking** - Show progress and request rate
- **Result saving** - Save results to a file
- **Timeout control** - Set the request timeout
- **User-agent customization** - Send a browser user-agent header
- **Title extraction** - Show the page title for each valid subdomain

## Requirements

- Python 3.10+
- Requests library
- BeautifulSoup library (for title extraction)

Install dependencies with:

```bash
pip3 install requests beautifulsoup4
```

## Usage

Basic usage:

```bash
python3 subdomain_enumeration.py example.com
```

Extended usage with options:

```bash
python3 subdomain_enumeration.py example.com -w wordlist.txt -t 20 --both-protocols -o results.txt
```

## Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Target domain to scan (e.g., example.com) | Required |
| `-w, --wordlist` | Wordlist file containing subdomains to check | wordlist.txt |
| `-t, --threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 5 |
| `-o, --output` | Save results to this file | None (display in terminal) |
| `--https` | Use HTTPS instead of HTTP | False (HTTP) |
| `--both-protocols` | Check both HTTP and HTTPS | False |

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
[+] Results saved to results.txt
```

## Creating a Wordlist

A small starter `wordlist.txt` ships with the script, so the default command works without extra setup. It is only a sample. For real assessments, replace it with a large list.

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

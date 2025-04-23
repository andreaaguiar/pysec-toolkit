# Subdomain Enumeration Tool

## Description

The `subdomain_enumeration.py` script is a powerful and efficient tool for discovering valid subdomains of a target domain. It uses multithreaded requests to check a list of potential subdomains against a specified domain.

## Features

- **Multithreaded** - Significantly faster than sequential scanning
- **Protocol Options** - Support for HTTP, HTTPS, or both
- **Progress Tracking** - Real-time progress display with scan speed
- **Result Saving** - Option to save results to a file
- **Timeout Control** - Configurable request timeouts
- **User-Agent Customization** - Uses realistic browser user-agent headers
- **Title Extraction** - Extracts and displays webpage titles for valid domains

## Requirements

- Python 3.9+
- Requests library

Install dependencies with:

```bash
pip3 install requests
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

For effective subdomain discovery, you need a good wordlist. You can:

1. Use existing wordlists like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
1. Create your own wordlist based on common naming patterns
1. Combine multiple wordlists for better coverage

Example of a simple wordlist (subdomains.txt):

```text
www
mail
blog
```

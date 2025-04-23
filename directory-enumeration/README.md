# Directory Enumeration Tool

## Description

The `directory_enumeration.py` script is a powerful web directory discovery tool designed to find hidden or unlinked directories on web servers. The tool works by testing a list of common directory names against a target website and identifying which ones exist.

## Features

- **Multithreaded scanning** - Significantly faster than sequential scanning
- **Wordlist-based scanning** - Tests directories based on a provided wordlist
- **Multiple file extensions** - Support for multiple file extensions (.html, .php, .asp, etc.)
- **Protocol options** - Support for HTTP, HTTPS
- **Progress tracking** - Real-time progress display with scan speed
- **Result saving** - Option to save results to a file
- **Timeout control** - Configurable request timeouts
- **User-agent customization** - Uses realistic browser user-agent headers
- **Title extraction** - Extracts and displays webpage titles for valid directories
- **Colored output** - Visual differentiation of status codes
- **Verbose mode** - Detailed information including content size

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
python3 directory_enumeration.py target-domain.com
```

Extended usage with options:

```bash
python3 directory_enumeration.py example.com -w custom_wordlist.txt -t 20 --https -x ".html,.php,.txt,/" -o results.txt -v
```

## Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target domain or URL to scan (e.g., example.com) | Required |
| `-w, --wordlist` | Wordlist file containing directories to check | wordlist.txt |
| `-t, --threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 3 |
| `-o, --output` | Save results to this file | None (results displayed in terminal) |
| `--https` | Use HTTPS instead of HTTP | False (HTTP) |
| `-x, --extensions` | Comma-separated list of extensions to check | .html,.php,.txt,.asp,.aspx,/ |
| `-v, --verbose` | Show verbose output including content length | False |

## How It Works

The script follows these general steps:

1. Read potential directory names from a wordlist file
1. Construct URLs by combining the target domain with each directory name and extension
1. Make HTTP requests to each constructed URL using multiple threads
1. Report any URL that doesn't return a 404 status code (Not Found)

## Example Output

During scanning:

```bash
[+] Starting directory enumeration for http://example.com
[+] Loaded 1000 directories to check
[+] Testing 6 extensions: .html, .php, .txt, .asp, .aspx, (none)
[+] Progress: 123/6000 (2.1%) - 45.2 req/sec

[+] Found: http://example.com/admin (Status: 200, Size: 4328 bytes - Admin Portal)

[+] Found: http://example.com/login.php (Status: 200, Size: 1234 bytes - Login Page)
```

After completion:

```bash
[+] Enumeration completed in 22.35 seconds
[+] Found 5 valid resources
[+] Results saved to results.txt
```

## Creating a Wordlist

For effective directory discovery, you should use a comprehensive wordlist. You can:

1. Use existing wordlists like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
1. Create your own wordlist based on common web directory names
1. Combine multiple wordlists for better coverage

Example of a simple wordlist (wordlist.txt):

```text
admin
login
images
blog
contact
about
```

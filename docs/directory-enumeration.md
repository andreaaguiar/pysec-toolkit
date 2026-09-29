# Directory Enumeration Tool

## Description

`directory_enumeration.py` finds directories and files on a web server. It tests names from a wordlist against the target and reports the ones that exist.

## Features

- **Multithreaded scanning** - Test many paths at once
- **Wordlist-based scanning** - Test directory names from a wordlist
- **Multiple file extensions** - Check several extensions (.html, .php, .asp, and more)
- **Protocol options** - Use HTTP or HTTPS
- **Progress tracking** - Show progress and request rate
- **Result saving** - Save results to a file
- **Timeout control** - Set the request timeout
- **User-agent customization** - Send a browser user-agent header
- **Title extraction** - Show the page title for each valid path
- **Colored output** - Color the status codes
- **Verbose mode** - Show extra detail such as content size

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
pysec dir target-domain.com
```

Extended usage with options:

```bash
pysec dir example.com -w custom_wordlist.txt -T 20 --https -x ".html,.php,.txt,/" -o results.txt -v
```

Or standalone with `python3 -m pysec.directory_enumeration target-domain.com`.

## Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target domain or URL to scan (e.g., example.com) | Required |
| `-w, --wordlist` | Wordlist file containing directories to check | Bundled `directory_wordlist.txt` |
| `-T, --threads` | Number of concurrent threads | 10 |
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

A small starter wordlist is bundled with the package and used by default, so the base command works without extra setup. It is only a sample. For real assessments, pass a large list with `-w`.

For real directory discovery, use a large wordlist. You can:

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

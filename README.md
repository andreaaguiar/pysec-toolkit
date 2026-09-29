# PySec Toolkit

[![Python >=3.10](https://img.shields.io/badge/python-%3E=3.10-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/tests.yml)
[![Lint](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/lint.yml/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/lint.yml)
[![CodeQL](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/github-code-scanning/codeql)
[![Dependabot Updates](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/dependabot/dependabot-updates)

A collection of security assessment and penetration testing tools written in Python.

## Overview

PySec Toolkit is a set of Python security tools for network reconnaissance, password cracking, and web application testing. Each tool runs on its own from the command line. Use them only for authorized assessments.

## Tools Included

| Tool | Description | Features |
| ------ | ------------- | ---------- |
| **Port Scanner** | TCP port scanning utility | • Multithreaded scanning<br>• Service identification<br>• Custom port ranges<br>• Progress tracking |
| **Network Scanner** | Network discovery using ARP | • Host discovery<br>• MAC address resolution<br>• Hardware vendor detection<br>• Results export |
| **SSH Brute Force** | SSH credential testing tool | • Password list testing<br>• Connection management<br>• Multithreading support<br>• Resume capability |
| **Hash Cracker** | Dictionary-based hash cracking | • Multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512)<br>• Performance metrics<br>• Progress tracking |
| **Directory Enumeration** | Web directory discovery | • Multiple file extension support<br>• Concurrent requests<br>• Status code analysis<br>• Results filtering |
| **Subdomain Enumeration** | Subdomain discovery tool | • DNS enumeration<br>• Protocol selection (HTTP/HTTPS)<br>• Response analysis<br>• Title extraction |
| **Web Vulnerability Scanner** | Web application security testing | • XSS detection<br>• SQL injection detection (error and time-based blind)<br>• Open redirect testing<br>• Security header analysis<br>• Directory listing detection<br>• Custom payload sets |

## Requirements

- Python 3.10+

The runtime packages (`requests`, `beautifulsoup4`, `paramiko`, `scapy`, and
`tqdm`) are declared in `pyproject.toml` and installed automatically.

## Installation

Clone the repository:

```bash
git clone https://github.com/andreaaguiar/pysec-toolkit.git
cd pysec-toolkit
```

Install the package. The editable install (`-e`) lets you run the tools while
you edit the source:

```bash
pip3 install -e .
```

This adds a `pysec` command to your environment.

## Usage

Run any tool through the `pysec` command, one subcommand per tool:

```bash
pysec <tool> [options]
```

Examples:

```bash
pysec port 192.168.1.10 -p 1-1000
pysec net 192.168.1.0/24
pysec ssh 192.168.1.10 -u root -w passwords.txt
pysec hash -H <hash> -w wordlist.txt --type md5
pysec dir example.com
pysec subdomain example.com
pysec web https://example.com --report results.html
```

The shared options mean the same thing across tools: the target is the first
positional argument (where one applies), `-T/--threads` sets the thread count,
`--timeout` sets the request timeout, `-w/--wordlist` gives the wordlist or
password list, and `-v/--verbose` adds detail. Run `pysec <tool> -h` for the
full option list.

The directory and subdomain scanners fall back to a small bundled wordlist when
you do not pass `-w/--wordlist`.

## Reporting

Every tool prints its results to the terminal. To also save them, pass
`--report PATH`, which writes a structured report in a format shared across all
tools:

```bash
pysec web https://example.com --report scan.json          # JSON
pysec net 192.168.1.0/24 --report hosts.html              # self-contained HTML
pysec port 192.168.1.10 --report scan --report-format both  # scan.json and scan.html
```

The format is inferred from the file extension. Use `--report-format` to set it
explicitly to `json`, `html`, or `both`. Each report records the tool, target,
start and finish times, duration, a summary, and the findings.

Each tool also runs on its own as a module, for example
`python3 -m pysec.port_scanner 192.168.1.10 -p 1-1000`. You can also run the
toolkit with `python3 -m pysec <tool> [options]`.

## Documentation

Each tool can be used independently and has its own detailed documentation. Please refer to the individual README files for usage instructions, examples, and additional information:

- [Port Scanner Documentation](./docs/port-scanner.md)
- [Network Scanner Documentation](./docs/network-scanner.md)
- [SSH Brute Force Documentation](./docs/ssh-brute-force.md)
- [Hash Cracker Documentation](./docs/hash-cracker.md)
- [Directory Enumeration Documentation](./docs/directory-enumeration.md)
- [Subdomain Enumeration Documentation](./docs/subdomain-enumeration.md)
- [Web Vulnerability Scanner Documentation](./docs/web-vuln-scanner.md)

## Security and Ethical Considerations

### Ethical Use Guidelines

Use the tools in this repository only for:

- **Legitimate security assessment** - Only use on systems you own or have explicit permission to test
- **Educational purposes** - Learn about security concepts in a controlled environment
- **Professional security work** - Conduct authorized penetration tests or security assessments

### Legal Considerations

- Unauthorized scanning, testing, or accessing systems is illegal in most jurisdictions
- Always obtain proper authorization before conducting security tests
- Comply with all applicable laws, regulations, and policies
- Maintain appropriate documentation of authorization for security testing

### Responsible Disclosure

If you discover vulnerabilities using these tools:

1. Do not exploit vulnerabilities beyond verification
1. Report findings responsibly to the system owner
1. Allow reasonable time for remediation before disclosure
1. Follow established responsible disclosure practices

### Data Protection

- Handle all data collected during assessments as sensitive information
- Do not extract or exfiltrate data beyond what's necessary for verification
- Securely delete sensitive data when it's no longer needed
- Comply with data protection regulations (GDPR, CCPA, etc.)

## Project Structure

```bash
pysec-toolkit/
├── .github/
│   ├── workflows/
│   │   ├── lint.yml
│   │   └── tests.yml
│   └── dependabot.yml
├── src/
│   └── pysec/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── report.py
│       ├── port_scanner.py
│       ├── network_scanner.py
│       ├── ssh_brute_force.py
│       ├── hash_cracker.py
│       ├── directory_enumeration.py
│       ├── subdomain_enumeration.py
│       ├── web_vuln_scanner.py
│       └── data/
│           ├── directory_wordlist.txt
│           ├── subdomain_wordlist.txt
│           ├── hash_wordlist.txt
│           ├── ssh_passwords.txt
│           ├── xss_payloads.txt
│           ├── sqli_payloads.txt
│           ├── sql_errors.txt
│           ├── open_redirect_payloads.txt
│           └── sqli_time_payloads.txt
├── docs/
│   ├── port-scanner.md
│   ├── network-scanner.md
│   ├── ssh-brute-force.md
│   ├── hash-cracker.md
│   ├── directory-enumeration.md
│   ├── subdomain-enumeration.md
│   └── web-vuln-scanner.md
├── tests/
│   ├── conftest.py
│   ├── test_pysec.py
│   ├── test_report.py
│   ├── test_port_scanner.py
│   ├── test_network_scanner.py
│   ├── test_ssh_brute_force.py
│   ├── test_hash_cracker.py
│   ├── test_directory_enumeration.py
│   ├── test_subdomain_enumeration.py
│   ├── test_title_extraction.py
│   └── test_web_vuln_scanner.py
├── .gitignore
├── LICENSE
├── README.md
├── SECURITY.md
└── pyproject.toml
```

## Development

Install the package with its development tools ([ruff](https://docs.astral.sh/ruff/) and pytest):

```bash
pip3 install -e ".[dev]"
```

Run the linter:

```bash
ruff check .
```

Run the tests:

```bash
pytest
```

GitHub Actions runs ruff and pytest on every push and pull request. The tests run on Python 3.10 through 3.14.

## Future Development

Planned features and improvements:

- Add GUI interface option

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

To report a security issue in the toolkit, see [SECURITY.md](./SECURITY.md).

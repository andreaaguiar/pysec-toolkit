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
| **Web Vulnerability Scanner** | Web application security testing | • XSS detection<br>• SQL injection detection<br>• Open redirect testing<br>• Security header analysis<br>• Directory listing detection |

## Requirements

- Python 3.10+
- Required Python packages:

  - `requests` - For web-based tools
  - `beautifulsoup4` - For HTML parsing in the web vulnerability scanner
  - `paramiko` - For SSH operations
  - `scapy` - For network scanning
  - `tqdm` - For progress bars

## Installation

Clone the repository:

```bash
git clone https://github.com/andreaaguiar/pysec-toolkit.git
cd pysec-toolkit
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

## Usage

Run any tool through the `pysec` command, one subcommand per tool:

```bash
python3 pysec.py <tool> [options]
```

Examples:

```bash
python3 pysec.py port 192.168.1.10 -p 1-1000
python3 pysec.py net 192.168.1.0/24
python3 pysec.py ssh 192.168.1.10 -u root -w passwords.txt
python3 pysec.py hash -H <hash> -w wordlist.txt --type md5
python3 pysec.py dir example.com -w wordlist.txt
python3 pysec.py subdomain example.com -w wordlist.txt
python3 pysec.py web https://example.com -o results.json
```

The shared options mean the same thing across tools: the target is the first
positional argument (where one applies), `-T/--threads` sets the thread count,
`--timeout` sets the request timeout, `-o/--output` writes results to a file,
`-w/--wordlist` gives the wordlist or password list, and `-v/--verbose` adds
detail. Run `python3 pysec.py <tool> -h` for the full option list.

Each tool also still runs on its own, for example
`python3 port-scanner/port_scanner.py 192.168.1.10 -p 1-1000`.

## Documentation

Each tool can be used independently and has its own detailed documentation. Please refer to the individual README files for usage instructions, examples, and additional information:

- [Port Scanner Documentation](./port-scanner/README.md)
- [Network Scanner Documentation](./network-scanner/README.md)
- [SSH Brute Force Documentation](./ssh-brute-force/README.md)
- [Hash Cracker Documentation](./hash-cracker/README.md)
- [Directory Enumeration Documentation](./directory-enumeration/README.md)
- [Subdomain Enumeration Documentation](./subdomain-enumeration/README.md)
- [Web Vulnerability Scanner Documentation](./web-vuln-scanner/README.md)

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
PySec-Toolkit/
├── .github/
│   ├── workflows/
│   │   ├── lint.yml
│   │   └── tests.yml
│   └── dependabot.yml
├── tests/
│   ├── conftest.py
│   ├── test_hash_cracker.py
│   ├── test_port_scanner.py
│   ├── test_ssh_brute_force.py
│   ├── test_title_extraction.py
│   └── test_web_vuln_scanner.py
├── port-scanner/
│   ├── port_scanner.py
│   └── README.md
├── network-scanner/
│   ├── network_scanner.py
│   └── README.md
├── ssh-brute-force/
│   ├── ssh_brute_force.py
│   ├── passwords.txt
│   └── README.md
├── hash-cracker/
│   ├── hash_cracker.py
│   ├── wordlist.txt
│   └── README.md
├── directory-enumeration/
│   ├── directory_enumeration.py
│   ├── wordlist.txt
│   └── README.md
├── subdomain-enumeration/
│   ├── subdomain_enumeration.py
│   ├── wordlist.txt
│   └── README.md
├── web-vuln-scanner/
│   ├── web_vuln_scanner.py
│   └── README.md
├── .gitignore
├── LICENSE
├── README.md
├── SECURITY.md
├── pysec.py
├── requirements-dev.txt
├── requirements.txt
└── ruff.toml
```

## Development

Install the development tools ([ruff](https://docs.astral.sh/ruff/) and pytest):

```bash
pip3 install -r requirements-dev.txt
```

Run the linter:

```bash
ruff check .
```

Run the tests (they also need the runtime dependencies):

```bash
pip3 install -r requirements.txt
pytest
```

GitHub Actions runs ruff and pytest on every push and pull request. The tests need Python 3.10 or newer.

## Future Development

Planned features and improvements:

- Implement automated reporting
- Add GUI interface option
- Add larger payload libraries for vulnerability scanning

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

To report a security issue in the toolkit, see [SECURITY.md](./SECURITY.md).

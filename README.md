# PySec Toolkit

[![Python 3.9+](https://img.shields.io/badge/python-3.9|3.10|3.11-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/andreaaguiar/pysec-toolkit/graphs/commit-activity)
[![GitHub stars](https://img.shields.io/github/stars/andreaaguiar/pysec-toolkit.svg)](https://GitHub.com/andreaaguiar/pysec-toolkit/stargazers)
[![Dependabot Updates](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/dependabot/dependabot-updates)
[![CodeQL](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/andreaaguiar/pysec-toolkit/actions/workflows/github-code-scanning/codeql)
[![Documentation Status](https://img.shields.io/badge/docs-up--to--date-brightgreen.svg)](./README.md)

A collection of security assessment and penetration testing tools written in Python.

## Overview

PySec Toolkit provides a set of lightweight, efficient, and customizable security tools for network reconnaissance, password cracking, and web application testing. Each tool is designed to help security professionals perform targeted security assessments.

## Tools Included

| Tool | Description | Features |
|------|-------------|----------|
| **Port Scanner** | TCP port scanning utility | • Multithreaded scanning<br>• Service identification<br>• Customizable port ranges<br>• Progress tracking |
| **Network Scanner** | Network discovery using ARP | • Host discovery<br>• MAC address resolution<br>• Hardware vendor detection<br>• Results export |
| **SSH Brute Force** | SSH credential testing tool | • Password list testing<br>• Connection management<br>• Multithreading support<br>• Resume capability |
| **Hash Cracker** | Dictionary-based hash cracking | • Multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512)<br>• Performance metrics<br>• Progress tracking |
| **Directory Enumeration** | Web directory discovery | • Multiple file extension support<br>• Concurrent requests<br>• Status code analysis<br>• Results filtering |
| **Subdomain Enumeration** | Subdomain discovery tool | • DNS enumeration<br>• Protocol selection (HTTP/HTTPS)<br>• Response analysis<br>• Title extraction |
| **Web Vulnerability Scanner** | Web application security testing | • XSS detection<br>• SQL injection detection<br>• Open redirect testing<br>• Security header analysis<br>• Directory listing detection |

## Requirements

- Python 3.9+
- Required Python packages:

  - `requests` - For web-based tools
  - `beautifulsoup4` - For HTML parsing in the web vulnerability scanner
  - `paramiko` - For SSH operations
  - `scapy` - For network scanning
  - `tqdm` - For progress bars

You can install all dependencies using:

```bash
pip3 install -r requirements.txt
```

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

All tools in this repository are designed for:

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
├── port-scanner/
│   ├── port_scanner.py
│   └── README.md
├── network-scanner/
│   ├── network_scanner.py
│   └── README.md
├── ssh-brute-force/
│   ├── ssh_brute_force.py
│   └── README.md
├── hash-cracker/
│   ├── hash_cracker.py
│   └── README.md
├── directory-enumeration/
│   ├── directory_enumeration.py
│   └── README.md
├── subdomain-enumeration/
│   ├── subdomain_enumeration.py
│   └── README.md
├── web-vuln-scanner/
│   ├── web_vuln_scanner.py
│   └── README.md
├── README.md
└── requirements.txt
```

## Future Development

Planned features and improvements:

- Implement automated reporting
- Create a unified CLI interface for all tools
- Add GUI interface option
- Improve cross-platform compatibility
- Add more comprehensive payload libraries for vulnerability scanning

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

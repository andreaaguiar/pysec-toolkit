#!/usr/bin/env python3
import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TOOLS = {
    "port": ("port-scanner/port_scanner.py", "Scan TCP ports on a target host"),
    "net": ("network-scanner/network_scanner.py", "Discover hosts on a local network with ARP"),
    "ssh": ("ssh-brute-force/ssh_brute_force.py", "Test SSH logins against a password list"),
    "hash": ("hash-cracker/hash_cracker.py", "Crack a hash with a wordlist"),
    "dir": ("directory-enumeration/directory_enumeration.py", "Discover directories and files on a web server"),
    "subdomain": ("subdomain-enumeration/subdomain_enumeration.py", "Discover subdomains of a domain"),
    "web": ("web-vuln-scanner/web_vuln_scanner.py", "Scan a web application for common vulnerabilities"),
}


def load_tool(relative_path):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(
        prog="pysec",
        description="PySec Toolkit - security assessment tools",
    )
    subparsers = parser.add_subparsers(dest="tool", metavar="<tool>", required=True)

    for name, (relative_path, help_text) in TOOLS.items():
        module = load_tool(relative_path)
        tool_parser = subparsers.add_parser(name, help=help_text, description=help_text)
        module.add_arguments(tool_parser)
        tool_parser.set_defaults(_run=module.run)

    args = parser.parse_args()

    try:
        args._run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

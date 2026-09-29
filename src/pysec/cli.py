#!/usr/bin/env python3
import argparse
import importlib
import sys

TOOLS = {
    "port": ("pysec.port_scanner", "Scan TCP ports on a target host"),
    "net": ("pysec.network_scanner", "Discover hosts on a local network with ARP"),
    "ssh": ("pysec.ssh_brute_force", "Test SSH logins against a password list"),
    "hash": ("pysec.hash_cracker", "Crack a hash with a wordlist"),
    "dir": ("pysec.directory_enumeration", "Discover directories and files on a web server"),
    "subdomain": ("pysec.subdomain_enumeration", "Discover subdomains of a domain"),
    "web": ("pysec.web_vuln_scanner", "Scan a web application for common vulnerabilities"),
}


def load_tool(module_name):
    return importlib.import_module(module_name)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pysec",
        description="PySec Toolkit - security assessment tools",
    )
    subparsers = parser.add_subparsers(dest="tool", metavar="<tool>", required=True)
    for name, (_module_name, help_text) in TOOLS.items():
        subparsers.add_parser(name, help=help_text, add_help=False)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = build_parser()

    if not argv or argv[0] not in TOOLS:
        parser.parse_args(argv)
        return

    tool = argv[0]
    module_name, help_text = TOOLS[tool]

    module = load_tool(module_name)

    tool_parser = argparse.ArgumentParser(prog=f"pysec {tool}", description=help_text)
    module.add_arguments(tool_parser)
    args = tool_parser.parse_args(argv[1:])

    try:
        module.run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        if getattr(args, "verbose", False):
            raise
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

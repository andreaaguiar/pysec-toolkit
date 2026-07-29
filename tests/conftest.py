import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TOOL_DIRS = [
    "port-scanner",
    "hash-cracker",
    "directory-enumeration",
    "subdomain-enumeration",
    "web-vuln-scanner",
    "ssh-brute-force",
]

for name in TOOL_DIRS:
    sys.path.insert(0, str(ROOT / name))

sys.path.insert(0, str(ROOT))

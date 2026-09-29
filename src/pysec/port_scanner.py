import argparse
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pysec.report import ReportBuilder, add_report_arguments, write_report

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--ports', help='Port range to scan (e.g. 1-1000)', default='1-65535')
    parser.add_argument('-T', '--threads', help='Number of threads to use', type=int, default=100)
    parser.add_argument('--timeout', help='Timeout in seconds for each port', type=float, default=0.5)
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    add_report_arguments(parser)


def parse_ports(ports_str):
    """Parse a port range string like '1-1000' or '80' into (start, end)."""
    parts = ports_str.split('-')
    start_port = int(parts[0])
    end_port = int(parts[1]) if len(parts) > 1 else start_port
    return start_port, end_port


def probe_port(ip, port, timeout):
    """Return True if the TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def run(args):
    ip = args.target
    report = ReportBuilder("port", ip)
    open_ports = []
    print_lock = threading.Lock()
    start_time = time.time()

    start_port, end_port = parse_ports(args.ports)
    ports = range(start_port, end_port + 1)
    total_ports = len(ports)
    ports_scanned = 0

    def scan_port(port):
        nonlocal ports_scanned
        is_open = probe_port(ip, port, args.timeout)

        with print_lock:
            ports_scanned += 1
            if args.verbose:
                percent_done = int(ports_scanned / total_ports * 100)
                print(f"Scanning port {port} [{percent_done}% complete]", end='\r')
            elif ports_scanned % 1000 == 0:
                percent_done = int(ports_scanned / total_ports * 100)
                print(f"Progress: {percent_done}% complete ({ports_scanned}/{total_ports})", end='\r')

            if is_open:
                open_ports.append(port)
                service = COMMON_SERVICES.get(port, "Unknown")
                print(f"Port {port} is open    [{service}]                ")

    print(f"\nStarting scan on {ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Using {args.threads} threads with a {args.timeout}s timeout")
    print("=" * 60)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        list(executor.map(scan_port, ports))

    elapsed_time = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Scan completed in {elapsed_time:.2f} seconds")

    open_ports.sort()
    if open_ports:
        print("Open Ports Summary:")
        for port in open_ports:
            service = COMMON_SERVICES.get(port, "Unknown")
            print(f"Port {port}: {service}")
        print(f"Total: {len(open_ports)} open ports found")
    else:
        print("No open ports found.")

    if getattr(args, "report", None):
        findings = [
            {"port": port, "service": COMMON_SERVICES.get(port, "Unknown")}
            for port in open_ports
        ]
        result = report.build(
            summary={
                "port_range": f"{start_port}-{end_port}",
                "ports_scanned": total_ports,
                "open_ports": len(open_ports),
            },
            findings=findings,
        )
        for path in write_report(result, args.report, args.report_format):
            print(f"[+] Report written to {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Port Scanner')
    add_arguments(parser)
    run(parser.parse_args(argv))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

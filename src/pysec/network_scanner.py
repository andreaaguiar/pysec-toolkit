import argparse
import ipaddress
import sys
import time
from datetime import datetime

from scapy.all import ARP, Ether, conf, srp
from tqdm import tqdm

from pysec.report import ReportBuilder, add_report_arguments, write_report


def add_arguments(parser):
    parser.add_argument('target', nargs='?', default='192.168.1.0/24',
                        help='IP range to scan in CIDR notation (default: 192.168.1.0/24)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Network interface to use (default: auto-detect)')
    parser.add_argument('--timeout', type=float, default=2,
                        help='Timeout for responses in seconds (default: 2)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    add_report_arguments(parser)

def get_default_interface():
    """Auto-detect the default interface to use"""
    try:
        return conf.iface
    except Exception as e:
        print(f"[!] Error detecting default interface: {e}")
        sys.exit(1)

def scan_network(interface, ip_range, timeout=2):
    """Perform the ARP scan on the specified network range"""
    print(f"[*] Starting ARP scan on {ip_range} via {interface}")
    print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    start_time = time.time()

    # Create and send the ARP packet
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    try:
        # Calculate target count for progress indication
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses
            print(f"[*] Scanning {total_hosts} potential hosts...")
        except ValueError:
            # If IP range format is invalid or can't be parsed
            total_hosts = None
            print("[*] Scanning targets...")

        # Create the ARP packet
        packet = Ether(dst=broadcast_mac)/ARP(pdst=ip_range)

        ans, _unans = srp(
            packet,
            timeout=timeout,
            iface=interface,
            inter=0.1,
            verbose=0,
            return_packets=True
        )

        results = []
        print("[*] Processing responses...")
        for _send, receive in tqdm(ans, desc="Processing", unit="host"):
            mac = receive.sprintf(r"%Ether.src%")
            ip = receive.sprintf(r"%ARP.psrc%")
            results.append({'ip': ip, 'mac': mac})

        end_time = time.time()
        scan_time = end_time - start_time

        return {
            'results': results,
            'scan_time': scan_time,
            'hosts_found': len(results)
        }
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        sys.exit(1)

def display_results(scan_results, verbose=False):
    """Format and display the scan results"""
    results = scan_results['results']
    scan_time = scan_results['scan_time']

    if not results:
        print("[!] No hosts found.")
        return

    print("\n" + "=" * 50)
    print(f"SCAN RESULTS: {len(results)} hosts found in {scan_time:.2f} seconds")
    print("=" * 50)
    print(f"{'IP Address':<16} {'MAC Address':<18}")
    print("-" * 50)

    for host in results:
        print(f"{host['ip']:<16} {host['mac']:<18}")

        # Try to get vendor information in verbose mode
        if verbose:
            try:
                oui = host['mac'][:8].replace(':', '').upper()
                if hasattr(conf, 'manufdb'):
                    vendor = conf.manufdb._get_manuf(oui)
                    if vendor:
                        print(f"{'':<16} Vendor: {vendor}")
            except Exception:
                pass

    print("=" * 50)

def run(args):
    report = ReportBuilder("net", args.target)
    interface = args.interface if args.interface else get_default_interface()
    scan_results = scan_network(interface, args.target, args.timeout)
    display_results(scan_results, args.verbose)

    if getattr(args, "report", None):
        built = report.build(
            summary={"hosts_found": scan_results["hosts_found"], "interface": str(interface)},
            findings=scan_results["results"],
        )
        for path in write_report(built, args.report, args.report_format):
            print(f"[+] Report written to {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Network Scanner - Discover active hosts using ARP requests')
    add_arguments(parser)
    run(parser.parse_args(argv))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

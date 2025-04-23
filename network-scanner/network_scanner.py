import argparse
import sys
import time
import ipaddress
from datetime import datetime
from scapy.all import Ether, ARP, srp, conf
from tqdm import tqdm

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Network Scanner - Discover active hosts using ARP requests')
    parser.add_argument('-i', '--interface', type=str, default=None, 
                        help='Network interface to use (default: auto-detect)')
    parser.add_argument('-r', '--range', type=str, default="192.168.1.0/24", 
                        help='IP range to scan in CIDR notation (default: 192.168.1.0/24)')
    parser.add_argument('-t', '--timeout', type=float, default=2, 
                        help='Timeout for responses in seconds (default: 2)')
    parser.add_argument('-o', '--output', type=str, 
                        help='Save results to the specified file')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Enable verbose output')
    return parser.parse_args()

def get_default_interface():
    """Auto-detect the default interface to use"""
    try:
        return conf.iface
    except Exception as e:
        print(f"[!] Error detecting default interface: {e}")
        sys.exit(1)

def scan_network(interface, ip_range, timeout=2, verbose=False):
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
        
        # Send packets with progress bar if tqdm is available
        if 'tqdm' in globals():
            ans, unans = srp(
                packet, 
                timeout=timeout, 
                iface=interface, 
                inter=0.1, 
                verbose=0,  # Disable scapy's output when using tqdm
                return_packets=True
            )
            
            # Process the results with progress indication
            results = []
            print("[*] Processing responses...")
            for send, receive in tqdm(ans, desc="Processing", unit="host"):
                mac = receive.sprintf(r"%Ether.src%")
                ip = receive.sprintf(r"%ARP.psrc%")
                results.append({'ip': ip, 'mac': mac})
        else:
            # Fallback if tqdm is not available
            ans, unans = srp(packet, timeout=timeout, iface=interface, inter=0.1, verbose=verbose)
            
            # Process the results
            results = []
            for send, receive in ans:
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
            except:
                pass
    
    print("=" * 50)

def save_to_file(filename, scan_results):
    """Save the scan results to a file"""
    try:
        with open(filename, 'w') as f:
            f.write(f"Network Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan completed in {scan_results['scan_time']:.2f} seconds\n")
            f.write(f"Found {scan_results['hosts_found']} active hosts\n\n")
            f.write(f"{'IP Address':<16} {'MAC Address':<18}\n")
            f.write("-" * 40 + "\n")
            
            for host in scan_results['results']:
                f.write(f"{host['ip']:<16} {host['mac']:<18}\n")
                
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving results to file: {e}")

def main():
    """Main function"""
    # Parse arguments
    args = parse_arguments()
    
    # Set interface
    interface = args.interface if args.interface else get_default_interface()
    
    # Perform scan
    scan_results = scan_network(interface, args.range, args.timeout, args.verbose)
    
    # Display results
    display_results(scan_results, args.verbose)
    
    # Save results if output file specified
    if args.output:
        save_to_file(args.output, scan_results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

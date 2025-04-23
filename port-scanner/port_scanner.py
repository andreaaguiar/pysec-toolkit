import sys
import socket
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Dictionary of common ports and their services
common_services = {
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

# Set up argument parser
parser = argparse.ArgumentParser(description='Port Scanner')
parser.add_argument('-t', '--target', help='Target IP address', required=True)
parser.add_argument('-p', '--ports', help='Port range to scan (e.g. 1-1000)', default='1-65535')
parser.add_argument('-th', '--threads', help='Number of threads to use', type=int, default=100)
parser.add_argument('-to', '--timeout', help='Timeout in seconds for each port', type=float, default=0.5)
parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
args = parser.parse_args()

ip = args.target
open_ports = []
print_lock = threading.Lock()
start_time = time.time()

# Parse port range
port_range = args.ports.split('-')
start_port = int(port_range[0])
end_port = int(port_range[1]) if len(port_range) > 1 else int(port_range[0])
ports = range(start_port, end_port + 1)
total_ports = len(ports)
ports_scanned = 0

def probe_port(ip, port, result = 1, timeout=0.5): 
  try: 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sock.settimeout(timeout) 
    r = sock.connect_ex((ip, port))   
    if r == 0: 
      result = r 
    sock.close() 
  except Exception as e: 
    if args.verbose:
      print(f"Error scanning port {port}: {str(e)}")
    pass 
  return result

def scan_port(port):
    global ports_scanned
    response = probe_port(ip, port, timeout=args.timeout)
    
    with print_lock:
        ports_scanned += 1
        if args.verbose:
            percent_done = int(ports_scanned / total_ports * 100)
            print(f"Scanning port {port} [{percent_done}% complete]", end='\r')
        else:
            if ports_scanned % 1000 == 0:
                percent_done = int(ports_scanned / total_ports * 100)
                print(f"Progress: {percent_done}% complete ({ports_scanned}/{total_ports})", end='\r')
            
    if response == 0:
        with print_lock:
            open_ports.append(port)
            service = common_services.get(port, "Unknown")
            print(f"Port {port} is open    [{service}]                ")

def main():
    print(f"\nStarting scan on {ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Using {args.threads} threads with a {args.timeout}s timeout")
    print("=" * 60)
    
    # Create a thread pool for scanning
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scan_port, ports)
    
    elapsed_time = time.time() - start_time
    
    print("\n" + "=" * 60)
    print(f"Scan completed in {elapsed_time:.2f} seconds")
    
    if open_ports: 
        print("Open Ports Summary:")
        open_ports.sort()
        for port in open_ports:
            service = common_services.get(port, "Unknown")
            print(f"Port {port}: {service}")
        print(f"Total: {len(open_ports)} open ports found")
    else: 
        print("No open ports found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

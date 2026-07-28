# Network Scanner Tool

## Description

`network_scanner.py` finds active hosts on a local network with ARP requests. It uses the Scapy library to build and send the packets. Use it to map hosts on a network you are authorized to test.

## Features

- **ARP-based discovery** - Detect hosts with ARP requests
- **Broadcast scanning** - Send requests to the whole subnet
- **MAC address resolution** - Report the IP and MAC address of each host
- **Configurable timeout** - Set the response wait time per network
- **Progress indication** - Show progress on large networks
- **Hardware vendor detection** - Name the vendor from the MAC address (verbose mode)
- **Output file support** - Save results to a text file

## Requirements

- Python 3.10+
- Scapy library
- tqdm library

Install dependencies with:

```bash
pip3 install scapy tqdm
```

Note: Scapy may require additional dependencies based on your operating system.

## Usage

```bash
sudo python3 network_scanner.py [-i INTERFACE] [-r RANGE] [-t TIMEOUT] [-o OUTPUT] [-v]
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Network interface to use | Auto-detected |
| `-r, --range` | IP range to scan in CIDR notation | 192.168.1.0/24 |
| `-t, --timeout` | Timeout for responses in seconds | 2 |
| `-o, --output` | Save results to the specified file | None (display in terminal) |
| `-v, --verbose` | Enable verbose output (includes MAC vendor information) | False |

Note: This script requires root/administrator privileges to send raw packets on the network interface.

## How It Works

The script:

1. Parses command line arguments to configure the scan
1. Auto-detects the network interface (if not specified)
1. Creates an Ethernet frame with a broadcast MAC address
1. Attaches an ARP request asking for all hosts in the specified IP range
1. Sends these packets on the network interface
1. Collects and processes responses from active hosts
1. Displays the results in a formatted table
1. Optionally saves results to a file (if output file is specified)

## Example Output

```text
==================================================
SCAN RESULTS: 3 hosts found in 1.25 seconds
==================================================
IP Address       MAC Address        
--------------------------------------------------
192.168.1.1      00:11:22:33:44:55  
192.168.1.2      aa:bb:cc:dd:ee:ff  
                 Vendor: Cisco Systems, Inc
192.168.1.10     11:22:33:44:55:66  
==================================================
```

With the `-o` option, these results will also be saved to the specified file.

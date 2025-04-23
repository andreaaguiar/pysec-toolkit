# Port Scanner Tool

## Description

The `port_scanner.py` script is a powerful and flexible port scanning utility designed for network reconnaissance. It systematically checks for open ports on a target IP address, helping security professionals identify potential entry points in a system.

## Features

- **Flexible Port Range** - Scan all 65,535 TCP ports or specify a custom range
- **Multithreaded Scanning** - Uses threads to significantly speed up the scanning process
- **Service Identification** - Identifies common services running on open ports
- **Progress Tracking** - Shows real-time progress during scanning
- **Customizable Parameters** - Adjust threads, timeout, port range via command-line arguments
- **Verbose Mode** - Optional detailed output for troubleshooting

## Requirements

- Python 3.9+

## Usage

```bash
python3 port_scanner.py -t TARGET_IP [options]
```

### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target IP address (required) | Required |
| `-p, --ports` | Port range to scan (e.g., 1-1000) | 1-65535 |
| `-th, --threads` | Number of threads to use | 100 |
| `-to, --timeout` | Timeout in seconds for each port | 0.5 |
| `-v, --verbose` | Enable verbose output | False |

### Examples

Scan all ports on a target:

```bash
python3 port_scanner.py -t 192.168.1.6
```

Scan specific port range with more threads:

```bash
python3 port_scanner.py -t 192.168.1.6 -p 1-1000 -th 200
```

Quick scan with shorter timeout:

```bash
python3 port_scanner.py -t 192.168.1.6 -p 1-1000 -to 0.2
```

## How It Works

The script works by:

1. Parsing command-line arguments to determine scan parameters
1. Establishing TCP socket connections to each port in parallel using multiple threads
1. Setting a customizable timeout for each connection attempt
1. Capturing successful connections and identifying common services
1. Displaying real-time progress and open port information
1. Providing a summary of results when the scan completes

## Example Output

```text
Starting scan on 192.168.1.6
Port range: 1-1000
Using 100 threads with a 0.5s timeout
============================================================
Port 22 is open    [SSH]                
Port 80 is open    [HTTP]                
Port 443 is open    [HTTPS]                
Port 8080 is open    [HTTP-Proxy]                
Progress: 100% complete (1000/1000)
============================================================
Scan completed in 8.32 seconds

Open Ports Summary:
Port 22: SSH
Port 80: HTTP
Port 443: HTTPS
Port 8080: HTTP-Proxy
Total: 4 open ports found
```

## Advanced Usage

### Service Identification

The scanner automatically identifies common services running on standard ports, including:

- Web servers (HTTP, HTTPS)
- SSH, FTP, Telnet
- Database servers (MySQL, PostgreSQL, MSSQL)
- Remote access protocols (RDP, VNC)
- And many more

### Performance Tuning

For faster scanning:

- Reduce the port range with `-p 1-1000`
- Increase thread count with `-th 200`
- Reduce timeout with `-to 0.3`

For more thorough scanning:

- Scan all ports with default `-p 1-65535`
- Use longer timeout with `-to 1.0`

### Error Handling

The scanner includes proper error handling and can be safely interrupted with Ctrl+C at any time.

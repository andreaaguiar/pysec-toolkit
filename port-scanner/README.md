# Port Scanner Tool

## Description

`port_scanner.py` scans TCP ports on a target IP address. It reports the open ports and names the common service on each one. Use it to find open entry points during an authorized assessment.

## Features

- **Port range** - Scan all 65,535 TCP ports or a custom range
- **Multithreaded scanning** - Use many threads to scan faster
- **Service identification** - Name the common service on each open port
- **Progress tracking** - Show progress while the scan runs
- **Command-line options** - Set threads, timeout, and port range
- **Verbose mode** - Print detailed output for troubleshooting

## Requirements

- Python 3.10+

## Usage

Through the toolkit command:

```bash
python3 pysec.py port TARGET_IP [options]
```

Or standalone:

```bash
python3 port_scanner.py TARGET_IP [options]
```

### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address (required) | Required |
| `-p, --ports` | Port range to scan (e.g., 1-1000) | 1-65535 |
| `-T, --threads` | Number of threads to use | 100 |
| `--timeout` | Timeout in seconds for each port | 0.5 |
| `-v, --verbose` | Enable verbose output | False |

### Examples

Scan all ports on a target:

```bash
python3 pysec.py port 192.168.1.6
```

Scan specific port range with more threads:

```bash
python3 pysec.py port 192.168.1.6 -p 1-1000 -T 200
```

Quick scan with shorter timeout:

```bash
python3 pysec.py port 192.168.1.6 -p 1-1000 --timeout 0.2
```

## How It Works

The script works by:

1. Parsing command-line arguments to determine scan parameters
1. Establishing TCP socket connections to each port in parallel using multiple threads
1. Setting a timeout for each connection attempt
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
- Increase thread count with `-T 200`
- Reduce timeout with `--timeout 0.3`

For more thorough scanning:

- Scan all ports with default `-p 1-65535`
- Use longer timeout with `--timeout 1.0`

### Error Handling

The scanner handles errors and stops safely when you press Ctrl+C.

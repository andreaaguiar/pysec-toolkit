# SSH Brute Force Tool

## Description

The `ssh_brute_force.py` script is a utility designed to test SSH server security by attempting to authenticate using a list of potential passwords. It uses the Paramiko library to establish SSH connections and test credentials.

## Features

- **Wordlist-based authentication** - Tests passwords from a provided wordlist
- **Interactive interface** - User-friendly prompts for target information
- **Targeted testing** - Tests a specific username against multiple passwords
- **Connection management** - Properly handles SSH connection states

## Requirements

- Python 3.9+
- Paramiko library

Install dependencies with:

```bash
pip3 install paramiko
```

## Usage

Run the script:

```bash
python3 ssh_brute_force.py
```

When prompted:

1. Enter the target IP address
1. Enter the username to test
1. Enter the path to your password list file

## How It Works

The script:

1. Establishes an SSH connection to the target server
1. Attempts authentication with the specified username and each password from the wordlist
1. Reports success when a valid password is found
1. Properly handles connection errors and authentication failures

## Example Output

```bash
Please enter target IP address: 192.168.1.10
Please enter username to bruteforce: admin
Please enter location of the password file: passwords.txt
no luck
no luck
password found: supersecret
```

## Potential Improvements

The current script could be enhanced by:

- Adding multithreading for faster testing
- Implementing connection throttling to avoid lockouts
- Adding support for key-based authentication testing
- Implementing a timeout mechanism for unresponsive servers
- Adding logging capabilities for audit trails

# SSH Brute Force Tool

## Description

`ssh_brute_force.py` tests SSH login security. It tries a list of passwords for one username against a target server. It uses the Paramiko library to make the SSH connections.

## Features

- **Wordlist-based testing** - Try passwords from a password file
- **Multithreading** - Run several attempts at once and stop on the first match
- **Interactive or command-line use** - Enter details at the prompt or pass them as flags
- **Resume support** - Continue from a given line in the password file
- **Output file** - Save progress and the result to a file

## Requirements

- Python 3.10+
- Paramiko library

Install dependencies with:

```bash
pip3 install paramiko
```

## Usage

Run with prompts:

```bash
python3 pysec.py ssh
```

Or pass the details as flags:

```bash
python3 pysec.py ssh 192.168.1.10 -u admin -w passwords.txt -T 8
```

Each tool also runs standalone, for example `python3 ssh-brute-force/ssh_brute_force.py 192.168.1.10 -u admin -w passwords.txt`.

### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address | Prompt |
| `-u, --username` | Username to test | Prompt |
| `-w, --wordlist` | Path to the password file | Prompt |
| `-P, --port` | SSH port | 22 |
| `-T, --threads` | Number of threads | 4 |
| `-d, --delay` | Delay between attempts in seconds | 0 |
| `--timeout` | Connection timeout in seconds | 5 |
| `-o, --output` | Save results to this file | None |
| `--resume` | Resume from a line number in the password file | None |
| `-v, --verbose` | Show each failed attempt | False |

When you run without flags, enter the target IP address, the username, and the path to your password file at the prompts.

A small starter `passwords.txt` ships with the script for quick testing. It is only a sample. For real assessments, supply a large password list such as [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords).

## How It Works

The script:

1. Reads passwords from the password file
1. Opens SSH connections to the target with several threads
1. Tries the username with each password
1. Stops and reports the password on the first match
1. Handles connection errors and failed logins

## Example Output

```bash
Please enter target IP address: 192.168.1.10
Please enter username to bruteforce: admin
Please enter location of the password file: passwords.txt
[*] Loaded 50 passwords from passwords.txt
[+] SUCCESS: Password found: supersecret

[+] Authentication successful!
[+] Target: admin@192.168.1.10:22
[+] Password: supersecret
```

## Potential Improvements

The script could add:

- Connection throttling to avoid account lockouts
- Key-based authentication testing

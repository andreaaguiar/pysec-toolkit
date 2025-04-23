import hashlib
import argparse
import os
import time
import sys
from typing import Optional

# Define available hash algorithms
HASH_TYPES = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512
}

def validate_hash(hash_string: str, hash_type: str) -> bool:
    """Validate if the hash string matches the expected format for the specified hash type."""
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }
    
    if len(hash_string) != expected_lengths.get(hash_type, 0):
        return False
    
    # Check if the hash is hexadecimal
    try:
        int(hash_string, 16)
        return True
    except ValueError:
        return False

def crack_hash(wordlist_path: str, hash_to_crack: str, hash_type: str = 'md5') -> Optional[str]:
    """
    Try to crack the hash using the provided wordlist.
    
    Args:
        wordlist_path: Path to the wordlist file
        hash_to_crack: The hash to be cracked
        hash_type: The hash algorithm to use
    
    Returns:
        The cleartext password if found, None otherwise
    """
    hash_func = HASH_TYPES.get(hash_type.lower())
    if not hash_func:
        print(f"Error: Unsupported hash type '{hash_type}'")
        print(f"Supported types: {', '.join(HASH_TYPES.keys())}")
        return None
    
    try:
        # Get total lines for progress calculation
        total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding='latin-1', errors='ignore'))
        
        start_time = time.time()
        with open(wordlist_path, 'r', encoding='latin-1', errors='ignore') as file:
            for i, line in enumerate(file, 1):
                password = line.strip()
                
                # Skip empty lines
                if not password:
                    continue
                
                # Show progress every 10000 attempts
                if i % 10000 == 0 or i == total_lines:
                    elapsed = time.time() - start_time
                    percent = (i / total_lines) * 100
                    passwords_per_sec = i / elapsed if elapsed > 0 else 0
                    print(f"\rProgress: {i}/{total_lines} ({percent:.2f}%) - {passwords_per_sec:.2f} passwords/sec", end="")
                
                try:
                    hash_obj = hash_func(password.encode())
                    hashed_pass = hash_obj.hexdigest()
                    
                    if hashed_pass.lower() == hash_to_crack.lower():
                        print(f"\nFound cleartext password after {i} attempts!")
                        return password
                except Exception:
                    # Skip words that can't be hashed properly
                    continue
            
        return None
    except FileNotFoundError:
        print(f"Error: The wordlist file '{wordlist_path}' could not be found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied when trying to read '{wordlist_path}'.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

def main():
    """Main function to parse arguments and execute the hash cracking process."""
    parser = argparse.ArgumentParser(description='Hash Cracker - A tool to crack various hash types')
    parser.add_argument('-w', '--wordlist', type=str, help='Path to the wordlist file')
    parser.add_argument('-H', '--hash', type=str, help='Hash to crack')
    parser.add_argument('-t', '--type', default='md5', choices=HASH_TYPES.keys(),
                        help=f'Hash type to use. Default is md5. Available options: {", ".join(HASH_TYPES.keys())}')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    # Get hash and wordlist (either from args or interactively)
    wordlist_path = args.wordlist
    hash_to_crack = args.hash
    hash_type = args.type
    
    if args.interactive or not (wordlist_path and hash_to_crack):
        if args.interactive or not wordlist_path:
            wordlist_path = input('Enter wordlist file location: ')
        if args.interactive or not hash_to_crack:
            hash_to_crack = input('Enter hash to be cracked: ')
        if args.interactive or not hash_type:
            hash_type = input(f'Enter hash type ({", ".join(HASH_TYPES.keys())}). Default is md5: ') or 'md5'
    
    # Validate inputs
    if not os.path.exists(wordlist_path):
        print(f"Error: The wordlist file '{wordlist_path}' does not exist.")
        return
    
    if not validate_hash(hash_to_crack, hash_type):
        print(f"Warning: The provided hash doesn't appear to be a valid {hash_type} hash.")
        response = input("Do you want to continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    print(f"\nStarting hash cracking process...")
    print(f"Hash type: {hash_type}")
    print(f"Wordlist: {wordlist_path}")
    
    start_time = time.time()
    result = crack_hash(wordlist_path, hash_to_crack, hash_type)
    total_time = time.time() - start_time
    
    if result:
        print(f"Found cleartext password: {result}")
        print(f"Time taken: {total_time:.2f} seconds")
    else:
        print(f"\nPassword not found in the wordlist.")
        print(f"Time taken: {total_time:.2f} seconds")
        print("Try with a different wordlist or hash type.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

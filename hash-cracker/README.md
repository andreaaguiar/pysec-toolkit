# Hash Cracker Tool

## Description

The `hash_cracker.py` script is a versatile hash cracking utility. It uses a dictionary-based approach to find plaintext passwords corresponding to their hash values, supporting multiple hash algorithms including MD5, SHA-1, SHA-256, and SHA-512.

## Features

- **Multiple Hash Algorithm Support** - Cracks MD5, SHA-1, SHA-256, and SHA-512 hashes
- **Wordlist-based cracking** - Tests passwords from a provided wordlist
- **Command-Line Interface** - Supports both interactive mode and command-line arguments
- **Progress Tracking** - Shows real-time progress and speed metrics during cracking
- **Hash Validation** - Verifies that input hashes match the expected format
- **Error Handling** - Robust error handling for files, permissions, and interruptions
- **Performance Statistics** - Reports cracking speed and elapsed time

## Requirements

- Python 3.9+

## Usage

### Interactive Mode

Run the script in interactive mode:

```bash
python3 hash_cracker.py -i
```

When prompted:

1. Enter the path to your wordlist file
1. Enter the hash you want to crack
1. Enter the hash type (optional, defaults to MD5)

### Command-Line Mode

Run the script with command-line arguments:

```bash
python3 hash_cracker.py -w /path/to/wordlist.txt -H <hash-to-crack> -t <hash-type>
```

#### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-w, --wordlist` | Path to the wordlist file | Required |
| `-H, --hash` | Hash to crack | Required |
| `-t, --type` | Hash type (md5, sha1, sha256, sha512) | md5 |
| `-i, --interactive` | Run in interactive mode | False |

## How It Works

The script:

1. Takes a wordlist file path, target hash, and hash type as input
1. Validates that the hash format matches the expected format for the chosen algorithm
1. Reads each line from the wordlist with progress tracking
1. Calculates the hash of each word using the selected algorithm
1. Compares it against the target hash (case-insensitive)
1. Returns the matching plaintext word if found, along with performance statistics

## Example Output

### Command-Line Mode

```bash
Starting hash cracking process...
Hash type: md5
Wordlist: wordlist.txt
Progress: 1000/10000 (10.00%) - 5000.25 passwords/sec
Found cleartext password after 1234 attempts!
Found cleartext password: password
Time taken: 0.25 seconds
```

### Interactive Mode

```bash
Enter wordlist file location: wordlist.txt
Enter hash to be cracked: 5f4dcc3b5aa765d61d8327deb882cf99
Enter hash type (md5, sha1, sha256, sha512). Default is md5: md5

Starting hash cracking process...
Hash type: md5
Wordlist: wordlist.txt
Progress: 1000/10000 (10.00%) - 5000.25 passwords/sec
Found cleartext password after 1234 attempts!
Found cleartext password: password
Time taken: 0.25 seconds
```

## Wordlist Resources

Good password wordlists for hash cracking:

1. RockYou.txt - A classic wordlist containing millions of real passwords
1. [SecLists - Password Dictionaries](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - Comprehensive collection of password lists
1. [CrackStation Wordlists](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm) - Large-scale password dictionary

## Performance Tips

- For very large wordlists, consider splitting them into smaller files for more manageable processing
- The script provides real-time metrics on passwords per second to help gauge performance
- The most common passwords are often placed at the beginning of specialized wordlists to speed up cracking

## Future Improvements

While this script now includes many advanced features, it could be further enhanced by:

- Implementing hash salt handling for salted hashes
- Adding multithreading/multiprocessing for faster cracking
- Implementing hybrid attack modes (combining dictionary + rules)
- Adding support for rule-based password mutations
- Implementing resume functionality for interrupted cracking sessions
- Adding GPU acceleration for significantly faster hash computation

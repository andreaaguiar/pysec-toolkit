import sys
import os
import argparse
import concurrent.futures
import time
import requests
from datetime import datetime
from urllib.parse import urljoin

def check_directory(base_url, directory, timeout, protocol, extensions, headers):
    """Attempt to connect to a directory and return the result"""
    results = []
    
    # Handle directory with no extension (directory itself)
    if "" in extensions:
        url = urljoin(f"{protocol}://{base_url}/", directory)
        result = make_request(url, timeout, headers)
        if result:
            results.append(result)
    
    # Check with different extensions
    for ext in [e for e in extensions if e != ""]:
        url = urljoin(f"{protocol}://{base_url}/", f"{directory}{ext}")
        result = make_request(url, timeout, headers)
        if result:
            results.append(result)
            
    return results

def make_request(url, timeout, headers):
    """Make HTTP request and return result if valid"""
    try:
        response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if response.status_code != 404:  # Consider any non-404 as potentially interesting
            return {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'title': extract_title(response.text) if response.status_code == 200 else None
            }
        return None
    except requests.ConnectionError:
        return None
    except requests.Timeout:
        return None
    except Exception as e:
        print(f"Error checking {url}: {str(e)}")
        return None

def extract_title(html):
    """Extract title from HTML content"""
    try:
        start = html.find('<title>')
        if start != -1:
            end = html.find('</title>', start)
            if end != -1:
                return html[start + 7:end].strip()
    except:
        pass
    return None

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Directory enumeration tool')
    parser.add_argument('target', help='Target domain or URL to scan (e.g. example.com)')
    parser.add_argument('-w', '--wordlist', default='wordlist.txt', help='Wordlist file containing directories to check')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=float, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', help='Save results to this file')
    parser.add_argument('--https', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('-x', '--extensions', default='.html,.php,.txt,.asp,.aspx,/', 
                        help='Comma-separated list of extensions to check. Use "/" for directory, empty for no extension (default: .html,.php,.txt,.asp,.aspx,/)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output including content length')
    args = parser.parse_args()
    
    # Validate inputs
    if not args.target:
        print("Error: You must provide a target domain or URL.")
        sys.exit(1)
    
    if not os.path.exists(args.wordlist):
        print(f"Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)
    
    # Clean target URL (remove protocol if present)
    base_url = args.target
    if base_url.startswith('http://'):
        base_url = base_url[7:]
    elif base_url.startswith('https://'):
        base_url = base_url[8:]
        args.https = True
    
    # Strip trailing slash if present
    base_url = base_url.rstrip('/')
    
    # Read directory list
    try:
        with open(args.wordlist, 'r') as file:
            directories = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading wordlist file: {e}")
        sys.exit(1)
    
    # Process extensions
    extensions = [ext.strip() for ext in args.extensions.split(',')]
    if '/' in extensions:
        extensions.remove('/')
        extensions.append('')  # Empty string represents directory itself
    
    # Set up headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    protocol = "https" if args.https else "http"
    
    print(f"\n[+] Starting directory enumeration for {protocol}://{base_url}")
    print(f"[+] Loaded {len(directories)} directories to check")
    print(f"[+] Testing {len(extensions)} extensions: {', '.join([e if e else '(none)' for e in extensions])}")
    
    valid_results = []
    start_time = time.time()
    total_checks = len(directories) * len(extensions)
    processed = 0
    
    # Function to update progress
    def update_progress():
        nonlocal processed
        processed += 1
        if processed % 10 == 0:  # Update every 10 checks to avoid console spam
            progress = (processed / total_checks) * 100
            elapsed = time.time() - start_time
            dirs_per_second = processed / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[+] Progress: {processed}/{total_checks} ({progress:.1f}%) - {dirs_per_second:.1f} req/sec")
            sys.stdout.flush()
    
    # Process directories with thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_dir = {}
        
        for directory in directories:
            future = executor.submit(
                check_directory, 
                base_url, 
                directory, 
                args.timeout, 
                protocol,
                extensions,
                headers
            )
            future_to_dir[future] = directory
        
        for future in concurrent.futures.as_completed(future_to_dir):
            results = future.result()
            if results:
                for result in results:
                    status_color = "\033[92m" if result['status_code'] < 400 else "\033[93m"  # Green for 2xx/3xx, Yellow for others
                    status_msg = f"{status_color}Status: {result['status_code']}\033[0m"
                    
                    if args.verbose:
                        title_info = f" - {result['title']}" if result['title'] else ""
                        print(f"\n[+] Found: {result['url']} ({status_msg}, Size: {result['content_length']} bytes{title_info})")
                    else:
                        print(f"\n[+] Found: {result['url']} ({status_msg})")
                    
                    valid_results.append(result)
            
            update_progress()
    
    # Print summary
    elapsed_time = time.time() - start_time
    print(f"\n\n[+] Enumeration completed in {elapsed_time:.2f} seconds")
    print(f"[+] Found {len(valid_results)} valid resources")
    
    # Save results to file if requested
    if args.output and valid_results:
        try:
            with open(args.output, 'w') as f:
                f.write(f"# Directory enumeration results for {protocol}://{base_url}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in valid_results:
                    status_info = f"Status: {result['status_code']}"
                    size_info = f"Size: {result['content_length']} bytes"
                    title_info = f"Title: {result['title']}" if result['title'] else ""
                    
                    f.write(f"{result['url']} | {status_info} | {size_info}")
                    if title_info:
                        f.write(f" | {title_info}")
                    f.write("\n")
                
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

import argparse
import concurrent.futures
import os
import sys
import time

import requests
from bs4 import BeautifulSoup

from pysec import data_path
from pysec.report import ReportBuilder, add_report_arguments, write_report

DEFAULT_WORDLIST = data_path("subdomain_wordlist.txt")


def check_domain(subdomain, domain, timeout, protocol):
    """Attempt to connect to a subdomain and return the result"""
    url = f"{protocol}://{subdomain}.{domain}"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        return {
            'url': url,
            'status_code': response.status_code,
            'valid': True,
            'title': extract_title(response.text) if response.status_code == 200 else None
        }
    except requests.ConnectionError:
        return {'url': url, 'valid': False}
    except requests.Timeout:
        return {'url': url, 'valid': False, 'error': 'Timeout'}
    except Exception as e:
        return {'url': url, 'valid': False, 'error': str(e)}

def extract_title(html):
    """Extract title from HTML content"""
    soup = BeautifulSoup(html, 'html.parser')
    if soup.title:
        return soup.title.get_text(strip=True) or None
    return None

def add_arguments(parser):
    parser.add_argument('domain', help='Target domain to scan (e.g. example.com)')
    parser.add_argument('-w', '--wordlist', default=DEFAULT_WORDLIST, help='Wordlist file containing subdomains to check')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=float, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--https', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('--both-protocols', action='store_true', help='Check both HTTP and HTTPS')
    add_report_arguments(parser)


def run(args):
    # Validate inputs
    if not args.domain:
        print("Error: You must provide a domain name.")
        sys.exit(1)

    if not os.path.exists(args.wordlist):
        print(f"Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)

    report = ReportBuilder("subdomain", args.domain)

    # Read subdomain list
    try:
        with open(args.wordlist) as file:
            subdomains = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading wordlist file: {e}")
        sys.exit(1)

    print(f"\n[+] Starting subdomain enumeration for {args.domain}")
    print(f"[+] Loaded {len(subdomains)} subdomains to check")

    # Determine protocols to check
    protocols = []
    if args.https:
        protocols = ['https']
    elif args.both_protocols:
        protocols = ['http', 'https']
    else:
        protocols = ['http']

    total_checks = len(subdomains) * len(protocols)
    start_time = time.time()
    valid_domains = []
    processed = 0

    # Function to update progress
    def update_progress():
        nonlocal processed
        processed += 1
        progress = (processed / total_checks) * 100
        elapsed = time.time() - start_time
        domains_per_second = processed / elapsed if elapsed > 0 else 0
        sys.stdout.write(f"\r[+] Progress: {processed}/{total_checks} ({progress:.1f}%) - {domains_per_second:.1f} domains/sec")
        sys.stdout.flush()

    # Process domains with thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []

        for subdomain in subdomains:
            for protocol in protocols:
                futures.append(
                    executor.submit(check_domain, subdomain, args.domain, args.timeout, protocol)
                )

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['valid']:
                valid_domains.append(result)
                status_msg = f" (Status: {result['status_code']})"
                title_msg = f" - {result['title']}" if result['title'] else ""
                print(f"\n[+] Valid domain: {result['url']}{status_msg}{title_msg}")
            update_progress()

    # Print summary
    elapsed_time = time.time() - start_time
    print(f"\n\n[+] Enumeration completed in {elapsed_time:.2f} seconds")
    print(f"[+] Found {len(valid_domains)} valid subdomains")

    if getattr(args, "report", None):
        findings = [
            {"url": d["url"], "status_code": d.get("status_code"), "title": d.get("title")}
            for d in valid_domains
        ]
        built = report.build(
            summary={"subdomains_found": len(valid_domains)},
            findings=findings,
        )
        for path in write_report(built, args.report, args.report_format):
            print(f"[+] Report written to {path}")

def main(argv=None):
    parser = argparse.ArgumentParser(description='Subdomain enumeration tool')
    add_arguments(parser)
    run(parser.parse_args(argv))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

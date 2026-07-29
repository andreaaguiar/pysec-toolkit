import argparse
import json
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class WebVulnScanner:
    """
    Web Vulnerability Scanner

    This class scans a target website for common vulnerabilities including:
    1. XSS (Cross-Site Scripting) vulnerabilities
    2. SQL Injection vulnerabilities
    3. Open redirects
    4. Insecure headers
    5. Directory listing
    """

    XSS_MARKER = "pysecXSS31337"
    XSS_PAYLOADS = [
        f"<script>{XSS_MARKER}</script>",
        f'"><img src=x onerror={XSS_MARKER}>',
        f"'><svg onload={XSS_MARKER}>",
    ]
    SQL_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "' UNION SELECT 1,2,3,4 --",
    ]
    SQL_ERRORS = [
        "SQL syntax",
        "mysql_fetch_array",
        "ORA-01756",
        "SQLSTATE[42000]",
        "Microsoft SQL Native Client error",
        "PostgreSQL query failed",
    ]

    def __init__(self, url, output=None, cookies=None, threads=5, user_agent=None):
        if not urlparse(url).scheme:
            url = "https://" + url
        parsed = urlparse(url)
        self.target_url = url
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.visited_urls = set()
        self.vulnerable_urls = set()
        self.forms = []
        self.output_file = output
        self.cookies = {}
        self.threads = threads
        self.results = {
            "xss": [],
            "sqli": [],
            "open_redirect": [],
            "insecure_headers": [],
            "directory_listing": []
        }

        # Set up cookies if provided
        if cookies:
            try:
                with open(cookies) as f:
                    cookie_data = f.read().strip()
                    cookie_pairs = cookie_data.split(';')
                    for pair in cookie_pairs:
                        if '=' in pair:
                            name, value = pair.strip().split('=', 1)
                            self.cookies[name] = value
            except Exception as e:
                print(f"Error loading cookies: {e}")

        # Set user agent
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def scan(self):
        """Main scanning method that orchestrates the whole process"""
        print(f"[+] Starting scan of {self.target_url} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # First crawl the site to find URLs
        print("[+] Crawling the website for links...")
        self._crawl_site(self.target_url)

        print(f"[+] Found {len(self.visited_urls)} unique URLs and {len(self.forms)} forms")

        # Now test each URL for vulnerabilities
        print("[+] Testing URLs for vulnerabilities...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._scan_url, url) for url in self.visited_urls]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error scanning URL: {e}")

        # Test each discovered form
        print("[+] Testing forms for vulnerabilities...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._scan_form, form) for form in self.forms]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error scanning form: {e}")

        # Check for insecure headers
        print("[+] Checking for insecure headers...")
        self._check_security_headers()

        # Save results if output file specified
        if self.output_file:
            self._save_results()

        # Print summary
        self._print_summary()
        print(f"[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _crawl_site(self, url, depth=2):
        """Crawl the website to discover URLs"""
        if depth <= 0 or url in self.visited_urls or not url.startswith(self.base_url):
            return

        self.visited_urls.add(url)

        try:
            response = requests.get(
                url,
                cookies=self.cookies,
                headers=self.headers,
                timeout=10,
                allow_redirects=True
            )

            # Check for directory listing
            if "Index of /" in response.text and response.status_code == 200:
                self.results["directory_listing"].append({
                    "url": url,
                    "details": "Directory listing detected"
                })

            # Parse the page for links
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)

                # Filter out external links, parameters, etc.
                if absolute_url.startswith(self.base_url) and '#' not in absolute_url:
                    if absolute_url not in self.visited_urls:
                        # Limit concurrent crawling by using recursion with reduced depth
                        self._crawl_site(absolute_url, depth-1)

            # Record any same-origin forms on the page
            for form in soup.find_all('form'):
                parsed_form = self._parse_form(form, url)
                if parsed_form and parsed_form not in self.forms:
                    self.forms.append(parsed_form)

        except Exception as e:
            print(f"[-] Error crawling {url}: {e}")

    def _parse_form(self, form, page_url):
        """Extract the action, method, and named fields from a form element."""
        action = urljoin(page_url, form.get('action') or page_url)
        if not action.startswith(self.base_url):
            return None

        method = (form.get('method') or 'get').strip().lower()
        if method not in ('get', 'post'):
            method = 'get'

        fields = {}
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name')
            if name:
                fields[name] = field.get('value') or 'test'

        if not fields:
            return None

        return {'action': action, 'method': method, 'fields': fields}

    def _scan_url(self, url):
        """Scan a single URL for multiple vulnerabilities"""
        self._check_xss(url)
        self._check_sql_injection(url)
        self._check_open_redirect(url)

    def _check_xss(self, url):
        """Check for reflected XSS by confirming the payload reflects as live markup"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return

        for param in query_params:
            for payload in self.XSS_PAYLOADS:
                test_params = query_params.copy()
                test_params[param] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{query_string}"

                try:
                    response = requests.get(
                        test_url,
                        cookies=self.cookies,
                        headers=self.headers,
                        timeout=10
                    )
                except Exception as e:
                    print(f"[-] Error testing XSS at {test_url}: {e}")
                    continue

                if self.XSS_MARKER in response.text and self._reflects_as_markup(response.text, self.XSS_MARKER):
                    self.results["xss"].append({
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "details": "Reflected XSS: payload reflected as unescaped markup"
                    })
                    print(f"[!] XSS vulnerability found at {url} in parameter {param}")
                    break

    @staticmethod
    def _reflects_as_markup(html_text, marker):
        """Return True if the marker parses as a real script element or event handler."""
        soup = BeautifulSoup(html_text, 'html.parser')

        # Marker inside an injected <script> element
        for script in soup.find_all('script'):
            if marker in script.get_text():
                return True

        # Marker inside an event-handler attribute (onerror, onload, and similar)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if not attr.lower().startswith('on'):
                    continue
                attr_value = ' '.join(value) if isinstance(value, list) else str(value)
                if marker in attr_value:
                    return True

        return False

    @classmethod
    def _response_sql_error(cls, text):
        """Return the first known SQL error signature found in the text, or None."""
        for error in cls.SQL_ERRORS:
            if error in text:
                return error
        return None

    def _check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return

        for param in query_params:
            for payload in self.SQL_PAYLOADS:
                test_params = query_params.copy()
                test_params[param] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{query_string}"

                try:
                    response = requests.get(
                        test_url,
                        cookies=self.cookies,
                        headers=self.headers,
                        timeout=10
                    )
                except Exception as e:
                    print(f"[-] Error testing SQL injection at {test_url}: {e}")
                    continue

                error = self._response_sql_error(response.text)
                if error:
                    self.results["sqli"].append({
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "error": error,
                        "details": "Possible SQL injection detected"
                    })
                    print(f"[!] SQL injection vulnerability found at {url} in parameter {param}")
                    break

    def _check_open_redirect(self, url):
        """Check for open redirect vulnerabilities"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)

        redirect_payloads = [
            "//example.com",
            "https://example.com",
            "http://example.com"
        ]

        redirect_params = [
            "redirect", "url", "next", "goto", "target", "destination",
            "redirect_uri", "redirect_url", "returnUrl"
        ]

        # If URL has parameters, test each parameter
        if query_params:
            for param in query_params:
                # Only test likely redirect parameters
                if param.lower() in redirect_params or "redir" in param.lower() or "url" in param.lower():
                    for payload in redirect_payloads:
                        test_params = query_params.copy()
                        test_params[param] = [payload]

                        query_string = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = f"{base_url}?{query_string}"

                        try:
                            response = requests.get(
                                test_url,
                                cookies=self.cookies,
                                headers=self.headers,
                                timeout=10,
                                allow_redirects=False
                            )

                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if "example.com" in location:
                                    self.results["open_redirect"].append({
                                        "url": url,
                                        "parameter": param,
                                        "payload": payload,
                                        "redirect_url": location,
                                        "details": "Open redirect vulnerability detected"
                                    })
                                    print(f"[!] Open redirect vulnerability found at {url} in parameter {param}")
                                    break
                        except Exception as e:
                            print(f"[-] Error testing open redirect at {test_url}: {e}")

    def _scan_form(self, form):
        """Test a single form for XSS and SQL injection"""
        self._check_form_xss(form)
        self._check_form_sqli(form)

    def _submit_form(self, form, data):
        """Submit a form with the given field data and return the response, or None."""
        try:
            if form['method'] == 'post':
                return requests.post(
                    form['action'],
                    data=data,
                    cookies=self.cookies,
                    headers=self.headers,
                    timeout=10
                )
            return requests.get(
                form['action'],
                params=data,
                cookies=self.cookies,
                headers=self.headers,
                timeout=10
            )
        except Exception as e:
            print(f"[-] Error submitting form to {form['action']}: {e}")
            return None

    def _check_form_xss(self, form):
        """Inject XSS payloads into each form field and confirm live reflection"""
        for field in form['fields']:
            for payload in self.XSS_PAYLOADS:
                data = dict(form['fields'])
                data[field] = payload

                response = self._submit_form(form, data)
                if response is None:
                    continue

                if self.XSS_MARKER in response.text and self._reflects_as_markup(response.text, self.XSS_MARKER):
                    self.results["xss"].append({
                        "url": form['action'],
                        "parameter": field,
                        "payload": payload,
                        "details": f"Reflected XSS in {form['method'].upper()} form field"
                    })
                    print(f"[!] XSS vulnerability found in form at {form['action']} in field {field}")
                    break

    def _check_form_sqli(self, form):
        """Inject SQL payloads into each form field and check for SQL errors"""
        for field in form['fields']:
            for payload in self.SQL_PAYLOADS:
                data = dict(form['fields'])
                data[field] = payload

                response = self._submit_form(form, data)
                if response is None:
                    continue

                error = self._response_sql_error(response.text)
                if error:
                    self.results["sqli"].append({
                        "url": form['action'],
                        "parameter": field,
                        "payload": payload,
                        "error": error,
                        "details": f"Possible SQL injection in {form['method'].upper()} form field"
                    })
                    print(f"[!] SQL injection vulnerability found in form at {form['action']} in field {field}")
                    break

    def _check_security_headers(self):
        """Check for missing security headers"""
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header"
        }

        try:
            response = requests.get(
                self.target_url,
                cookies=self.cookies,
                headers=self.headers,
                timeout=10
            )

            missing_headers = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    missing_headers.append({
                        "header": header,
                        "issue": message
                    })

            if missing_headers:
                self.results["insecure_headers"].append({
                    "url": self.target_url,
                    "missing_headers": missing_headers,
                    "details": f"Missing {len(missing_headers)} security headers"
                })
                print(f"[!] Missing security headers at {self.target_url}")
        except Exception as e:
            print(f"[-] Error checking security headers: {e}")

    def _save_results(self):
        """Save scan results to a file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    "target": self.target_url,
                    "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "results": self.results
                }, f, indent=4)
            print(f"[+] Results saved to {self.output_file}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")

    def _print_summary(self):
        """Print a summary of findings"""
        print("\n--- SCAN SUMMARY ---")
        print(f"Target URL: {self.target_url}")
        print(f"URLs scanned: {len(self.visited_urls)}")
        print(f"Forms tested: {len(self.forms)}")
        print(f"XSS vulnerabilities: {len(self.results['xss'])}")
        print(f"SQL injection vulnerabilities: {len(self.results['sqli'])}")
        print(f"Open redirect vulnerabilities: {len(self.results['open_redirect'])}")
        print(f"Directory listing issues: {len(self.results['directory_listing'])}")
        print(f"Security header issues: {len(self.results['insecure_headers'])}")
        print("-------------------\n")


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-c', '--cookies', help='File containing cookies (format: name=value; name2=value2)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-a', '--user-agent', help='Custom User-Agent string')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    scanner = WebVulnScanner(
        url=args.url,
        output=args.output,
        cookies=args.cookies,
        threads=args.threads,
        user_agent=args.user_agent
    )

    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)

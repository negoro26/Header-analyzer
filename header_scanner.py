import sys
import requests
import argparse

client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Upgrade-Insecure-Requests': '1'
}

security_headers = {
    'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
    'Content-Security-Policy': 'Mitigates XSS and data injection',
    'X-Content-Type-Options': 'Prevents MIME sniffing (should be "nosniff")',
    'X-Frame-Options': 'Prevents clickjacking (should be "DENY" or "SAMEORIGIN")',
    'X-XSS-Protection': 'Legacy XSS protection (modern browsers ignore)',
    'Referrer-Policy': 'Controls referrer information',
    'Permissions-Policy': 'Controls browser feature access'
}

sensitive_headers = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Runtime',
    'X-Version'
]

def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url

def make_request(url, timeout=10, insecure=False):
    try:
        response = requests.head(
            url,
            headers=client_headers,
            timeout=timeout,
            verify=not insecure,
            allow_redirects=True
        )
        if response.status_code in (400, 403, 405, 501):
            raise requests.exceptions.RequestException("HEAD most likely not supported")
        return response
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError):
        try:
            response = requests.get(
                url,
                headers=client_headers,
                timeout=timeout,
                verify=not insecure,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            raise e

def analyze_security_headers(headers):
    print("\n" + "=" * 60)
    print("[+] Analyzing security headers...")
    print("=" * 60)

    present = []
    missing = []

    for header,description in security_headers.items():
        if header in headers:
            present.append((header, headers[header]))
        else:
            missing.append((header, description))

    if present:
        print("Security headers present:")
        for header, value in present:
            if header == 'X-Content-Type-Options' and value.lower() != 'nosniff':
                print(f"  • {header} → {value} (should be 'nosniff')")
            elif header == 'X-Frame-Options' and value.upper() not in ('DENY', 'SAMEORIGIN'):
                print(f"  • {header} → {value} (should be 'DENY' or 'SAMEORIGIN')")
            else:
                print(f"  • {header} → {value}")
    else:
        print("All security headers missing")

    if missing:
        print("Security headers missing:")
        for header, description in missing:
            print(f"  • {header} → {description}")
    else:
        print("All security headers present")

def analyze_sensitive_headers(headers):
    print("\n" + "=" * 60)
    print("[+] Analyzing sensitive headers...")
    print("=" * 60)

    found = []
    for header in sensitive_headers:
        if header in headers:
            found.append((header, headers[header]))

    if found:
        print("Potentially sensitive headers found:")
        for header, value in found:
            print(f"  • {header}: {value}")
        print("These headers might reveal technology, version or framework details")
    else:
        print("[+] No sensitive headers present")


def print_headers(headers):
    print("\n" + "=" * 60)
    print("[+] RAW RESPONSE HEADERS")
    print("=" * 60)
    for key, value in headers.items():
        print(f"{key}: {value}")

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='HTTP Header Security Analyzer'
        )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--insecure', '-k', action='store_true',
                        help='Skip SSL certificate verification')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')

    args = parser.parse_args()
    url = validate_url(args.url.strip())

    try:
        response = make_request(url, insecure=args.insecure, timeout=args.timeout)

        print(f"[+] Target: {url}")
        print(f"[+] Status Code: {response.status_code}")
        if response.history:
            print(f"[+] Redirected {len(response.history)} times")
            print(f"    Final URL: {response.url}")

        print_headers(response.headers)
        analyze_security_headers(response.headers)
        analyze_sensitive_headers(response.headers)

        print("\n" + "=" * 60)
        print("[+] Scan completed successfully!")
        print("=" * 60)
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL Error: {e}")
        print("    Use --insecure to bypass certificate validation")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[!] Request timed out after {args.timeout} seconds")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("[!] Failed to connect to the server")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
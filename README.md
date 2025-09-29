# Header-analyzer

HTTP Header Security Analyzer – a simple Python CLI that inspects a target URL’s HTTP response headers. It prints the raw headers, highlights key security headers (present/missing/incorrect values), and flags potentially sensitive headers that may leak implementation details.

## Features

- Sends a HEAD request first, falling back to GET if needed (with redirects followed).
- Dumps raw response headers for visibility.
- Checks common security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy
  - X-Content-Type-Options (expects "nosniff")
  - X-Frame-Options (expects "DENY" or "SAMEORIGIN")
  - X-XSS-Protection (legacy)
  - Referrer-Policy
  - Permissions-Policy
- Flags disclosure-prone headers (e.g., Server, X-Powered-By, X-Runtime).
- Customizable request headers (override User-Agent, add -H "Key: Value", or start with --no-default-headers).
- Optional TLS verification bypass (-k/--insecure) and configurable timeout.

## Requirements

- Python 3.8+ (recommended)
- requests

## Installation

PowerShell (Windows):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install requests
```

Bash (macOS/Linux):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install requests
```

## Usage

Basic:

```powershell
python header_scanner.py <url>
```

Options:

- -k, --insecure
  - Skip SSL certificate verification.
- --timeout <int>
  - Request timeout in seconds (default: 10).
- --user-agent "<string>"
  - Override the User-Agent header.
- -H, --header "Key: Value"
  - Add a custom request header (repeatable).
- --no-default-headers
  - Do not include the built-in client headers (start from an empty set).

Examples:

```powershell
# Simple scan (scheme is optional; https:// is assumed if missing)
python header_scanner.py example.com

# Disable SSL verification and shorten the timeout
python header_scanner.py https://example.com -k --timeout 5

# Override User-Agent and add custom headers
python header_scanner.py https://example.com --user-agent "MyScanner/1.0" `
  -H "Accept-Language: en-US" -H "Cache-Control: no-cache"

# Start with no defaults, then add only what you want
python header_scanner.py https://example.com --no-default-headers -H "User-Agent: curl/8.0"
```

## Output overview

- Target and status information (including redirect count and final URL).
- RAW RESPONSE HEADERS section (verbatim headers).
- Security headers analysis:
  - Present headers listed with values; known expectations are validated:
    - X-Content-Type-Options should be "nosniff".
    - X-Frame-Options should be "DENY" or "SAMEORIGIN".
  - Missing headers listed with brief descriptions.
- Sensitive headers analysis:
  - Lists any headers like Server or X-Powered-By that may disclose stack details.

## How it works

- Attempts a HEAD request with allow_redirects=True and a realistic header set.
- If HEAD response is not OK or unsupported, automatically retries with GET.
- TLS verification is enabled by default; use -k/--insecure to bypass.
- Default timeout is 10 seconds (configurable via --timeout).

## Configuration and extensibility

You can adjust checks directly in header_scanner.py:

- client_headers: defaults used for requests.
- security_headers: map of header -> purpose/description.
- sensitive_headers: list of headers considered disclosure-prone.

To add a new check, extend security_headers or sensitive_headers accordingly.

## Development

- Single-file CLI: header_scanner.py (argparse-based).
- No linter or tests are currently configured.

Recommended local run:

```powershell
.\.venv\Scripts\Activate.ps1
python header_scanner.py https://example.com
```

## License

Add your license of choice (e.g., MIT) as LICENSE in the repo and reference it here.

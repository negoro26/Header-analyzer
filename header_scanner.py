import sys
import requests

client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': '1'
}

def main():
    if len(sys.argv) < 2:
        print("Usage: python header_scanner.py <url>")
        sys.exit(1)
        
    url = sys.argv[1].strip()
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    try:
        response = requests.get(url, headers=client_headers)
        print(response.headers)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
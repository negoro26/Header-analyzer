import sys
import requests

def main():
    if len(sys.argv) < 2:
        print("Usage: python header_scanner.py <url>")
        sys.exit(1)
        
    url = sys.argv[1].strip()
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    try:
        response = requests.get(url)
        print(f"Found {len(headers)} headers:")
        print(response.headers)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
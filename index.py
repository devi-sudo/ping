import requests
import time

# Configuration
website_url = "https://fine-sunny-weeder.glitch.me/"  # Replace with your website's URL
interval_in_minutes = 5  # Ping every 5 minutes

def ping_website():
    try:
        print(f"Pinging {website_url}...")
        response = requests.get(website_url, timeout=10)
        if response.status_code == 200:
            print(f"Ping successful! Status: {response.status_code}")
        else:
            print(f"Ping received a non-200 status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Ping failed! Error: {e}")

def main():
    while True:
        ping_website()
        time.sleep(interval_in_minutes * 60)

if __name__ == "__main__":
    main()

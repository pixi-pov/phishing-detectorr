import whois
from datetime import datetime

try:
    domain = "google.com"
    print(f"Checking WHOIS for {domain}...")
    w = whois.whois(domain)
    print(f"Creation Date: {w.creation_date}")
    if isinstance(w.creation_date, list):
        print(f"Age in days: {(datetime.now() - w.creation_date[0]).days}")
    else:
        print(f"Age in days: {(datetime.now() - w.creation_date).days}")
except Exception as e:
    print(f"Error: {e}")

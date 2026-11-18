"""Step 1: Download the CISA KEV catalog and print how many entries it has.

Run:  python 01_kev_download.py
Needs: pip install requests
"""
import json
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

resp = requests.get(KEV_URL, timeout=60)
resp.raise_for_status()
data = resp.json()

vulns = data["vulnerabilities"]
print(f"Catalog version : {data.get('catalogVersion')}")
print(f"Date released   : {data.get('dateReleased')}")
print(f"Total entries   : {len(vulns)}")

# Peek at the fields so you know what you can use later
print("\nFields in each entry:", list(vulns[0].keys()))
print("\nExample entry:")
print(json.dumps(vulns[0], indent=2))

# Save a local copy so you don't have to re-download while developing
with open("kev.json", "w", encoding="utf-8") as f:
    json.dump(data, f)
print("\nSaved to kev.json")

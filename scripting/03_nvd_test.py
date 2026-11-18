"""Step 3 (after you get your key): test the NVD API with one CVE.

1. Request a free key: https://nvd.nist.gov/developers/request-an-api-key
   (click the link in the confirmation email to activate it)
2. In Command Prompt:   set NVD_API_KEY=your-key-here
3. Run:  python 03_nvd_test.py
Needs: pip install requests
"""
import os
import requests

API_KEY = os.environ.get("NVD_API_KEY")  # works without a key too, but much slower limits
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

headers = {"apiKey": API_KEY} if API_KEY else {}
print("Using API key" if API_KEY else "No key set (5 requests / 30 s limit)")

r = requests.get(URL, params={"cveId": "CVE-2021-44228"}, headers=headers, timeout=60)
print("HTTP", r.status_code)
r.raise_for_status()

cve = r.json()["vulnerabilities"][0]["cve"]
print("ID        :", cve["id"])
print("Published :", cve["published"])

# CVSS can be missing, so always check
metrics = cve.get("metrics", {})
for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
    if metrics.get(ver):
        d = metrics[ver][0]["cvssData"]
        print(f"{ver}: score {d['baseScore']}")
        break
else:
    print("No CVSS score available")

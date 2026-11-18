"""Probe ransomware.live's free API: does it fill the gaps in our RansomLook data?

Run:  python probe_ransomwarelive.py
Needs: pip install requests ; ransomlook_raw.json in the same folder.

Answers four questions and prints a summary:
  1. Which API address works?
  2. Do victim records include country (and sector)? How often?
  3. Do its victims overlap with our RansomLook posts (same group + same name)?
  4. Do group records mention CVEs or ATT&CK techniques?
Saves: rl_live_victims.json, rl_live_group_sample.json  (raw samples to look at)

Before using this data in your project, read ransomware.live's Terms & Conditions page and
credit them on the dashboard.
"""
import json, re, time
from collections import Counter
import requests

import os
UA = {"User-Agent": "ransomware-landscape-student-project", "Accept": "application/json"}
# Ransomware.live's terms recommend api-pro.ransomware.live with a free personal token.
# Read the terms page for the exact base URL and header name, then set them here or as env vars:
#   set RL_BASE=https://api-pro.ransomware.live      set RL_TOKEN=your-token
TOKEN = os.environ.get("RL_TOKEN")
TOKEN_HEADER = "X-API-KEY"        # UNVERIFIED header name: confirm in the terms/docs and change if different
if TOKEN:
    UA[TOKEN_HEADER] = TOKEN
BASES = ([os.environ["RL_BASE"]] if os.environ.get("RL_BASE") else []) + \
        ["https://api.ransomware.live/v2", "https://api.ransomware.live"]   # first one that works is used
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def get(base, path):
    r = requests.get(f"{base}{path}", headers=UA, timeout=60)
    print(f"  GET {base}{path} -> HTTP {r.status_code}")
    if r.status_code == 429:
        print("  rate limited: wait a minute and run again")
    r.raise_for_status()
    return r.json()


base, victims = None, None
for b in BASES:
    try:
        victims = get(b, "/recentvictims")
        base = b
        break
    except Exception as e:
        print("  failed:", str(e)[:100])
if victims is None:
    raise SystemExit("No ransomware.live address worked. Open https://www.ransomware.live/apidocs, "
                     "find the base URL, and put it first in BASES.")
if isinstance(victims, dict):
    victims = victims.get("victims") or next((v for v in victims.values() if isinstance(v, list)), [])
json.dump(victims, open("rl_live_victims.json", "w", encoding="utf-8"), indent=2)
print(f"\n1) Using {base}  ->  {len(victims)} recent victims")

print("\n2) Victim fields:", sorted(victims[0].keys()))
n = len(victims)
for field in ("country", "sector", "activity", "description", "website"):
    have = sum(1 for v in victims if v.get(field) not in (None, "", "Not Found"))
    if any(field in v for v in victims):
        print(f"   {field:12s} filled in {have}/{n} ({have * 100 // n}%)")
print("   example:", json.dumps(victims[0], ensure_ascii=False)[:400])
print("   top countries:", Counter(v.get("country") for v in victims).most_common(6))

# 3) overlap with our RansomLook posts
mine = json.load(open("ransomlook_raw.json", encoding="utf-8"))
ours = {(norm(p["group_name"]), norm(p["post_title"])) for p in mine}
theirs = {(norm(v.get("group") or v.get("group_name")), norm(v.get("victim") or v.get("post_title")))
          for v in victims}
print(f"\n3) Overlap: {len(ours & theirs)} of {len(theirs)} ransomware.live victims also in our RansomLook "
      "file (only recent days can overlap)")
print("   group-name overlap:", len({g for g, _ in ours} & {g for g, _ in theirs}), "groups in common")

# 4) group details: any CVEs / techniques?
group = next((v.get("group") or v.get("group_name") for v in victims if v.get("group") or v.get("group_name")), None)
for g in ["akira", group]:
    if not g:
        continue
    time.sleep(1)
    try:
        info = get(base, f"/group/{g}")
    except Exception as e:
        print("   group lookup failed:", str(e)[:100])
        continue
    json.dump(info, open("rl_live_group_sample.json", "w", encoding="utf-8"), indent=2)
    blob = json.dumps(info)
    print(f"\n4) /group/{g} fields:", sorted(info.keys()) if isinstance(info, dict) else type(info))
    print("   CVE IDs found in group record:", sorted(set(CVE_RE.findall(blob))) or "none")
    print("   mentions TTPs/techniques:", bool(re.search(r"ttp|technique|T1\d{3}", blob, re.I)))
    break
print("\nPaste this output back to me (or open rl_live_victims.json / rl_live_group_sample.json).")

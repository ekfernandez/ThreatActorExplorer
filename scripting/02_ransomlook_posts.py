"""Step 2: Fetch ~30 days of RansomLook posts and inspect the raw fields.

Run:  python 02_ransomlook_posts.py
Needs: pip install requests

NOTE: I could not verify RansomLook's API paths from its docs, so this script
tries a few likely endpoints in order and tells you which one worked.
If none work, open https://www.ransomlook.io in your browser, find the API/doc
link, and put the correct path at the top of CANDIDATES.
"""
import json
import requests
from collections import Counter

BASE = "https://www.ransomlook.io"
DAYS = 30

CANDIDATES = [
    f"{BASE}/api/last/{DAYS}",   # posts from the last N days (most likely)
    f"{BASE}/api/recent",        # most recent posts (fallback)
]

HEADERS = {"User-Agent": "ransomware-landscape-student-project", "Accept": "application/json"}

posts = None
for url in CANDIDATES:
    try:
        r = requests.get(url, headers=HEADERS, timeout=60)
        print(f"{url} -> HTTP {r.status_code}")
        if r.status_code == 200:
            posts = r.json()
            print(f"Using: {url}\n")
            break
    except Exception as e:
        print(f"{url} -> failed: {e}")

if posts is None:
    raise SystemExit("No endpoint worked. See the note at the top of this file.")

# Save the raw response so you can study it
with open("ransomlook_raw.json", "w", encoding="utf-8") as f:
    json.dump(posts, f, indent=2)
print("Saved raw response to ransomlook_raw.json")

# Handle list-of-posts or a dict wrapper
items = posts if isinstance(posts, list) else posts.get("posts", posts)
if isinstance(items, dict):
    items = list(items.values())

print(f"\nNumber of posts returned: {len(items)}")
if items and isinstance(items[0], dict):
    print("\nFields in a post:", list(items[0].keys()))
    print("\nExample post:")
    print(json.dumps(items[0], indent=2))

    # Which group names appear most? (field name may differ; try common ones)
    for key in ("group_name", "group", "actor"):
        if key in items[0]:
            counts = Counter(p.get(key) for p in items)
            print(f"\nTop 10 by '{key}':")
            for name, n in counts.most_common(10):
                print(f"  {name}: {n}")
            break

    # KEY QUESTION for your project: do posts include sector or country?
    wanted = ("country", "sector", "industry", "activity", "website", "discovered")
    present = [k for k in items[0].keys() if any(w in k.lower() for w in wanted)]
    print("\nFields useful for 'target diversity':", present or "NONE FOUND - note this for your slides")

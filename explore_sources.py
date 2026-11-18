"""Explore MITRE ATT&CK and CISA advisories for group -> CVE / technique info.

Run:  python explore_sources.py mitre
      python explore_sources.py cisa
      python explore_sources.py all
Needs: pip install requests ; ransomlook_raw.json in the same folder.

Outputs (CSV, open in Excel):
  mitre_groups.csv      RansomLook groups that exist in ATT&CK, with technique counts + any CVEs
  advisory_cves.csv     CVEs and ATT&CK technique IDs found in each CISA advisory
  group_cves_candidates.csv   rows in the same format as group_cves.csv (verified=no, REVIEW BY HAND)

If the CISA listing page can't be parsed, put advisory URLs (one per line) in advisory_urls.txt.
"""
import csv, json, os, re, sys, time
from collections import Counter
import requests

UA = {"User-Agent": "ransomware-landscape-student-project"}
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX_FILE = "enterprise-attack.json"
LISTING = "https://www.cisa.gov/stopransomware/newsroom"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
TID_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def my_groups():
    posts = json.load(open("ransomlook_raw.json", encoding="utf-8"))
    return Counter(p["group_name"].strip().lower() for p in posts)


# ---------------------------------------------------------------- MITRE
def mitre():
    if not os.path.exists(STIX_FILE):
        print("Downloading ATT&CK data (~55 MB, one time)...")
        r = requests.get(STIX_URL, headers=UA, timeout=300)
        r.raise_for_status()
        open(STIX_FILE, "wb").write(r.content)
    objs = json.load(open(STIX_FILE, encoding="utf-8"))["objects"]
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in live}
    mine = my_groups()
    mine_norm = {norm(g): g for g in mine}

    def tid(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")

    # techniques used by each group (directly)
    uses = {}
    for o in live:
        if o["type"] == "relationship" and o["relationship_type"] == "uses" \
                and o["source_ref"].startswith("intrusion-set--") and o["target_ref"].startswith("attack-pattern--"):
            t = by_id.get(o["target_ref"])
            if t:
                uses.setdefault(o["source_ref"], []).append(f"{tid(t)} {t['name']}")

    rows = []
    for g in live:
        if g["type"] != "intrusion-set":
            continue
        names = [g["name"]] + g.get("aliases", [])
        match = next((mine_norm[norm(n)] for n in names if norm(n) in mine_norm), None)
        if not match:
            continue
        cves = sorted(set(CVE_RE.findall(json.dumps(g))))
        techs = uses.get(g["id"], [])
        rows.append([match, g["name"], len(techs), ";".join(cves), " | ".join(techs[:5])])
    rows.sort(key=lambda r: -mine[r[0]])

    print(f"\nMITRE ATT&CK: {len(rows)} of your {len(mine)} RansomLook groups appear as ATT&CK groups")
    for r in rows:
        print(f"  {r[0]:15s} posts={mine[r[0]]:3d}  techniques={r[2]:3d}  CVEs={r[3] or 'none'}")
    # software entries (ransomware families) with matching names
    sw = [o["name"] for o in live if o["type"] in ("malware", "tool")
          and any(norm(n) in mine_norm for n in [o["name"]] + o.get("x_mitre_aliases", []))]
    print("  Also matches as ATT&CK software (malware families):", sw or "none")
    with open("mitre_groups.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ransomlook_group", "attack_group", "n_techniques", "cves_in_entry", "sample_techniques"])
        w.writerows(rows)
    print("  Saved mitre_groups.csv")
    print("  Takeaway: ATT&CK is good for TECHNIQUES (how groups operate), rarely for CVEs.")


# ---------------------------------------------------------------- CISA
def text_of(html):
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html))


def group_guess(title):
    t = re.sub(r"(?i)joint cybersecurity advisory:?|#?stopransom\w*:?|ransomware|\|.*$|cisa", "", title)
    return t.strip(" -:|").lower()


def cisa():
    urls = []
    if os.path.exists("advisory_urls.txt"):
        urls += [u.strip() for u in open("advisory_urls.txt") if u.strip().startswith("http")]
    else:
        print("Fetching CISA listing:", LISTING)
        try:
            html = requests.get(LISTING, headers=UA, timeout=60).text
            hrefs = re.findall(r'href="([^"]*cybersecurity-advisories/[^"#?]+)"', html)
            urls += ["https://www.cisa.gov" + h if h.startswith("/") else h for h in hrefs]
        except Exception as e:
            print("  could not fetch listing:", e)
    urls = list(dict.fromkeys(urls))
    if not urls:
        print("No advisory links found. Create advisory_urls.txt (one URL per line) from "
              f"{LISTING} and run again.")
        return
    print(f"{len(urls)} advisory pages to read")
    rows, cands = [], []
    for u in urls:
        try:
            html = requests.get(u, headers=UA, timeout=60).text
        except Exception as e:
            print("  failed", u, e)
            continue
        m = re.search(r"(?is)<title>(.*?)</title>", html)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else u
        txt = text_of(html)
        cves, tids = sorted(set(CVE_RE.findall(txt))), sorted(set(TID_RE.findall(txt)))
        print(f"  {title[:70]:70s} CVEs={len(cves):2d} techniques={len(tids)}")
        rows.append([title, u, ";".join(cves), ";".join(tids)])
        for c in cves:
            cands.append([group_guess(title), c, u, "no"])
        time.sleep(1)
    with open("advisory_cves.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["title", "url", "cves", "attack_techniques"])
        w.writerows(rows)
    with open("group_cves_candidates.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["group", "cve", "source", "verified"])
        w.writerows(cands)
    print("Saved advisory_cves.csv and group_cves_candidates.csv")
    print("REVIEW BY HAND: a CVE mentioned in an advisory may be a reference or mitigation, not proof the "
          "group exploited it. Fix the group names to match RansomLook, then copy good rows into group_cves.csv.")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("mitre", "all"):
        mitre()
    if which in ("cisa", "all"):
        cisa()

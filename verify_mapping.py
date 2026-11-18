"""Print the group -> CVE mapping with scores so it can be checked by hand.

Run:  python verify_mapping.py                         (default groups: akira play clop)
      python verify_mapping.py --groups akira rhysida play
Needs: group_cves.csv, kev.json, and (for CVSS / EPSS) ransomware.db after running pipeline.py.
Writes: outputs/mapping_check.md  (a table + a hand-check checklist you can paste into the README)
"""
import argparse, csv, json, os, re, sqlite3

ap = argparse.ArgumentParser()
ap.add_argument("--groups", nargs="+", default=["akira", "play", "clop"])
args = ap.parse_args()

kev = {v["cveID"]: v for v in json.load(open("kev.json", encoding="utf-8"))["vulnerabilities"]}
nvd, epss = {}, {}
if os.path.exists("ransomware.db"):
    con = sqlite3.connect("ransomware.db")
    try:
        nvd = {r[0]: r[1] for r in con.execute("SELECT cve, cvss FROM nvd")}
        epss = {r[0]: r[1] for r in con.execute("SELECT cve, epss FROM epss")}
    except sqlite3.OperationalError:
        pass

rows = [r for r in csv.DictReader(open("group_cves.csv", encoding="utf-8"))
        if r["group"].strip().lower() in args.groups]
fmt = lambda x, d=1: "n/a" if x is None else f"{x:.{d}f}"

table, summary = [], {}
for r in rows:
    g, c = r["group"].strip().lower(), r["cve"].strip()
    k = kev.get(c)
    m = re.search(r"https?://\S+", r["source"])
    url = m.group(0) if m else ""
    table.append((g, c, f"{k['vendorProject']} {k['product']}" if k else "NOT IN KEV",
                  nvd.get(c), epss.get(c), k["knownRansomwareCampaignUse"] if k else "-", r["verified"], url))
    s = summary.setdefault(g, {"n": 0, "cvss": [], "epss": [], "url": url})
    s["n"] += 1
    if nvd.get(c) is not None: s["cvss"].append(nvd[c])
    if epss.get(c) is not None: s["epss"].append(epss[c])

lines = ["| Group | CVE | Product (from KEV) | CVSS | EPSS | KEV ransomware use | Verified | Advisory |",
         "|---|---|---|---|---|---|---|---|"]
for g, c, prod, cv, ep, kr, ver, url in table:
    lines.append(f"| {g} | {c} | {prod} | {fmt(cv)} | {fmt(ep, 3)} | {kr} | {ver} | {url} |")
lines += ["", "| Group | Mapped CVEs | Avg CVSS | Avg EPSS |", "|---|---|---|---|"]
for g, s in summary.items():
    a = lambda v: None if not v else sum(v) / len(v)
    lines.append(f"| {g} | {s['n']} | {fmt(a(s['cvss']))} | {fmt(a(s['epss']), 3)} |")
lines += ["", "## Hand-check checklist (do this for each CVE row)", ""]
for g, s in summary.items():
    lines.append(f"- **{g}** advisory: {s['url'] or '(no URL in group_cves.csv)'}")
    lines.append("  - [ ] Every CVE above appears in the advisory text, and the product matches")
    lines.append("  - [ ] No CVE in the advisory is missing from the table")
    lines.append("  - [ ] CVSS matches https://nvd.nist.gov/vuln/detail/<CVE-ID>")
    lines.append("  - [ ] Advisory says the group *exploited* it (not just a mitigation or reference)")
text = "\n".join(lines)
print(text)
os.makedirs("outputs", exist_ok=True)
open("outputs/mapping_check.md", "w", encoding="utf-8").write(text + "\n")
print("\nSaved outputs/mapping_check.md")
if not nvd:
    print("NOTE: no CVSS found. Run `python pipeline.py` first (needs internet and your NVD key).")

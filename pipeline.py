"""Build ransomware.db from the three sources.

Run:  python pipeline.py
Needs: pip install requests
Inputs (same folder): ransomlook_raw.json, kev.json, group_cves.csv
Optional: set NVD_API_KEY (Command Prompt: set NVD_API_KEY=your-key)
"""
import csv, json, os, sqlite3, time
import requests

DB = "ransomware.db"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY = os.environ.get("NVD_API_KEY")


def cvss_from(cve):
    m = cve.get("metrics", {})
    for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(ver):
            d = m[ver][0]["cvssData"]
            return d["baseScore"], ver
    return None, None


def fetch_nvd(cve_id):
    headers = {"apiKey": KEY} if KEY else {}
    for _ in range(4):
        try:
            r = requests.get(NVD, params={"cveId": cve_id}, headers=headers, timeout=60)
        except requests.RequestException as e:
            print("  network error:", str(e)[:80])
            time.sleep(7)
            continue
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        time.sleep(7)  # rate limited: wait and retry
    return None


EPSS = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids):
    """EPSS = estimated probability (0-1) a CVE is exploited in the next 30 days. One call per 50 CVEs."""
    out = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        try:
            r = requests.get(EPSS, params={"cve": ",".join(chunk)}, timeout=60)
            r.raise_for_status()
            for row in r.json().get("data", []):
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]),
                                   row.get("date") or row.get("created"))
        except Exception as e:
            print("  EPSS request failed:", str(e)[:100])
    return out


def main():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS posts(
      misp_uuid TEXT PRIMARY KEY, group_name TEXT, victim TEXT, discovered TEXT,
      description TEXT, link TEXT, country TEXT, sector TEXT);
    CREATE TABLE IF NOT EXISTS kev(
      cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
      date_added TEXT, ransomware_use TEXT);
    CREATE TABLE IF NOT EXISTS group_cves(
      group_name TEXT, cve TEXT, source TEXT, verified TEXT, PRIMARY KEY(group_name, cve));
    CREATE TABLE IF NOT EXISTS epss(
      cve TEXT PRIMARY KEY, epss REAL, percentile REAL, score_date TEXT);
    CREATE TABLE IF NOT EXISTS nvd(
      cve TEXT PRIMARY KEY, cvss REAL, cvss_version TEXT, published TEXT, description TEXT);
    """)

    posts = json.load(open("ransomlook_raw.json", encoding="utf-8"))
    for p in posts:
        # INSERT OR IGNORE keeps existing country/sector labels when you re-run
        c.execute("INSERT OR IGNORE INTO posts(misp_uuid,group_name,victim,discovered,description,link)"
                  " VALUES(?,?,?,?,?,?)",
                  (p["misp_uuid"], p["group_name"].strip().lower(), p["post_title"],
                   p["discovered"], p["description"] or "", p["link"]))
    print("posts:", c.execute("SELECT COUNT(*) FROM posts").fetchone()[0])

    kev = json.load(open("kev.json", encoding="utf-8"))["vulnerabilities"]
    for v in kev:
        c.execute("INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?)",
                  (v["cveID"], v["vendorProject"], v["product"], v["vulnerabilityName"],
                   v["dateAdded"], v["knownRansomwareCampaignUse"]))
    print("kev:", len(kev))

    for row in csv.DictReader(open("group_cves.csv", encoding="utf-8")):
        c.execute("INSERT OR REPLACE INTO group_cves VALUES(?,?,?,?)",
                  (row["group"].strip().lower(), row["cve"].strip(), row["source"], row["verified"]))
    con.commit()

    # NVD lookups only for the CVEs we actually mapped (keeps rate limits painless)
    todo = [r[0] for r in c.execute(
        "SELECT DISTINCT cve FROM group_cves WHERE cve NOT IN (SELECT cve FROM nvd)")]
    for cve_id in todo:
        cve = fetch_nvd(cve_id)
        if cve:
            score, ver = cvss_from(cve)
            desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            c.execute("INSERT OR REPLACE INTO nvd VALUES(?,?,?,?,?)",
                      (cve_id, score, ver, cve["published"], desc))
            print(f"  {cve_id}: CVSS {score}")
        else:
            print(f"  {cve_id}: not found / failed")
        time.sleep(0.7 if KEY else 6.5)
    con.commit()

    mapped = [r[0] for r in c.execute("SELECT DISTINCT cve FROM group_cves")]
    scores = fetch_epss(mapped)
    for cve_id, (e, pct, d) in scores.items():
        c.execute("INSERT OR REPLACE INTO epss VALUES(?,?,?,?)", (cve_id, e, pct, d))
    print(f"EPSS: {len(scores)} of {len(mapped)} mapped CVEs scored")
    con.commit()
    print("done ->", DB)


if __name__ == "__main__":
    main()

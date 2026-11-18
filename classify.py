"""Label each victim post with country + sector using your local Ollama model (faster version).

Run:  python classify.py --limit 100     (quick timing test)
      python classify.py                 (everything that is still unlabeled; resumable)
      python classify.py --workers 4     (parallel; see note below)
Needs: pip install requests ; Ollama running ; model pulled.

Speed-ups in this version:
  * only groups with >= --min-group-posts posts (the ones the dashboard ranks), biggest first
  * posts with no description are marked Unknown without calling the model (use --include-empty to label them)
  * shorter prompts + capped output length
  * --workers N sends N requests at once. For this to really help, start Ollama with
    OLLAMA_NUM_PARALLEL=N (Windows: quit Ollama from the tray, then in Command Prompt:
        set OLLAMA_NUM_PARALLEL=4
        ollama serve
    ). Without it, extra workers just queue and give no speed-up.
"""
import argparse, json, re, sqlite3, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

MODEL = "qwen3.5:4b"   # check with: ollama list
SECTORS = ["Manufacturing", "Healthcare", "Finance", "Technology", "Education", "Government",
           "Retail", "Construction", "Legal/Professional Services", "Energy/Utilities",
           "Transportation/Logistics", "Hospitality", "Media/Entertainment", "Other", "Unknown"]

PROMPT = """Label a ransomware victim. Reply ONLY with JSON:
{{"country": "<English country name or Unknown>", "sector": "<one of: {sectors}>"}}
Use "Unknown" if unclear. A domain ending (.de .fr .ca .au) hints at the country.

Victim: {title}
Description: {desc}"""


def ask(url, title, desc):
    body = {"model": MODEL, "stream": False, "format": "json", "think": False, "keep_alive": "30m",
            "options": {"temperature": 0, "num_predict": 60},
            "messages": [{"role": "user", "content": PROMPT.format(
                sectors=", ".join(SECTORS), title=title, desc=(desc or "")[:300])}]}
    r = requests.post(url, json=body, timeout=180)
    r.raise_for_status()
    text = r.json()["message"]["content"]
    out = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
    sector = out.get("sector", "Unknown")
    if sector not in SECTORS:
        sector = "Other"
    return (str(out.get("country", "Unknown")).strip() or "Unknown"), sector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--min-group-posts", type=int, default=5)
    ap.add_argument("--include-empty", action="store_true")
    ap.add_argument("--url", default="http://localhost:11434/api/chat")
    ap.add_argument("--db", default="ransomware.db")
    a = ap.parse_args()

    con = sqlite3.connect(a.db)
    rows = con.execute("""
        SELECT p.misp_uuid, p.victim, p.description FROM posts p
        JOIN (SELECT group_name, COUNT(*) n FROM posts GROUP BY group_name) g USING(group_name)
        WHERE p.country IS NULL AND g.n >= ?
        ORDER BY g.n DESC, p.discovered DESC""", (a.min_group_posts,)).fetchall()

    # posts with nothing to read: mark Unknown instantly
    if not a.include_empty:
        empty = [r for r in rows if not (r[2] or "").strip()]
        for uid, _, _ in empty:
            con.execute("UPDATE posts SET country='Unknown', sector='Unknown' WHERE misp_uuid=?", (uid,))
        con.commit()
        rows = [r for r in rows if (r[2] or "").strip()]
        print(f"{len(empty)} posts had no description -> marked Unknown (no model call)")
    if a.limit:
        rows = rows[:a.limit]
    print(f"{len(rows)} posts to label with {MODEL}, workers={a.workers}")

    t0, done = time.time(), 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(ask, a.url, t, d): (u, t) for u, t, d in rows}
        for f in as_completed(futs):
            uid, title = futs[f]
            try:
                country, sector = f.result()
            except Exception as e:
                print("  skip", title[:30], "->", str(e)[:80])
                continue
            con.execute("UPDATE posts SET country=?, sector=? WHERE misp_uuid=?", (country, sector, uid))
            done += 1
            if done % 10 == 0:
                con.commit()
                rate = done / (time.time() - t0) * 60
                left = (len(rows) - done) / max(rate, 0.01)
                print(f"  {done}/{len(rows)}  {rate:.0f} posts/min  ~{left:.0f} min left  "
                      f"e.g. {title[:25]} -> {country} / {sector}")
    con.commit()
    print("done")


if __name__ == "__main__":
    main()

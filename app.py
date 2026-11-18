"""Ransomware Landscape Explorer - prototype dashboard.

Run:  streamlit run app.py
Needs: pip install streamlit pandas plotly requests
"""
import math, sqlite3
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

MODEL = "qwen3.5:4b"   # change if your model name differs
st.set_page_config(page_title="Ransomware Landscape Explorer", layout="wide")


@st.cache_data
def load():
    con = sqlite3.connect("ransomware.db")
    con.execute("CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, epss REAL, percentile REAL, score_date TEXT)")
    posts = pd.read_sql("SELECT * FROM posts", con)
    gc = pd.read_sql("SELECT g.group_name, g.cve, g.verified, n.cvss, e.epss, k.ransomware_use "
                     "FROM group_cves g LEFT JOIN nvd n ON n.cve=g.cve "
                     "LEFT JOIN epss e ON e.cve=g.cve "
                     "LEFT JOIN kev k ON k.cve=g.cve", con)
    return posts, gc


# Diversity = how many distinct countries / sectors a group hits, counting evenly-spread
# victims as more "different places" than a few outliers (effective number = exp(entropy)).
COUNTRY_CAP = 10   # a group reaching ~10 effective countries scores 1.0 on that part
SECTOR_CAP = 8     # ... and ~8 effective sectors scores 1.0
MIN_LABELS = 3     # need at least this many usable labels, else "not enough data"


def diversity_part(series, cap, ignore):
    s = series[series.notna() & ~series.isin(ignore)]
    if len(s) < MIN_LABELS:
        return None
    p = s.value_counts(normalize=True)
    eff = math.exp(-sum(x * math.log(x) for x in p))   # 1 category -> 1.0
    return min(eff / cap, 1.0)


def scoreboard(posts, gc, w_vol, w_div, w_sev, w_epss, min_posts):
    rows = []
    for g, d in posts.groupby("group_name"):
        if len(d) < min_posts:
            continue
        labeled = d[d.country.notna()]
        cpart = diversity_part(labeled.country, COUNTRY_CAP, ["Unknown"])
        spart = diversity_part(labeled.sector, SECTOR_CAP, ["Unknown", "Other"])
        parts = [x for x in (cpart, spart) if x is not None]
        div = sum(parts) / len(parts) if parts else None
        sub = gc[gc.group_name == g]
        # Severity (how bad if exploited) and likelihood (how likely to be exploited) are kept SEPARATE
        sev = (sub.cvss.mean() / 10) if len(sub) and sub.cvss.notna().any() else None    # average CVSS / 10
        lik = sub.epss.mean() if len(sub) and sub.epss.notna().any() else None           # average EPSS (already 0-1)
        rows.append(dict(group=g, posts=len(d),
                         countries=labeled.country[~labeled.country.isin(["Unknown"])].nunique(),
                         sectors=labeled.sector[~labeled.sector.isin(["Unknown", "Other"])].nunique(),
                         diversity=round(div, 2) if div is not None else None,
                         severity=round(sev, 2) if sev is not None else None,
                         epss=round(lik, 2) if lik is not None else None,
                         mapped_cves=len(sub)))
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["volume_n"] = df.posts / df.posts.max()
    df["score"] = (w_vol * df.volume_n + w_div * df.diversity.fillna(0)
                   + w_sev * df.severity.fillna(0) + w_epss * df.epss.fillna(0)) \
                  / (w_vol + w_div + w_sev + w_epss)
    df["score"] = (df.score * 100).round(1)
    return df.sort_values("score", ascending=False).reset_index(drop=True)


def briefing(facts):
    prompt = ("You are a threat intelligence analyst. Write a 120-word briefing for a non-expert "
              "audience using ONLY these facts. Do not invent numbers or CVEs. If a value is "
              "None, say the data is not available. The victims are CLAIMS posted on the group's "
              "leak site, not confirmed incidents: say 'claimed victims', never 'confirmed attacks'. "
              "'severity' is average CVSS (how bad a flaw is) and 'epss' is the average chance of "
              "exploitation in the next 30 days; describe them as two separate things."
              "\n\nFACTS:\n" + facts)
    r = requests.post("http://localhost:11434/api/chat", timeout=300, json={
        "model": MODEL, "stream": False, "think": False, "options": {"temperature": 0.2},
        "messages": [{"role": "user", "content": prompt}]})
    r.raise_for_status()
    return r.json()["message"]["content"]


posts, gc = load()
st.title("Global Ransomware Landscape Explorer")
st.caption(f"{len(posts):,} victim claims posted on leak sites, {posts.discovered.min()[:10]} to "
           f"{posts.discovered.max()[:10]}. These are claims made by the groups, not confirmed incidents. Prototype.")
st.caption("Sources: [Ransomware.live](https://www.ransomware.live) · "
           "[RansomLook](https://www.ransomlook.io) (CC BY 4.0) · "
           "[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · "
           "[NIST NVD](https://nvd.nist.gov) · [FIRST EPSS](https://www.first.org/epss) · "
           "[CISA #StopRansomware advisories](https://www.cisa.gov/stopransomware)")

with st.sidebar:
    st.header("Score weights")
    w_vol = st.slider("Attack volume (claims)", 0.0, 1.0, 0.4)
    w_div = st.slider("Target diversity", 0.0, 1.0, 0.2)
    w_sev = st.slider("Vulnerability severity (CVSS)", 0.0, 1.0, 0.2)
    w_epss = st.slider("Exploit likelihood (EPSS)", 0.0, 1.0, 0.2)
    min_posts = st.slider("Minimum claims to rank", 1, 30, 5)
    labeled = posts.country.notna().sum()
    st.metric("Posts labeled by AI", f"{labeled} / {len(posts)}")
    st.caption("Diversity = effective number of countries/sectors (needs 3+ labeled posts). "
               "Severity = average CVSS of a group's mapped CVEs (how bad). "
               "EPSS = average probability those CVEs are exploited in the next 30 days (how likely). "
               "Both need a CVE mapped to the group (group_cves.csv); others show as empty and count as 0.")

if w_vol + w_div + w_sev + w_epss == 0:
    st.stop()
board = scoreboard(posts, gc, w_vol, w_div, w_sev, w_epss, min_posts)
st.subheader("Threat actor scoreboard")
cols = ["group", "score", "posts", "countries", "sectors", "diversity", "severity", "epss", "mapped_cves"]
st.dataframe(board[cols].rename(columns={"posts": "claims"}), use_container_width=True, hide_index=True)
st.download_button("Download scoreboard (CSV)", board[cols].to_csv(index=False), "scoreboard.csv", "text/csv")
st.caption("Claims = victims a group has posted on its leak site. A posted name is not proof of a confirmed incident.")
st.plotly_chart(px.bar(board.head(15), x="score", y="group", orientation="h",
                       title="Top 15 groups by composite score").update_yaxes(autorange="reversed"),
                use_container_width=True)

st.subheader("Group profile")
g = st.selectbox("Group", board.group.tolist())
d = posts[posts.group_name == g]
c1, c2 = st.columns(2)
with c1:
    cc = d[d.country.notna() & (d.country != "Unknown")].country.value_counts().reset_index()
    cc.columns = ["country", "victims"]
    if len(cc):
        st.plotly_chart(px.bar(cc.head(10), x="victims", y="country", orientation="h",
                               title="Target countries"), use_container_width=True)
    else:
        st.info("Run classify.py to label countries.")
with c2:
    ss = d[d.sector.notna() & (d.sector != "Unknown")].sector.value_counts().reset_index()
    ss.columns = ["sector", "victims"]
    if len(ss):
        st.plotly_chart(px.bar(ss.head(10), x="victims", y="sector", orientation="h",
                               title="Target sectors"), use_container_width=True)
    else:
        st.info("Run classify.py to label sectors.")
sub = gc[gc.group_name == g]
st.markdown("**Mapped CVEs**")
if len(sub):
    st.dataframe(sub[["cve", "cvss", "epss", "ransomware_use", "verified"]], hide_index=True)
else:
    st.info("No CVEs mapped for this group yet (this is the known data gap).")
st.markdown("**Victims claimed by this group**")
st.caption("Names posted on the group's leak site. Claims only; not confirmed incidents.")
st.dataframe(d.sort_values("discovered", ascending=False)[["discovered", "victim", "country", "sector"]].head(15),
             hide_index=True, use_container_width=True)

if st.button("Generate AI briefing (local model)"):
    row = board[board.group == g].iloc[0].to_dict()
    facts = f"group={g}; rank={int(board.index[board.group == g][0]) + 1} of {len(board)}; " + \
            "; ".join(f"{'claims' if k == 'posts' else k}={v}" for k, v in row.items() if k not in ("group", "volume_n"))
    if len(sub):
        facts += "; mapped_cves=" + ", ".join(f"{r.cve}(CVSS {r.cvss}, EPSS {r.epss})" for r in sub.itertuples())
    try:
        with st.spinner("Asking local model..."):
            st.write(briefing(facts))
        st.caption("Generated from computed numbers only: " + facts)
    except Exception as e:
        st.error(f"Could not reach Ollama: {e}")

import streamlit as st
import requests
from bs4 import BeautifulSoup
import re
import tldextract
from graphviz import Digraph

st.set_page_config(page_title="TraceTheLink Redirect Analysis", layout="wide")

# ============================
# Modern Blue UI
# ============================

st.markdown("""
<style>

body {
    background: #0f1217;
}

h1, h2, h3 {
    color: #cfe3ff !important;
}

.df-box {
    background: #1a1d22;
    border: 1px solid #2d3643;
    padding: 18px;
    border-radius: 10px;
    margin-bottom: 22px;
}

.status-200 { color: #00ff8c; font-weight: 600; }
.status-301 { color: #4da6ff; font-weight: 600; }
.status-302 { color: #ffe44d; font-weight: 600; }
.status-error { color: #ff4f4f; font-weight: 600; }

.threat-low { background:#0f341c; padding:12px; border-radius:8px; color:#4dff94; }
.threat-med { background:#332a00; padding:12px; border-radius:8px; color:#ffea4d; }
.threat-high { background:#341111; padding:12px; border-radius:8px; color:#ff4d4d; }

.header-box {
    background:#0d1117;
    border:1px solid #334155;
    padding:12px;
    border-radius:6px;
    margin-bottom:10px;
}

</style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='color:#cfe3ff;'>🔗 Redirect Analyzer</h1>", unsafe_allow_html=True)

# ============================
# Helper Functions
# ============================

def explain_status(code):
    data = {
        200: "OK – Final content delivered.",
        301: "Moved Permanently – browser caches this redirect.",
        302: "Temporary Redirect – often used for tracking.",
        307: "Temporary redirect (method preserved).",
        308: "Permanent redirect (method preserved)."
    }
    return data.get(code, "Unknown behavior")


def check_meta_refresh(html):
    soup = BeautifulSoup(html, "lxml")
    meta = soup.find("meta", attrs={"http-equiv": "refresh"})
    if meta and "url=" in meta.get("content", "").lower():
        return meta["content"].split("url=")[-1]
    return None


def analyze_redirects(url):
    chain = []
    visited = set()

    while url and url not in visited:
        visited.add(url)

        try:
            r = requests.get(url, allow_redirects=False, timeout=7)
            status = r.status_code

            chain.append({
                "url": url,
                "status": status,
                "explain": explain_status(status),
                "headers": dict(r.headers)
            })

            if status in (301, 302, 303, 307, 308):
                url = r.headers.get("Location")
                continue

            meta = check_meta_refresh(r.text)
            if meta:
                url = meta
                continue

            js = re.search(r"window.location.href\\s*=\\s*['\"](.*?)['\"]", r.text)
            if js:
                url = js.group(1)
                continue

            break

        except Exception as e:
            chain.append({"url": url, "status": "ERROR", "explain": str(e)})
            break

    return chain


def phishing_score(url, chain):
    score = 0
    reasons = []

    ext = tldextract.extract(url)
    suffix = ext.suffix

    bad_tlds = ["zip", "xyz", "click", "loan"]
    shorteners = ["bit.ly", "tinyurl", "t.co"]
    keywords = ["login", "bank", "wallet", "update"]

    if suffix in bad_tlds:
        score += 20
        reasons.append(f"Suspicious TLD: .{suffix}")

    if any(s in url for s in shorteners):
        score += 25
        reasons.append("URL shortener detected")

    if any(k in url.lower() for k in keywords):
        score += 20
        reasons.append("Sensitive phishing keyword")

    if len(chain) > 4:
        score += 20
        reasons.append("Long redirect chain")

    return min(score, 100), reasons


# ============================
# UI
# ============================

url = st.text_input("Enter URL:", placeholder="https://example.com")

if st.button("Analyze") and url:

    chain = analyze_redirects(url)
    final_url = chain[-1]["url"]

    # -------------------------
    # Redirect Chain
    # -------------------------
    st.markdown("<div class='df-box'><h3>📑 Redirect Chain</h3>", unsafe_allow_html=True)

    for step in chain:
        s = step["status"]
        color = (
            "status-200" if s == 200 else
            "status-301" if s == 301 else
            "status-302" if s == 302 else
            "status-error"
        )
        st.markdown(
            f"<p><span class='{color}'>[{s}]</span> → <code>{step['url']}</code><br>"
            f"<small>{step['explain']}</small></p>",
            unsafe_allow_html=True
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------
    # HTTP Header Inspector
    # -------------------------
    st.markdown("<div class='df-box'><h3>🧩 HTTP Header Inspector</h3>", unsafe_allow_html=True)

    for i, step in enumerate(chain):
        with st.expander(f"Headers for Hop {i+1} — {step['url']}"):
            for k, v in step.get("headers", {}).items():
                st.markdown(f"<div class='header-box'><b>{k}</b>: {v}</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------
    # Graph
    # -------------------------
    st.markdown("<div class='df-box'><h3>📊 Redirect Graph</h3>", unsafe_allow_html=True)

    dot = Digraph()
    dot.attr("node", shape="box", style="filled", color="#4d88ff", fontcolor="black")

    for i, step in enumerate(chain):
        dot.node(f"n{i}", f"{step['status']}\n{step['url']}")

    for i in range(len(chain) - 1):
        dot.edge(f"n{i}", f"n{i+1}")

    st.graphviz_chart(dot)
    st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------
    # Threat Level
    # -------------------------
    st.markdown("<div class='df-box'><h3>⚠️ Threat Level</h3>", unsafe_allow_html=True)

    risk, reasons = phishing_score(final_url, chain)
    panel = (
        "threat-low" if risk < 30 else
        "threat-med" if risk < 70 else
        "threat-high"
    )

    st.markdown(f"<div class='{panel}'>Threat Score: {risk}%</div>", unsafe_allow_html=True)

    st.write("Why this score:")
    for r in reasons:
        st.write(f"- {r}")

    st.markdown("</div>", unsafe_allow_html=True)

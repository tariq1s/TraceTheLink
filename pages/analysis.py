import streamlit as st
from graphviz import Digraph

from core.analyzer import DEFAULT_MAX_REDIRECTS, DEFAULT_TIMEOUT, analyze_url
from core.reporting import render_markdown_result, render_text_result

st.set_page_config(page_title="TraceTheLink Redirect Analysis", layout="wide")

st.markdown(
    """
<style>
body {
    background: #0f1217;
}
.box {
    background: #151d27;
    border: 1px solid #2f4157;
    padding: 18px;
    border-radius: 14px;
    margin-bottom: 18px;
}
.risk-low { background:#12311f; color:#8ef0b5; padding:12px; border-radius:10px; }
.risk-medium { background:#3a300d; color:#ffe08a; padding:12px; border-radius:10px; }
.risk-high { background:#3a1717; color:#ffaaaa; padding:12px; border-radius:10px; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("Redirect Analyzer")
st.caption("Interactive URL triage with redirect tracing, metadata review, and risk context.")

col1, col2, col3 = st.columns([4, 1, 1])
with col1:
    url = st.text_input("URL", placeholder="https://example.com")
with col2:
    timeout = st.number_input("Timeout", min_value=1, max_value=60, value=DEFAULT_TIMEOUT)
with col3:
    max_redirects = st.number_input("Max redirects", min_value=1, max_value=30, value=DEFAULT_MAX_REDIRECTS)
allow_private = st.checkbox("Allow private/internal targets", value=False)

if st.button("Analyze", width="stretch"):
    if not url or not url.strip():
        st.error("Please enter a URL to analyze.")
        st.stop()
    try:
        result = analyze_url(
            url,
            timeout=int(timeout),
            max_redirects=int(max_redirects),
            allow_private=allow_private,
        )
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
    else:
        risk_class = {
            "low": "risk-low",
            "medium": "risk-medium",
            "high": "risk-high",
        }.get(result["risk_level"], "risk-low")

        summary_left, summary_right = st.columns([2, 1])
        with summary_left:
            st.markdown("<div class='box'>", unsafe_allow_html=True)
            st.subheader("Analysis Summary")
            st.write(f"**Original URL:** `{result['original_url']}`")
            st.write(f"**Final URL:** `{result['final_url']}`")
            st.write(f"**Final Status:** `{result['final_status_code']}` ({result['final_status_text']})")
            st.write(f"**Page Title:** {result.get('title') or 'N/A'}")
            st.write(f"**Recommended Action:** {result['recommended_action']}")
            st.markdown("</div>", unsafe_allow_html=True)

        with summary_right:
            st.markdown("<div class='box'>", unsafe_allow_html=True)
            st.subheader("Risk")
            st.markdown(
                f"<div class='{risk_class}'>Risk Level: {result['risk_level'].upper()} ({result['risk_score']}/100)</div>",
                unsafe_allow_html=True,
            )
            for item in result["risk_reasoning"]:
                st.write(f"- {item}")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.subheader("Redirect Chain")
        for hop in result["redirect_chain"]:
            line = f"**Hop {hop['hop']}** `[{hop['status_code']}]` `{hop['url']}`"
            if hop.get("location"):
                line += f" -> `{hop['location']}`"
            st.write(line)
            st.caption(hop["status_text"])
        st.markdown("</div>", unsafe_allow_html=True)

        details_left, details_right = st.columns(2)
        with details_left:
            st.markdown("<div class='box'>", unsafe_allow_html=True)
            st.subheader("Domain Changes")
            if result["domain_changes"]:
                for change in result["domain_changes"]:
                    st.write(f"- `{change['from']}` -> `{change['to']}`")
            else:
                st.write("No domain changes observed.")
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("<div class='box'>", unsafe_allow_html=True)
            st.subheader("Suspicious Indicators")
            if result["suspicious_indicators"]:
                for indicator in result["suspicious_indicators"]:
                    st.write(f"- {indicator}")
            else:
                st.write("No suspicious indicators identified from static analysis.")
            st.markdown("</div>", unsafe_allow_html=True)

        with details_right:
            st.markdown("<div class='box'>", unsafe_allow_html=True)
            st.subheader("Metadata")
            metadata = result.get("metadata") or {}
            st.write(f"**Content-Type:** {metadata.get('content_type') or 'N/A'}")
            st.write(f"**Server:** {metadata.get('server') or 'N/A'}")
            st.write(f"**Meta Description:** {metadata.get('meta_description') or 'N/A'}")
            st.write(f"**Meta Refresh:** {metadata.get('meta_refresh') or 'N/A'}")
            st.write(f"**JS Redirect Pattern:** {metadata.get('javascript_redirect') or 'N/A'}")
            if result.get("error"):
                st.warning(result["error"])
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.subheader("Redirect Graph")
        dot = Digraph()
        dot.attr("node", shape="box", style="rounded,filled", color="#60a5fa", fillcolor="#dbeafe", fontname="Segoe UI")
        for hop in result["redirect_chain"]:
            dot.node(f"hop_{hop['hop']}", f"{hop['hop']}: {hop['status_code']}\n{hop['domain']}")
        for idx in range(len(result["redirect_chain"]) - 1):
            dot.edge(f"hop_{idx + 1}", f"hop_{idx + 2}")
        st.graphviz_chart(dot, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

        export_left, export_right = st.columns(2)
        with export_left:
            st.download_button(
                "Download Markdown Report",
                data=render_markdown_result(result),
                file_name="tracethelink-report.md",
                mime="text/markdown",
                width="stretch",
            )
        with export_right:
            st.download_button(
                "Download Text Report",
                data=render_text_result(result),
                file_name="tracethelink-report.txt",
                mime="text/plain",
                width="stretch",
            )

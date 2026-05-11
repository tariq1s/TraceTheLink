import streamlit as st

st.set_page_config(page_title="TraceTheLink", layout="wide", page_icon="TL")

st.markdown(
    """
<style>
body {
    background: #0f1217;
    font-family: 'Segoe UI', sans-serif;
}
.hero {
    background: linear-gradient(135deg, #101720 0%, #172434 100%);
    border: 1px solid #2d3d52;
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 20px;
}
.panel {
    background: #141b24;
    border: 1px solid #29384a;
    border-radius: 14px;
    padding: 20px;
}
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="hero">
    <h1 style="margin:0; color:#dbeafe;">TraceTheLink</h1>
    <p style="color:#9db4cc; font-size:1.05rem; margin-top:10px;">
        Practical URL and redirect analysis for phishing triage, suspicious link investigation,
        and analyst-friendly reporting.
    </p>
</div>
""",
    unsafe_allow_html=True,
)

left, right = st.columns([2, 1])

with left:
    st.markdown(
        """
<div class="panel">
    <h3 style="color:#dbeafe; margin-top:0;">What it does</h3>
    <p style="color:#bfd0e4;">
        TraceTheLink follows redirect chains, highlights domain changes, extracts basic page metadata,
        and produces a simple risk assessment to support fast link triage.
    </p>
</div>
""",
        unsafe_allow_html=True,
    )

with right:
    st.markdown(
        """
<div class="panel">
    <h3 style="color:#dbeafe; margin-top:0;">Modes</h3>
    <p style="color:#bfd0e4; margin-bottom:8px;">Use Streamlit for interactive review.</p>
    <p style="color:#bfd0e4;">Use <code>tracethelink.py</code> for terminal and batch workflows.</p>
</div>
""",
        unsafe_allow_html=True,
    )

if st.button("Open Redirect Analyzer", width="stretch"):
    st.switch_page("pages/analysis.py")

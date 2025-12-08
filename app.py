import streamlit as st
import time

st.set_page_config(
    page_title="TraceTheLink – DFIR Suite",
    layout="wide",
    page_icon="🛡"
)

# ============================
# CSS – Modern DFIR Blue Theme
# ============================

st.markdown("""
<style>

body {
    background: #0f1217;
    font-family: 'Inter', sans-serif;
}

h1, h2, h3, h4 {
    color: #cfe3ff !important;
}

.sidebar .sidebar-content {
    background: #11151c !important;
}

.df-card {
    background-color: #1a1d22;
    border: 1px solid #2d3643;
    padding: 20px;
    border-radius: 10px;
    color: #d6e0f5;
    margin-bottom: 25px;
    transition: 0.2s ease-in-out;
}

.df-card:hover {
    border-color: #4d88ff;
    box-shadow: 0 0 10px #1b2b44;
}

.button-main {
    background: linear-gradient(90deg, #2f59d1, #4d88ff);
    padding: 14px 22px;
    border-radius: 8px;
    color: white !important;
    font-weight: 600;
    border: none;
    transition: 0.15s ease-in-out;
}

.button-main:hover {
    background: linear-gradient(90deg, #4d88ff, #2f59d1);
    transform: scale(1.03);
}

.glow {
    text-shadow: 0 0 15px #4d88ff;
}

</style>
""", unsafe_allow_html=True)

# ============================
# Main UI
# ============================

st.markdown("""
    <h1 style='color:#cfe3ff; margin-bottom: 5px;'>
        🛡 TraceTheLink – Analysis Suite
    </h1>
    <p style='color:#9bb5d1; font-size: 1.1rem;'>
        Modern Tools for URL Intelligence, Redirect Tracking, and Threat Analysis.
    </p>
""", unsafe_allow_html=True)



col1, col2 = st.columns(2)

with col1:
    if st.button("🔗 Redirect Analyzer", use_container_width=True):
        st.switch_page("pages/analysis.py")

with col2:
    if st.button("⚙️ Coming Soon: Threat Scoring Engine", use_container_width=True):
        st.info("This module will be released soon.")


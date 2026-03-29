import streamlit as st
import json
import pandas as pd

from scanner.port_scan import scan_ports
from scanner.service_scan import scan_services
from analyzer.risk_analyzer import analyze_risks
from scanner.web_scan import scan_web
from scanner.subdomain_scan import scan_subdomains


# 🔹 Page Config
st.set_page_config(page_title="PhantomSurface", layout="wide")

# 🔹 Custom Hacker Theme
st.markdown("""
<style>
html, body, [class*="css"] {
    background-color: #0d1117;
    color: #00ffcc;
}

.stTextInput>div>div>input {
    background-color: #161b22;
    color: #00ffcc;
}

.stButton>button {
    background-color: #00ffcc;
    color: black;
    border-radius: 8px;
    font-weight: bold;
}

.block-container {
    padding-top: 2rem;
}

h1, h2, h3 {
    color: #00ffcc;
}
</style>
""", unsafe_allow_html=True)

# 🔹 Sidebar
st.sidebar.title("⚡ PhantomSurface")
st.sidebar.markdown("Attack Surface Mapper")
target = st.sidebar.text_input("🎯 Target", "scanme.nmap.org")

start = st.sidebar.button("🚀 Start Scan")

# 🔹 Main Title
st.title("🛡️ PhantomSurface Dashboard")

if start:
    st.info(f"Scanning {target}...\n")

    col1, col2 = st.columns(2)

    # 🔹 Subdomains
    with st.spinner("🌐 Enumerating Subdomains..."):
        subs = scan_subdomains(target)

    with col1:
        st.subheader("🌐 Subdomains")
        st.write(subs if subs else "None found")

    # 🔹 Ports
    with st.spinner("🔓 Scanning Ports..."):
        ports = scan_ports(target)

    with col2:
        st.subheader("🔓 Open Ports")
        st.write(ports)

    # 🔹 Services
    with st.spinner("⚙️ Detecting Services..."):
        services = scan_services(target)

    st.success("⚙️ Service scan completed")

    # 🔹 Risks
    risks, score = analyze_risks(ports)

    st.subheader("⚠️ Risk Analysis")

    for sev, msg in risks:
        if sev == "HIGH":
            st.error(f"[HIGH] {msg}")
        elif sev == "MEDIUM":
            st.warning(f"[MEDIUM] {msg}")
        else:
            st.success(f"[LOW] {msg}")

    # 🔹 Web Scan
    if "80" in ports or "443" in ports:
        with st.spinner("🌍 Scanning Web..."):
            web = scan_web(target)
        if web:
            st.subheader("🌍 Web Info")
            st.code(web)

    # 🔹 Risk Level
    if score >= 6:
        level = "HIGH"
        st.error(f"🔥 Risk Level: {level}")
    elif score >= 3:
        level = "MEDIUM"
        st.warning(f"⚠️ Risk Level: {level}")
    else:
        level = "LOW"
        st.success(f"✅ Risk Level: {level}")

    # 🔹 Metrics Row
    st.subheader("📊 Dashboard Metrics")
    m1, m2, m3 = st.columns(3)
    m1.metric("Risk Score", f"{score}/10")
    m2.metric("Subdomains", len(subs))
    m3.metric("Open Ports", len(ports))

    # 🔹 Risk Chart
    risk_counts = {
        "HIGH": sum(1 for s, _ in risks if s == "HIGH"),
        "MEDIUM": sum(1 for s, _ in risks if s == "MEDIUM"),
        "LOW": sum(1 for s, _ in risks if s == "LOW")
    }

    df = pd.DataFrame({
        "Severity": list(risk_counts.keys()),
        "Count": list(risk_counts.values())
    })

    st.subheader("📊 Risk Distribution")
    st.bar_chart(df.set_index("Severity"))

    # 🔹 Download Report
    report = {
        "target": target,
        "subdomains": subs,
        "ports": ports,
        "risks": [{"severity": s, "desc": m} for s, m in risks],
        "score": score,
        "level": level
    }

    st.download_button(
        "📥 Download Report",
        json.dumps(report, indent=4),
        file_name="phantomsurface_report.json"
    )

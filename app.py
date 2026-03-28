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

# 🔹 Dark Theme Styling
st.markdown(
    """
    <style>
    body {
        background-color: #0e1117;
        color: #00ffcc;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# 🔹 Title
st.title("🛡️ PhantomSurface Attack Surface Mapper")

# 🔹 Input
target = st.text_input("Enter Target Domain/IP", "scanme.nmap.org")

# 🔹 Start Button
if st.button("Start Scan"):

    st.info(f"Scanning {target}...")

    # 🔹 Subdomains
    with st.spinner("Enumerating Subdomains..."):
        subs = scan_subdomains(target)

    st.subheader("🌐 Subdomains")
    if subs:
        st.write(subs)
    else:
        st.write("No subdomains found")

    # 🔹 Ports
    with st.spinner("Scanning Ports..."):
        ports = scan_ports(target)

    st.subheader("🔓 Open Ports")
    st.write(ports)

    # 🔹 Services
    with st.spinner("Detecting Services..."):
        services = scan_services(target)

    st.subheader("⚙️ Services Detected")
    st.success("Service scan completed")

    # 🔹 Risks
    risks, score = analyze_risks(ports)

    st.subheader("⚠️ Risks")
    for sev, msg in risks:
        if sev == "HIGH":
            st.error(msg)
        elif sev == "MEDIUM":
            st.warning(msg)
        else:
            st.success(msg)

    # 🔹 Web Scan
    if "80" in ports or "443" in ports:
        with st.spinner("Scanning Web Technologies..."):
            web = scan_web(target)
        if web:
            st.subheader("🌍 Web Info")
            st.text(web)

    # 🔹 Risk Level
    if score >= 6:
        level = "HIGH"
        st.error(f"Risk Level: {level}")
    elif score >= 3:
        level = "MEDIUM"
        st.warning(f"Risk Level: {level}")
    else:
        level = "LOW"
        st.success(f"Risk Level: {level}")

    # 🔹 Metrics Dashboard
    st.subheader("📊 Summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Score", f"{score}/10")
    col2.metric("Subdomains", len(subs))
    col3.metric("Open Ports", len(ports))

    # 🔹 Risk Distribution Chart
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
    report_data = {
        "target": target,
        "subdomains": subs,
        "ports": ports,
        "risks": [{"severity": s, "description": m} for s, m in risks],
        "score": score,
        "level": level
    }

    st.download_button(
        label="📥 Download Report (JSON)",
        data=json.dumps(report_data, indent=4),
        file_name="phantomsurface_report.json",
        mime="application/json"
    )

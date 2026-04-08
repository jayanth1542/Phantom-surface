import streamlit as st
from fpdf import FPDF
from tech_detector import detect_technologies
from port_scanner import scan_ports
from exposure_scanner import scan_exposures
from cve_engine import get_cves_for_technologies, calculate_risk

import plotly.express as px
import pandas as pd
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

st.set_page_config(page_title="PhantomSurface", layout="wide")

# -------------------------------
# HEADER
# -------------------------------
st.markdown("# 🛡️ PhantomSurface")
st.caption("Cybersecurity Project - Attack Surface Mapping Tool")

# -------------------------------
# SIDEBAR
# -------------------------------
st.sidebar.title("⚙️ Controls")

domain = st.sidebar.text_input("🌐 Enter Domain")

if st.sidebar.button("🚀 Run Scan"):
    if not domain:
        st.sidebar.warning("Enter a domain")
    else:
        with st.spinner("Scanning target..."):

            techs = detect_technologies(domain)
            ports = scan_ports(domain)
            exposures = scan_exposures(domain)

            st.session_state["results"] = {
                "domain": domain,
                "technologies": techs,
                "ports": ports,
                "exposures": exposures
            }

            st.session_state["cves"] = {}

        st.success("Scan Completed")

if st.sidebar.button("🛡️ Fetch CVEs"):
    if "results" not in st.session_state:
        st.sidebar.warning("Run scan first")
    else:
        with st.spinner("Fetching CVEs..."):
            cves = get_cves_for_technologies(
                st.session_state["results"]["technologies"]
            )
            st.session_state["cves"] = cves

if st.sidebar.button("🔄 Reset"):
    st.session_state.clear()
    st.rerun()

# -------------------------------
# TABS
# -------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Scan", "🛡️ CVEs", "📄 Report", "📈 Dashboard"
])

# -------------------------------
# TAB 1: SCAN
# -------------------------------
with tab1:
    if "results" in st.session_state:
        r = st.session_state["results"]

        st.subheader("📊 Scan Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric("Domain", r["domain"])
        col2.metric("Technologies", len(r["technologies"]))
        col3.metric("Open Ports", len(r["ports"]))

        st.divider()

        st.write("### 🧠 Technologies")
        st.success(", ".join(r["technologies"]) if r["technologies"] else "None")

        st.write("### 🌐 Open Ports")
        st.info(r["ports"] if r["ports"] else "None")

        st.write("### 🔐 Exposed Endpoints")

        if r["exposures"]:
            for exp in r["exposures"]:
                icon = "🔴" if exp["risk"] == "HIGH" else "🟠"
                st.write(f"{icon} {exp['path']} ({exp['status']})")
        else:
            st.success("No exposures found")

    else:
        st.info("Run a scan from sidebar")

# -------------------------------
# TAB 2: CVEs
# -------------------------------
with tab2:
    if "cves" in st.session_state and st.session_state["cves"]:
        st.subheader("🛡️ Vulnerabilities")

        for tech, cves in st.session_state["cves"].items():
            st.markdown(f"### 🔍 {tech}")

            for cve in cves:
                if "error" in cve:
                    st.error(cve["error"])
                    continue

                color = {
                    "LOW": "🟢",
                    "MEDIUM": "🟡",
                    "HIGH": "🟠",
                    "CRITICAL": "🔴"
                }.get(cve["severity"], "⚪")

                st.write(f"{color} **{cve['id']}**")
                st.write(cve["description"])
                st.divider()

        # Risk
        risk = calculate_risk(
            st.session_state["cves"],
            st.session_state["results"]["exposures"]
        )

        st.subheader("🚨 Risk Level")
        st.error(risk)

        st.session_state["risk"] = risk

    else:
        st.info("Fetch CVEs first")

# -------------------------------
# TAB 3: REPORT
# -------------------------------
# -------------------------------
# TAB 3: REPORT
# -------------------------------
with tab3:
    if "results" in st.session_state and "cves" in st.session_state:

        if st.button("📄 Generate PDF"):

            r = st.session_state["results"]
            risk = st.session_state.get("risk", "UNKNOWN")

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            # Title
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "PhantomSurface Report", ln=True)

            pdf.ln(5)
            pdf.set_font("Arial", size=12)

            # Basic Info
            pdf.cell(0, 10, f"Domain: {r['domain']}", ln=True)
            pdf.cell(0, 10, f"Risk: {risk}", ln=True)

            # Technologies
            pdf.ln(5)
            pdf.cell(0, 10, "Technologies:", ln=True)

            if r["technologies"]:
                for t in r["technologies"]:
                    pdf.cell(0, 10, f"- {t}", ln=True)
            else:
                pdf.cell(0, 10, "None", ln=True)

            # Exposures
            pdf.ln(5)
            pdf.cell(0, 10, "Exposures:", ln=True)

            if r["exposures"]:
                for exp in r["exposures"]:
                    pdf.cell(0, 10, f"{exp['path']} ({exp['status']})", ln=True)
            else:
                pdf.cell(0, 10, "None", ln=True)

            # CVEs (🔥 upgrade)
            pdf.ln(5)
            pdf.cell(0, 10, "CVEs:", ln=True)

            cves = st.session_state.get("cves", {})
            if cves:
                for tech, items in cves.items():
                    pdf.cell(0, 10, f"{tech}:", ln=True)
                    for cve in items[:3]:  # limit to avoid overflow
                        if "id" in cve:
                            pdf.cell(0, 10, f"- {cve['id']} ({cve['severity']})", ln=True)
            else:
                pdf.cell(0, 10, "No CVEs fetched", ln=True)

            # Save
            pdf.output("report.pdf")

            # ✅ IMPORTANT: Download button
            with open("report.pdf", "rb") as f:
                st.download_button(
                    label="⬇️ Download Report",
                    data=f,
                    file_name="PhantomSurface_Report.pdf",
                    mime="application/pdf"
                )

            st.success("Report Generated & Ready to Download")

    else:
        st.info("Run scan + CVE first")
# -------------------------------
# TAB 4: DASHBOARD
# -------------------------------
with tab4:
    st.subheader("📈 Visual Dashboard")

    if "results" not in st.session_state:
        st.info("Run a scan first")
    else:
        r = st.session_state["results"]
        cves = st.session_state.get("cves", {})

        # -------------------------------
        # PIE CHART
        # -------------------------------
        st.write("### 🚨 CVE Severity Distribution")

        severity_counts = {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}

        for tech, items in cves.items():
            for cve in items:
                sev = cve.get("severity","LOW")
                if sev in severity_counts:
                    severity_counts[sev] += 1

        df = pd.DataFrame({
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        })

        if df["Count"].sum() > 0:
            fig = px.pie(df, names="Severity", values="Count")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No CVEs yet")

        # -------------------------------
        # PORTS CHART
        # -------------------------------
        st.write("### 🌐 Open Ports")

        if r["ports"]:
            port_df = pd.DataFrame({"Ports": r["ports"]})
            fig2 = px.histogram(port_df, x="Ports")
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.warning("No ports found")

        # -------------------------------
        # EXPOSURE CHART
        # -------------------------------
        st.write("### 🔐 Exposure Risk")

        if r["exposures"]:
            exp_df = pd.DataFrame(r["exposures"])
            fig3 = px.histogram(exp_df, x="risk")
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.success("No exposures")

        # -------------------------------
        # ATTACK GRAPH (REAL VISUAL)
        # -------------------------------
        st.write("### 🌐 Attack Surface Graph")

        net = Network(height="500px", width="100%", notebook=False)

        domain_node = r["domain"]
        net.add_node(domain_node, label=domain_node, color="blue")

        # tech
        for tech in r["technologies"]:
            net.add_node(tech, color="green")
            net.add_edge(domain_node, tech)

        # ports
        for port in r["ports"]:
            p = f"port {port}"
            net.add_node(p, color="orange")
            net.add_edge(domain_node, p)

        # exposures
        for exp in r["exposures"]:
            net.add_node(exp["path"], color="red")
            net.add_edge(domain_node, exp["path"])

        net.save_graph("graph.html")

        with open("graph.html", "r", encoding="utf-8") as f:
            html = f.read()

        components.html(html, height=500)

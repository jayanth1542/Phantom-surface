import streamlit as st
from fpdf import FPDF
from cve_engine import get_cves_for_technologies, calculate_risk_from_cves

st.set_page_config(page_title="PhantomSurface", layout="wide")

st.title("🛡️ PhantomSurface - Attack Surface Scanner")

# -------------------------------
# USER INPUT
# -------------------------------
domain = st.text_input("🌐 Enter Domain (e.g. example.com)")

# -------------------------------
# SESSION STATE INIT
# -------------------------------
if "results" not in st.session_state:
    st.session_state["results"] = {}

if "cve_results" not in st.session_state:
    st.session_state["cve_results"] = {}

if "risk_level" not in st.session_state:
    st.session_state["risk_level"] = "UNKNOWN"

# -------------------------------
# RUN SCAN BUTTON
# -------------------------------
if st.button("🚀 Run Scan"):

    if not domain:
        st.warning("Please enter a domain")
    else:
        # 🔥 Replace with your real scanner later
        results = {
            "domain": domain,
            "technologies": ["nginx", "php"],  # simulated detection
            "ports": [80, 443]
        }

        st.session_state["results"] = results
        st.success("Scan completed!")

# -------------------------------
# SHOW RESULTS
# -------------------------------
results = st.session_state.get("results", {})

if results:
    st.subheader("📊 Scan Results")

    st.write("**Domain:**", results.get("domain"))
    st.write("**Technologies:**", ", ".join(results.get("technologies", [])))
    st.write("**Open Ports:**", results.get("ports"))

# -------------------------------
# CVE FETCH BUTTON
# -------------------------------
if results and "technologies" in results:

    if st.button("🛡️ Fetch Live CVEs"):

        with st.spinner("Fetching vulnerabilities from NVD..."):
            tech_list = results.get("technologies", [])
            cve_results = get_cves_for_technologies(tech_list)

        st.session_state["cve_results"] = cve_results

        st.subheader("🛡️ Live Vulnerabilities (NVD)")

        for tech, cves in cve_results.items():
            st.markdown(f"### 🔍 {tech}")

            if not cves:
                st.write("No CVEs found")
                continue

            for cve in cves:
                if "error" in cve:
                    st.error(cve["error"])
                    continue

                icon = {
                    "LOW": "🟢",
                    "MEDIUM": "🟡",
                    "HIGH": "🟠",
                    "CRITICAL": "🔴"
                }.get(cve["severity"], "⚪")

                st.write(f"{icon} **{cve['id']}**")
                st.write(cve["description"])
                st.write("---")

        # -------------------------------
        # RISK CALCULATION
        # -------------------------------
        risk = calculate_risk_from_cves(cve_results)
        st.session_state["risk_level"] = risk

        st.subheader("🚨 Updated Risk Level")
        st.write(f"### {risk}")

# -------------------------------
# PDF GENERATION FUNCTION
# -------------------------------
def generate_pdf(results, cve_results, risk):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, "PhantomSurface Report", ln=True)
    pdf.ln(5)

    pdf.cell(0, 10, f"Domain: {results.get('domain')}", ln=True)
    pdf.cell(0, 10, f"Risk Level: {risk}", ln=True)

    pdf.ln(5)
    pdf.cell(0, 10, "Technologies:", ln=True)

    for tech in results.get("technologies", []):
        pdf.cell(0, 10, f"- {tech}", ln=True)

    pdf.ln(5)
    pdf.cell(0, 10, "Live CVE Findings:", ln=True)

    for tech, cves in cve_results.items():
        pdf.cell(0, 10, f"{tech}:", ln=True)

        for cve in cves[:3]:
            line = f"{cve['id']} ({cve['severity']})"
            pdf.multi_cell(0, 8, line)

    return pdf.output(dest="S").encode("latin-1")

# -------------------------------
# DOWNLOAD PDF BUTTON
# -------------------------------
if st.session_state.get("cve_results"):

    if st.button("📄 Generate PDF Report"):

        pdf_data = generate_pdf(
            st.session_state["results"],
            st.session_state["cve_results"],
            st.session_state["risk_level"]
        )

        st.download_button(
            label="⬇️ Download Report",
            data=pdf_data,
            file_name="phantomsurface_report.pdf",
            mime="application/pdf"
        )

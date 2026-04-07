import requests
import os
import time
from dotenv import load_dotenv
import streamlit as st

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY") or st.secrets.get("NVD_API_KEY")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(keyword):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    headers = {
        "User-Agent": "PhantomSurface/1.0"
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(BASE_URL, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id", "N/A")

            desc = "No description"
            if cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "No description")

            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]

            cves.append({
                "id": cve_id,
                "description": desc,
                "severity": severity
            })

        return cves

    except Exception as e:
        return [{"error": str(e)}]


def get_cves_for_technologies(technologies):
    results = {}

    for tech in technologies:
        results[tech] = fetch_cves(tech)
        time.sleep(1)

    return results


def calculate_risk(cve_results, exposures):
    score = 0

    for tech, cves in cve_results.items():
        for cve in cves:
            sev = cve.get("severity", "")
            if sev == "LOW":
                score += 1
            elif sev == "MEDIUM":
                score += 3
            elif sev == "HIGH":
                score += 6
            elif sev == "CRITICAL":
                score += 10

    for exp in exposures:
        if exp["risk"] == "HIGH":
            score += 10
        elif exp["risk"] == "MEDIUM":
            score += 5

    if score > 40:
        return "CRITICAL"
    elif score > 25:
        return "HIGH"
    elif score > 10:
        return "MEDIUM"
    else:
        return "LOW"

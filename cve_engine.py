import requests
import os
import time
from dotenv import load_dotenv

# -------------------------------
# LOAD ENV VARIABLES
# -------------------------------
load_dotenv()  # make sure .env is in same folder

NVD_API_KEY = os.getenv("NVD_API_KEY")

# 🔍 DEBUG (check terminal)
print("DEBUG: NVD API KEY =", NVD_API_KEY)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# -------------------------------
# FETCH CVEs FROM NVD
# -------------------------------
def fetch_cves(keyword):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    # ✅ ALWAYS include User-Agent
    headers = {
        "User-Agent": "PhantomSurface/1.0"
    }

    # ✅ ADD API KEY IF PRESENT
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # 🔍 DEBUG HEADERS
    print(f"\nDEBUG: Fetching CVEs for '{keyword}'")
    print("DEBUG: Headers Sent =", headers)

    try:
        response = requests.get(
            BASE_URL,
            params=params,
            headers=headers,
            timeout=10
        )

        # 🔍 DEBUG STATUS
        print("DEBUG: Response Status =", response.status_code)

        response.raise_for_status()
        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id", "N/A")

            # Description
            desc = "No description"
            if cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "No description")

            # Severity
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

        print(f"DEBUG: Found {len(cves)} CVEs\n")

        return cves

    except Exception as e:
        print("ERROR:", str(e))
        return [{"error": str(e)}]


# -------------------------------
# MULTI-TECH CVE FETCH
# -------------------------------
def get_cves_for_technologies(technologies):
    results = {}

    for tech in technologies:
        results[tech] = fetch_cves(tech)

        # ⚡ Avoid rate limiting
        time.sleep(1)

    return results


# -------------------------------
# RISK CALCULATION
# -------------------------------
def calculate_risk_from_cves(cve_results):
    score = 0

    for tech, cves in cve_results.items():
        for cve in cves:
            severity = cve.get("severity", "")

            if severity == "LOW":
                score += 1
            elif severity == "MEDIUM":
                score += 3
            elif severity == "HIGH":
                score += 6
            elif severity == "CRITICAL":
                score += 10

    if score > 30:
        return "CRITICAL"
    elif score > 20:
        return "HIGH"
    elif score > 10:
        return "MEDIUM"
    else:
        return "LOW"

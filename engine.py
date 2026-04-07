import socket
import requests
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 80, 443, 8080]

def get_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    if domain in name:
                        subdomains.add(name.strip())
    except:
        pass

    return list(subdomains)


def scan_port(host, port):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((host, port))
        return port
    except:
        return None
    finally:
        s.close()


def port_scan(domain):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(domain, p), COMMON_PORTS)

    for r in results:
        if r:
            open_ports.append(r)

    return open_ports


def get_headers(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=3)
        return dict(r.headers)
    except:
        return {}


def detect_tech(headers):
    tech = []
    if "Server" in headers:
        tech.append(headers["Server"])
    if "X-Powered-By" in headers:
        tech.append(headers["X-Powered-By"])
    return tech


def find_vulnerabilities(technologies):
    vulns = []

    for tech in technologies:
        tech_lower = tech.lower()

        if "apache" in tech_lower:
            vulns.append({"cve": "CVE-2021-41773", "severity": "HIGH"})
        if "nginx" in tech_lower:
            vulns.append({"cve": "CVE-2019-20372", "severity": "MEDIUM"})
        if "php" in tech_lower:
            vulns.append({"cve": "CVE-2019-11043", "severity": "CRITICAL"})

    return vulns


def generate_ai_summary(result):
    if result["risk"] == "CRITICAL":
        return "Critical vulnerabilities detected. Immediate patching required."
    elif result["risk"] == "HIGH":
        return "High-risk services exposed. Investigate and secure endpoints."
    elif result["risk"] == "MEDIUM":
        return "Moderate exposure. Review open ports and configurations."
    else:
        return "Low risk. No major exposures detected."


def run_full_scan(domain):
    result = {
        "domain": domain,
        "subdomains": [],
        "ports": [],
        "technologies": [],
        "vulnerabilities": [],
        "risk": "LOW",
        "summary": ""
    }

    subs = get_subdomains(domain)
    ports = port_scan(domain)
    headers = get_headers(domain)
    tech = detect_tech(headers)
    vulns = find_vulnerabilities(tech)

    result["subdomains"] = subs[:10]
    result["ports"] = ports
    result["technologies"] = tech
    result["vulnerabilities"] = vulns

    if any(v["severity"] == "CRITICAL" for v in vulns):
        result["risk"] = "CRITICAL"
    elif any(v["severity"] == "HIGH" for v in vulns):
        result["risk"] = "HIGH"
    elif len(ports) > 1:
        result["risk"] = "MEDIUM"
    else:
        result["risk"] = "LOW"

    result["summary"] = generate_ai_summary(result)

    return result

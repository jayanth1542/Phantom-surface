import requests

PATHS = ["/admin","/login","/.env","/.git","/backup","/config"]

def scan_exposures(domain):
    findings = []

    for path in PATHS:
        try:
            r = requests.get(f"http://{domain}{path}", timeout=3)

            if r.status_code == 200:
                findings.append({"path": path, "status": r.status_code, "risk": "HIGH"})
            elif r.status_code in [401,403]:
                findings.append({"path": path, "status": r.status_code, "risk": "MEDIUM"})

        except:
            continue

    return findings

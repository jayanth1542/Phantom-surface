def analyze_risks(ports):
    """
    Analyzes open ports and assigns:
    - Severity level (LOW / MEDIUM / HIGH)
    - Risk description
    - Numerical score
    Returns:
        risks (list of tuples)
        total_score (int)
    """

    risks = []
    total_score = 0

    for port in ports:

        # 🔴 HIGH RISK SERVICES
        if port == "22":
            risks.append(("HIGH", "SSH exposed – Brute-force attack risk"))
            total_score += 3

        elif port == "21":
            risks.append(("HIGH", "FTP detected – Plaintext credential exposure risk"))
            total_score += 3

        elif port == "23":
            risks.append(("HIGH", "Telnet detected – Unencrypted remote access risk"))
            total_score += 3

        # 🟠 MEDIUM RISK SERVICES
        elif port == "80":
            risks.append(("MEDIUM", "HTTP detected – Traffic not encrypted"))
            total_score += 2

        elif port == "3306":
            risks.append(("MEDIUM", "MySQL exposed – Database attack surface risk"))
            total_score += 2

        elif port == "8080":
            risks.append(("MEDIUM", "Alternate HTTP port exposed – Web service risk"))
            total_score += 2

        # 🟢 LOW RISK SERVICES
        elif port == "443":
            risks.append(("LOW", "HTTPS detected – Certificate validation recommended"))
            total_score += 1

        else:
            risks.append(("LOW", f"Port {port} exposed – Review service configuration"))
            total_score += 1

    # If no risky ports found
    if not ports:
        risks.append(("LOW", "No open ports detected"))
        total_score = 0

    return risks, total_score

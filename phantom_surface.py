#!/usr/bin/env python3

import json
import platform
import argparse
import time
from colorama import Fore, init
from tqdm import tqdm

from scanner.port_scan import scan_ports
from scanner.service_scan import scan_services
from analyzer.risk_analyzer import analyze_risks
from scanner.web_scan import scan_web
from scanner.subdomain_scan import scan_subdomains


# 🔹 Banner
def print_banner():
    banner = f"""
{Fore.CYAN}
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

{Fore.GREEN}        PhantomSurface - Attack Surface Mapper
"""
    print(banner)


def main():
    init(autoreset=True)
    print_banner()

    parser = argparse.ArgumentParser(description="PhantomSurface Attack Surface Mapper")
    parser.add_argument("--target", required=True, help="Target IP or Domain")
    args = parser.parse_args()

    # 🔹 OS Detection
    current_os = platform.system()
    print(Fore.GREEN + f"[+] Running on: {current_os}")

    target = args.target
    print(Fore.CYAN + f"\n[+] Starting scan on {target}\n")

    # 🔹 Progress Steps
    steps = [
        ("Enumerating Subdomains", scan_subdomains),
        ("Scanning Ports", scan_ports),
        ("Detecting Services", scan_services),
    ]

    results = {}

    for step_name, func in tqdm(steps, desc="Overall Progress", ncols=70):
        print(Fore.YELLOW + f"\n[*] {step_name}...")
        time.sleep(0.5)
        results[step_name] = func(target)

    subdomains = results["Enumerating Subdomains"]
    ports = results["Scanning Ports"]
    services = results["Detecting Services"]

    # 🔹 Risk Analysis
    risks, total_score = analyze_risks(ports)

    if total_score >= 6:
        overall_level = "HIGH"
    elif total_score >= 3:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    # 🔹 Web Scan
    web_result = None
    if "80" in ports or "443" in ports:
        for _ in tqdm(range(1), desc="Web Scan", ncols=70):
            web_result = scan_web(target)

    print(Fore.CYAN + "\n[+] Scan Complete")
    print("[+] Potential Risks Identified:")

    for severity, message in risks:
        if severity == "HIGH":
            color = Fore.RED
        elif severity == "MEDIUM":
            color = Fore.YELLOW
        else:
            color = Fore.GREEN

        print(color + f" - [{severity}] {message}")

    print(Fore.CYAN + f"\n[+] Overall Risk Score: {total_score}/10")

    if overall_level == "HIGH":
        print(Fore.RED + f"[!] Overall Risk Level: {overall_level}")
    elif overall_level == "MEDIUM":
        print(Fore.YELLOW + f"[!] Overall Risk Level: {overall_level}")
    else:
        print(Fore.GREEN + f"[!] Overall Risk Level: {overall_level}")

    # 🔹 Summary Dashboard
    high_count = sum(1 for s, _ in risks if s == "HIGH")
    medium_count = sum(1 for s, _ in risks if s == "MEDIUM")
    low_count = sum(1 for s, _ in risks if s == "LOW")

    print(Fore.CYAN + "\n========== SCAN SUMMARY ==========")
    print(f"Target              : {target}")
    print(f"Subdomains Found    : {len(subdomains)}")
    print(f"Open Ports          : {len(ports)}")
    print(Fore.RED + f"High Risks          : {high_count}")
    print(Fore.YELLOW + f"Medium Risks        : {medium_count}")
    print(Fore.GREEN + f"Low Risks           : {low_count}")
    print(Fore.CYAN + f"Overall Score       : {total_score}/10")

    if overall_level == "HIGH":
        print(Fore.RED + f"Overall Risk Level  : {overall_level}")
    elif overall_level == "MEDIUM":
        print(Fore.YELLOW + f"Overall Risk Level  : {overall_level}")
    else:
        print(Fore.GREEN + f"Overall Risk Level  : {overall_level}")

    print(Fore.CYAN + "=================================\n")

    # 🔹 TXT REPORT
    with open("reports/report.txt", "w") as f:
        f.write("PhantomSurface Scan Report\n")
        f.write("=========================\n")
        f.write(f"Target: {target}\n\n")

        f.write("Subdomains:\n")
        for sub in subdomains:
            f.write(f"- {sub}\n")

        if web_result:
            f.write("\nWeb Info:\n")
            f.write(web_result + "\n")

        f.write("\nRisks:\n")
        for s, m in risks:
            f.write(f"[{s}] {m}\n")

        f.write(f"\nScore: {total_score}/10\n")
        f.write(f"Level: {overall_level}\n")

    print(Fore.GREEN + "[+] TXT report saved")

    # 🔹 JSON REPORT
    json_data = {
        "target": target,
        "subdomains": subdomains,
        "ports": ports,
        "risks": [{"severity": s, "desc": m} for s, m in risks],
        "score": total_score,
        "level": overall_level
    }

    with open("reports/report.json", "w") as jf:
        json.dump(json_data, jf, indent=4)

    print(Fore.GREEN + "[+] JSON report saved")


if __name__ == "__main__":
    main()

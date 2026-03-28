#!/usr/bin/env python3

import json
import platform
import argparse
from scanner.port_scan import scan_ports
from scanner.service_scan import scan_services
from analyzer.risk_analyzer import analyze_risks
from scanner.web_scan import scan_web
from scanner.subdomain_scan import scan_subdomains
from colorama import Fore, Style, init



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

    if current_os == "Windows":
        print(Fore.YELLOW + "[!] Warning: Some tools may not work natively on Windows.")
    elif current_os == "Darwin":
        print("[+] macOS detected.")
    elif current_os == "Linux":
        print("[+] Linux detected. Recommended environment.")

    target = args.target
    print(f"\n[+] Starting PhantomSurface scan on {target}\n")

    # 🔹 Subdomain Enumeration
    subdomains = scan_subdomains(target)

    # 🔹 Port & Service Scanning
    ports = scan_ports(target)
    services = scan_services(target)

    # 🔹 Risk Analysis
    risks, total_score = analyze_risks(ports)

    if total_score >= 6:
        overall_level = "HIGH"
    elif total_score >= 3:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    # 🔹 Web Scan (Python-based)
    web_result = None
    if "80" in ports or "443" in ports:
        web_result = scan_web(target)

    print("\n[+] Scan Complete")
    print("[+] Potential Risks Identified:")
    
    for severity, message in risks:
    if severity == "HIGH":
        color = Fore.RED
    elif severity == "MEDIUM":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    print(color + f" - [{severity}] {message}")
    

    print(f"\n[+] Overall Risk Score: {total_score}/10")
    print(f"[!] Overall Risk Level: {overall_level}")

    # 🔹 TXT REPORT
    with open("reports/report.txt", "w") as f:
        f.write("PhantomSurface Scan Report\n")
        f.write("=========================\n")
        f.write(f"Target: {target}\n\n")

        # Subdomains
        f.write("Discovered Subdomains:\n")
        f.write("----------------------\n")
        if subdomains:
            for sub in subdomains:
                f.write(f"- {sub}\n")
        else:
            f.write("No subdomains found\n")

        # Web Results
        if web_result:
            f.write("\nWeb Technologies Detected:\n")
            f.write("-------------------------\n")
            f.write(web_result + "\n")

        # Risks
        f.write("\nIdentified Risks:\n")
        f.write("----------------\n")
        for severity, message in risks:
            f.write(f"[{severity}] {message}\n")

        f.write(f"\nOverall Risk Score: {total_score}/10\n")
        f.write(f"Overall Risk Level: {overall_level}\n")

    print("\n[+] TXT report saved to reports/report.txt")

    # 🔹 JSON REPORT
    json_data = {
        "target": target,
        "subdomains": subdomains,
        "open_ports": ports,
        "risks": [
            {"severity": severity, "description": message}
            for severity, message in risks
        ],
        "total_score": total_score,
        "overall_risk_level": overall_level
    }

    with open("reports/report.json", "w") as jf:
        json.dump(json_data, jf, indent=4)

    print("[+] JSON report saved to reports/report.json")


if __name__ == "__main__":
    main()

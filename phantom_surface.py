#!/usr/bin/env python3

import json
import platform
import argparse
from scanner.port_scan import scan_ports
from scanner.service_scan import scan_services
from analyzer.risk_analyzer import analyze_risks
from scanner.web_scan import scan_web


def main():
    parser = argparse.ArgumentParser(description="PhantomSurface Attack Surface Mapper")
    parser.add_argument("--target", required=True, help="Target IP or Domain")
    args = parser.parse_args()

    # Detect Operating System
    current_os = platform.system()
    print(f"[+] Running on: {current_os}")

    if current_os == "Windows":
        print("[!] Warning: Some tools like WhatWeb may not work natively on Windows.")
    elif current_os == "Darwin":
        print("[+] macOS detected. Ensure Nmap and WhatWeb are installed via Homebrew.")
    elif current_os == "Linux":
        print("[+] Linux detected. Recommended environment for PhantomSurface.")

    target = args.target
    print(f"\n[+] Starting PhantomSurface scan on {target}\n")

    ports = scan_ports(target)
    services = scan_services(target)
    risks, total_score = analyze_risks(ports)

    # Determine overall risk level
    if total_score >= 6:
        overall_level = "HIGH"
    elif total_score >= 3:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    # Web Scan
    web_result = None
    if "80" in ports or "443" in ports:
        if current_os == "Windows":
            print("[!] Web scanning skipped on Windows.")
        else:
            web_result = scan_web(target)

    print("\n[+] Scan Complete")
    print("[+] Potential Risks Identified:")

    for severity, message in risks:
        print(f" - [{severity}] {message}")

    print(f"\n[+] Overall Risk Score: {total_score}/10")
    print(f"[!] Overall Risk Level: {overall_level}")

    # TXT REPORT GENERATION
    with open("reports/report.txt", "w") as f:
        f.write("PhantomSurface Scan Report\n")
        f.write("=========================\n")
        f.write(f"Target: {target}\n\n")

        if web_result:
            f.write("Web Technologies Detected:\n")
            f.write("-------------------------\n")
            f.write(web_result + "\n")

        f.write("\nIdentified Risks:\n")
        f.write("----------------\n")
        for severity, message in risks:
            f.write(f"[{severity}] {message}\n")

        f.write(f"\nOverall Risk Score: {total_score}/10\n")
        f.write(f"Overall Risk Level: {overall_level}\n")

    print("\n[+] TXT report saved to reports/report.txt")

    # JSON REPORT GENERATION
    json_data = {
        "target": target,
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

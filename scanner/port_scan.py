import subprocess
import re

def scan_ports(target):
    print("[*] Scanning open ports...")
    result = subprocess.check_output(
        ["nmap", "-Pn", "-T4", target],
        text=True
    )

    ports = re.findall(r"(\d+)/tcp\s+open", result)
    print(f"[+] Open ports found: {ports}")
    return ports

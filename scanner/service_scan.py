import subprocess

def scan_services(target):
    print("[*] Detecting services...")
    result = subprocess.check_output(
        ["nmap", "-sV", target],
        text=True
    )
    print(result)
    return result

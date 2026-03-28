import socket

def scan_subdomains(domain):
    print("[*] Starting subdomain enumeration...")

    subdomains = ["www", "mail", "ftp", "admin", "test", "dev"]
    found = []

    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            print(f"[+] Found: {full_domain} -> {ip}")
            found.append(full_domain)
        except socket.gaierror:
            pass

    if not found:
        print("[-] No subdomains found.")

    return found

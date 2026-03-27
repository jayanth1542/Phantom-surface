import requests


def scan_web(target):
    print("[*] Performing Python-based web scan...")

    urls = [
        f"http://{target}",
        f"https://{target}"
    ]

    for url in urls:
        try:
            response = requests.get(url, timeout=5)

            print(f"[+] Web service detected at {url}")
            print(f"[+] Status Code: {response.status_code}")

            server = response.headers.get("Server", "Unknown")
            powered_by = response.headers.get("X-Powered-By", "Not Disclosed")

            print(f"[+] Server: {server}")
            print(f"[+] X-Powered-By: {powered_by}")

            return (
                f"URL: {url}\n"
                f"Status Code: {response.status_code}\n"
                f"Server: {server}\n"
                f"X-Powered-By: {powered_by}\n"
            )

        except requests.RequestException:
            continue

    print("[-] No accessible web service found.")
    return None

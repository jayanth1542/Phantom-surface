import requests

def detect_technologies(domain):
    techs = set()

    urls = [f"http://{domain}", f"https://{domain}"]

    for url in urls:
        try:
            res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})

            server = res.headers.get("Server", "")
            powered = res.headers.get("X-Powered-By", "")

            if server:
                techs.add(server.split("/")[0].lower())

            if powered:
                techs.add(powered.split("/")[0].lower())

            content = res.text.lower()

            if "wordpress" in content:
                techs.add("wordpress")
            if "php" in content:
                techs.add("php")
            if "nginx" in content:
                techs.add("nginx")
            if "apache" in content:
                techs.add("apache")

        except:
            continue

    return list(techs)

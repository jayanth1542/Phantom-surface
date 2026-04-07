import datetime

def log_scan(domain):
    with open("logs.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - Scanned {domain}\n")

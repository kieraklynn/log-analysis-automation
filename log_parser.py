import os
from datetime import datetime

BAD_IPS_FILE = "bad_ips.txt"
LOG_FILE = os.path.join("logs", "sample_logs.txt")
OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "flagged_entries.txt")

def load_bad_ips(path):
    with open(path, "r") as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}

def scan_logs(log_path, bad_ips):
    alerts = []
    with open(log_path, "r") as f:
        for line in f:
            for ip in bad_ips:
                if ip in line:
                    alerts.append((ip, line.strip()))
    return alerts

def write_report(alerts, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        f.write(f"Suspicious IP Report — generated {ts}\n")
        f.write("=" * 60 + "\n")
        if not alerts:
            f.write("No suspicious activity found.\n")
        else:
            for ip, entry in alerts:
                f.write(f"[ALERT] IP: {ip} | LOG: {entry}\n")

def main():
    bad_ips = load_bad_ips(BAD_IPS_FILE)
    print(f"Loaded {len(bad_ips)} bad IPs.")
    alerts = scan_logs(LOG_FILE, bad_ips)
    for ip, entry in alerts:
        print(f"⚠️ ALERT: {ip} -> {entry}")
    write_report(alerts, OUTPUT_FILE)
    print(f"\nReport written to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

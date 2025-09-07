import sys
import os
import yaml
import requests
import socket
import concurrent.futures
import time
import traceback
from collections import defaultdict

# ---------------- Paths ----------------
ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(ROOT, ".."))
SOURCE_FILE = os.path.join(REPO_ROOT, "https://github.com/PuddinCat/BestClash/raw/refs/heads/main/proxies.yaml")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")

# ---------------- DNS / Geo ----------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def geo_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            country_code = r.json().get("country")
            country_name = r.json().get("region")
            if country_code and country_name:
                return country_code.lower(), country_name.replace(" ", "_")
    except:
        pass
    return "unknown", "Unknown"

# ---------------- Load PuddinCat proxies ----------------
def load_proxies():
    if not os.path.isfile(SOURCE_FILE):
        print(f"[FATAL] source file not found: {SOURCE_FILE}")
        sys.exit(1)
    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if "proxies" not in data:
        print(f"[FATAL] no proxies found in source file")
        sys.exit(1)
    return data["proxies"]

# ---------------- Correct node info ----------------
def correct_node(p, country_counter):
    host = str(p.get("server"))
    raw_port = str(p.get("port", ""))
    if "/" in raw_port:
        raw_port = raw_port.split("/")[0]
    try:
        port = int(raw_port)
    except ValueError:
        port = 443

    ip = resolve_ip(host) or host
    country_code, country_name = geo_ip(ip)

    # increment country counter
    country_counter[country_code] += 1
    index = country_counter[country_code]

    # rename node
    p["name"] = f"{country_code}_{country_name}_{index}"
    p["flag"] = country_code

    # update port in case original is malformed
    p["port"] = port
    return p

# ---------------- Main ----------------
def main():
    proxies = load_proxies()
    print(f"[start] loaded {len(proxies)} nodes from PuddinCat")

    # Correct flags, country, and add index
    country_counter = defaultdict(int)
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                corrected_nodes.append(f.result())
            except Exception as e:
                print("[job error]", e)

    print(f"[done] corrected {len(corrected_nodes)} nodes")

    # ---------------- Build full Clash config template ----------------
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:53",
            "default-nameserver": ["223.5.5.5", "114.114.114.114"],
            "fallback": ["1.1.1.1", "8.8.8.8"]
        },
        "proxies": corrected_nodes,
        "proxy-groups": [
            {
                "name": "Auto",
                "type": "url-test",
                "proxies": [p["name"] for p in corrected_nodes],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            },
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["Auto", "DIRECT"]
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-KEYWORD,youtube,PROXY",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY"
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)

    print(f"[done] wrote full Clash config to {OUTPUT_FILE}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

import sys
import os
import yaml
import requests
import socket
import concurrent.futures
import traceback
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
PUDDIN_URL = "https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml"
NODE_SUFFIX = "@SHFX"  # suffix for node names

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
                return country_code.upper(), country_name.replace(" ", "_")
    except:
        pass
    return "XX", "Unknown"

def country_code_to_emoji(code):
    # Convert ISO country code to emoji flag
    OFFSET = 127397
    if len(code) != 2:
        return "🏳️"  # default white flag if invalid
    return chr(ord(code[0]) + OFFSET) + chr(ord(code[1]) + OFFSET)

# ---------------- Load proxies from PuddinCat ----------------
def load_proxies():
    try:
        r = requests.get(PUDDIN_URL, timeout=15)
        r.raise_for_status()
        data = yaml.safe_load(r.text)
        if "proxies" not in data:
            print(f"[FATAL] no proxies found in source URL")
            sys.exit(1)
        return data["proxies"]
    except Exception as e:
        print(f"[FATAL] failed to fetch PuddinCat proxies -> {e}")
        sys.exit(1)

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

# Use outlet_ip if exists, else server
    ip_for_country = p.get("outlet_ip") or p.get("server")
    country_code, country_name = geo_ip(ip_for_country)

    # increment country counter
    country_counter[country_code] += 1
    index = country_counter[country_code]

    # Emoji flag
    flag_emoji = country_code_to_emoji(country_code)

    # rename node with format: 🇺🇸|US1|@SHFX
    p["name"] = f"{flag_emoji}|{country_code}{index}|{NODE_SUFFIX}"
    p["flag"] = flag_emoji

    # ensure port is int
    raw_port = str(p.get("port") or p.get("server_port", 443))
    if "/" in raw_port:
        raw_port = raw_port.split("/")[0]
    try:
        p["port"] = int(raw_port)
    except ValueError:
        p["port"] = 443

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
        "port": 7890,
        "socks-port": 7891,
        "redir-port": 7892,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:53",
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
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

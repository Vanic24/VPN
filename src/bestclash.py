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

def country_code_to_emoji(code):
    OFFSET = 127397
    if len(code) != 2:
        return "🏳️"
    return chr(ord(code[0]) + OFFSET) + chr(ord(code[1]) + OFFSET)

def geo_ip(ip):
    """Get country code and region from IP"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        r.raise_for_status()
        data = r.json()
        country_code = data.get("country", "XX").upper()
        country_name = data.get("region", "Unknown").replace(" ", "_")
        return country_code, country_name
    except:
        return "XX", "Unknown"

# ---------------- Get outlet IP ----------------
def get_outlet_ip(node):
    """
    Simulate Karing: get outlet IP for node using api.ipify.org
    node: dict with server info
    returns: outlet_ip string
    """
    try:
        # NOTE: this only works if node is HTTP/SOCKS proxy
        proxy = f"http://{node['server']}:{node['port']}"
        proxies = {"http": proxy, "https": proxy}
        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=8).text.strip()
        return ip
    except:
        # fallback to server IP if cannot connect
        return node.get("server")

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

    p["port"] = port

    # Get outlet IP like Karing
    outlet_ip = get_outlet_ip(p)
    p["outlet_ip"] = outlet_ip

    # Get country/region from outlet IP
    country_code, country_name = geo_ip(outlet_ip)

    # increment country counter
    country_counter[country_code] += 1
    index = country_counter[country_code]

    # emoji flag
    flag_emoji = country_code_to_emoji(country_code)

    # rename node like: 🇺🇸|US1|@SHFX
    p["name"] = f"{flag_emoji}|{country_code}{index}|{NODE_SUFFIX}"
    p["flag"] = flag_emoji
    p["latency"] = ""  # you can measure latency here if needed
    p["outlet_region"] = country_name

    return p

# ---------------- Main ----------------
def main():
    proxies = load_proxies()
    print(f"[start] loaded {len(proxies)} nodes from PuddinCat")

    country_counter = defaultdict(int)
    corrected_nodes = []

    # use thread pool for parallel outlet IP and geo check
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
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

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
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
CLASH_TEMPLATE_URL = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR.ini"

# ---------------- Inputs ----------------
USE_LATENCY = os.environ.get("LATENCY_FILTER", "false").lower() == "true"
LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))  # ms

# ---------------- Helpers ----------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def tcp_latency_ms(host, port, timeout=2.0):
    try:
        import time
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return 9999

def geo_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            cc = data.get("country")
            if cc:
                return cc.lower(), cc.upper()
    except:
        pass
    return "unknown", "UN"

def country_to_flag(cc):
    """Convert 2-letter country code to flag emoji."""
    if not cc or len(cc) != 2:
        return "🏳️"
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + \
           chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] sources.txt not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

# ---------------- Load proxies from URLs ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = yaml.safe_load(r.text)
        if "proxies" in data:
            return data["proxies"]
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return []

# ---------------- Correct node ----------------
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
    cc_lower, cc_upper = geo_ip(ip)
    flag = country_to_flag(cc_upper)

    # latency check
    latency = tcp_latency_ms(host, port)

    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None  # filtered out

    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    # rename
    p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    p["port"] = port
    return p

# ---------------- Load external Clash template ----------------
def load_clash_template():
    try:
        r = requests.get(CLASH_TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        data = yaml.safe_load(r.text)
        if not isinstance(data, dict):
            print("[warn] fetched template is not valid YAML dict, creating empty template")
            data = {}
        return data
    except Exception as e:
        print(f"[warn] failed to fetch Clash template -> {e}, creating empty template")
        return {}

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_proxies = []
    for url in sources:
        proxies = load_proxies(url)
        print(f"[source] {url} -> {len(proxies)} proxies")
        all_proxies.extend(proxies)

    print(f"[collect] total {len(all_proxies)} proxies")

    country_counter = defaultdict(int)
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    # ---------------- Load Clash template ----------------
    clash_config = load_clash_template()

    # Replace proxies section with corrected nodes
    clash_config["proxies"] = corrected_nodes

    # If proxy-groups exist, update the list to use new node names
    if "proxy-groups" in clash_config:
        for group in clash_config["proxy-groups"]:
            if "proxies" in group:
                group["proxies"] = [p["name"] for p in corrected_nodes]

    # Write final YAML
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)

    print(f"[done] wrote {OUTPUT_FILE}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

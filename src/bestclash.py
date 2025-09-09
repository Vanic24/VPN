import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
import subprocess
import time
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"

XRAY_BIN = os.path.join("Xray", "xray.exe")
XRAY_CONFIG_DIR = os.path.join(REPO_ROOT, "config")
XRAY_TIMEOUT = 10  # seconds before force kill

# ---------------- Inputs ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"

try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

# ---------------- Helpers ----------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def tcp_latency_ms(host, port, timeout=2.0):
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return int((time.time() - start) * 1000)
    except:
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
    if not cc or len(cc) != 2:
        return "🏳️"
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + \
           chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

# ---------------- Xray Outbound IP ----------------
def get_outbound_ip(node, index):
    process = None
    try:
        os.makedirs(XRAY_CONFIG_DIR, exist_ok=True)
        cfg_file = os.path.join(XRAY_CONFIG_DIR, f"node_{index}.json")

        # write single-node config
        with open(cfg_file, "w", encoding="utf-8") as f:
            yaml.dump({"outbounds": [node]}, f, allow_unicode=True)

        process = subprocess.Popen([XRAY_BIN, "run", f"-config={cfg_file}"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        start_time = time.time()
        outlet_ip = None
        while time.time() - start_time < XRAY_TIMEOUT:
            try:
                proxies = {"http": "http://127.0.0.1:1080", "https": "http://127.0.0.1:1080"}
                r = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=3)
                if r.status_code == 200:
                    outlet_ip = r.json().get("ip")
                    break
            except:
                time.sleep(1)

        # kill after timeout or success
        if process and process.poll() is None:
            process.kill()

        if outlet_ip:
            cc_lower, cc_upper = geo_ip(outlet_ip)
            flag = country_to_flag(cc_upper)
            node["outlet_ip"] = outlet_ip
            node["outlet_region"] = cc_upper
            node["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
        return node
    except Exception as e:
        print("[xray error]", e)
        if process and process.poll() is None:
            process.kill()
        return None

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] sources.txt not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not sources:
        print(f"[FATAL] sources.txt is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

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
        return None  # skip → outbound ip check won’t run

    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    # assign temporary name
    p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    p["port"] = port
    return p

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
    filtered_nodes = []

    # Step 1: Latency filter
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    filtered_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[filter] {len(filtered_nodes)} nodes passed latency filter (<= {LATENCY_THRESHOLD}ms)")

    # Step 2: Outbound IP check only for filtered nodes
    final_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(get_outbound_ip, node, i+1) for i, node in enumerate(filtered_nodes)]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    final_nodes.append(res)
            except Exception as e:
                print("[outbound error]", e)

    print(f"[done] {len(final_nodes)} nodes with outbound IP info")

    # ---------------- Load template as text ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert proxies to YAML block ----------------
    proxies_yaml_block = yaml.dump(final_nodes, allow_unicode=True, default_flow_style=False)

    # ---------------- Build proxy names block ----------------
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in final_nodes])

    # ---------------- Replace placeholders ----------------
    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

    # ---------------- Write output ----------------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"[done] wrote {OUTPUT_FILE}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

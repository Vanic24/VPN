import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
import subprocess
import time
import json
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"

# ---------------- Inputs ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"

try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

MIHOMO_BIN = os.path.join(REPO_ROOT, "mihomo")

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
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

def start_mihomo(node_dict):
    """
    Start mihomo in HTTP proxy mode for outbound IP detection
    """
    temp_yaml = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    with open(temp_yaml, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": [node_dict], "port": 0}, f, allow_unicode=True)
    try:
        proc = subprocess.Popen([MIHOMO_BIN, "-f", temp_yaml, "--mode", "http"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)  # wait for proxy to start
        # Check outbound IP
        r = requests.get("https://api.ipify.org?format=json", proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=5)
        ip = r.json().get("ip")
        proc.kill()
        return ip
    except Exception as e:
        print(f"[warn] Mihomo failed for {node_dict.get('server')}:{node_dict.get('port')} -> {e}")
        try: proc.kill()
        except: pass
        return None

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] sources.txt not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not sources:
        print(f"[FATAL] sources.txt is empty.")
        sys.exit(1)
    return sources

# ---------------- Load proxies from URL ----------------
def load_proxies(url):
    proxies = []
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text.strip()
        if text.startswith("{") or text.startswith("---"):  # YAML/Clash format
            data = yaml.safe_load(text)
            if "proxies" in data:
                proxies.extend(data["proxies"])
        else:  # raw protocol links
            lines = text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if any(line.startswith(proto) for proto in ["vmess://", "vless://", "trojan://", "ss://", "socks://", "hysteria2://", "anytls://"]):
                    proxies.append({"raw": line})
                else:
                    print(f"[skip] unsupported line: {line[:50]}...")
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return proxies

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    # If raw protocol link, convert to minimal dict with server/port
    server = p.get("server") or "unknown"
    port = p.get("port") or 443
    if "raw" in p:
        server = "unknown"
        port = 443

    ip = resolve_ip(server) or server
    cc_lower, cc_upper = geo_ip(ip)
    flag = country_to_flag(cc_upper)

    # latency check
    latency = tcp_latency_ms(server, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None

    # detect real outbound IP using Mihomo
    node_for_mihomo = {
        "server": server,
        "port": port,
        "type": p.get("type", "vless"),
        "name": p.get("name", "node"),
        "uuid": p.get("uuid", "")
    }
    real_ip = start_mihomo(node_for_mihomo)
    if real_ip:
        cc_lower, cc_upper = geo_ip(real_ip)
        flag = country_to_flag(cc_upper)

    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    # rename
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
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    # ---------------- Load template as text ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert proxies to YAML block ----------------
    proxies_yaml_block = yaml.dump(corrected_nodes, allow_unicode=True, default_flow_style=False)

    # ---------------- Build proxy names block ----------------
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected_nodes])

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

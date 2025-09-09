import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import subprocess
import time
import traceback
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"
MIHOMO_BIN = os.path.join(REPO_ROOT, "mihomo", "mihomo")

# ---------------- Inputs ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"
try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

# ---------------- Helpers ----------------
VALID_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "hysteria2://", "anytls://")

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return host  # fallback to host itself

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

def filter_valid_nodes(raw_nodes):
    valid_nodes = []
    for line in raw_nodes:
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith(VALID_PREFIXES):
            valid_nodes.append(line)
        else:
            print(f"[skip] invalid line skipped -> {line[:50]}...")
    return valid_nodes

# ---------------- Mihomo helpers ----------------
def get_outbound_ip(node_yaml_path):
    try:
        # Run mihomo in HTTP mode
        cmd = [MIHOMO_BIN, "-c", node_yaml_path, "--mode", "http", "--timeout", "5"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("OUTBOUND_IP:"):
                    return line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"[warn] Mihomo failed -> {e}")
    return None

# ---------------- Node processing ----------------
def correct_node(node_line, country_counter):
    temp_yaml = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    # Write single node to mihomo YAML format
    try:
        with open(temp_yaml, "w", encoding="utf-8") as f:
            f.write("proxies:\n")
            f.write(f"  - {node_line}\n")
    except Exception as e:
        print(f"[job error] failed to write temp YAML -> {e}")
        return None

    # Extract host & port for latency check
    host, port = None, None
    try:
        if node_line.startswith(("vmess://", "vless://", "trojan://")):
            # crude parsing for host:port
            if "@" in node_line:
                part = node_line.split("@")[1]
                host = part.split(":")[0]
                port = int(part.split(":")[1].split("?")[0])
            else:
                host, port = None, 443
        elif node_line.startswith(("ss://", "socks://", "hysteria2://", "anytls://")):
            host, port = None, 443
        else:
            return None
    except:
        host, port = None, 443

    ip = resolve_ip(host) if host else None
    latency = tcp_latency_ms(host, port) if host else 0
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        print(f"[skip] node skipped due to high latency {latency}ms -> {node_line[:50]}...")
        return None

    # Get real outbound IP via Mihomo
    outlet_ip = get_outbound_ip(temp_yaml)
    if outlet_ip:
        cc_lower, cc_upper = geo_ip(outlet_ip)
    else:
        cc_lower, cc_upper = geo_ip(ip or host)
    flag = country_to_flag(cc_upper)

    # Rename node
    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]
    return {
        "name": f"{flag}|{cc_upper}{index}|@SHFX",
        "raw": node_line,
        "outlet_ip": outlet_ip or "unknown",
        "latency": latency
    }

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_raw_nodes = []
    for url in sources:
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            raw_lines = r.text.splitlines()
            valid_nodes = filter_valid_nodes(raw_lines)
            print(f"[source] {url} -> {len(valid_nodes)} valid nodes")
            all_raw_nodes.extend(valid_nodes)
        except Exception as e:
            print(f"[warn] failed to fetch {url} -> {e}")

    print(f"[collect] total {len(all_raw_nodes)} nodes")

    country_counter = defaultdict(int)
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(correct_node, node, country_counter) for node in all_raw_nodes]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    # ---------------- Load template ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert proxies to YAML block ----------------
    proxies_yaml_block = yaml.dump([n["raw"] for n in corrected_nodes], allow_unicode=True, default_flow_style=False)
    proxy_names_block = "\n".join([f"      - {n['name']}" for n in corrected_nodes])

    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

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

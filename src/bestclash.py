import os
import sys
import yaml
import requests
import socket
import subprocess
import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"
MIHOMO_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.13/mihomo-linux-amd64-v3-v1.19.13.gz"
MIHOMO_BIN = os.path.join(REPO_ROOT, "mihomo")

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
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

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

# ---------------- Load proxies ----------------
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

# ---------------- Parse node to JSON ----------------
def parse_node_to_json(node_line, name_override=None):
    """
    Accept both dict (Clash node) or string node
    """
    if isinstance(node_line, dict):
        node_json = node_line.copy()
        if name_override:
            node_json["name"] = name_override
        return node_json
    # For string-based protocols, you can extend parsing here if needed
    return None

# ---------------- Start Mihomo to get real outbound IP ----------------
def start_mihomo(node_dict):
    """
    Start mihomo with HTTP proxy mode to detect real outbound IP
    """
    if not os.path.exists(MIHOMO_BIN):
        # Download and decompress
        print("[info] downloading Mihomo binary...")
        import gzip
        import shutil
        r = requests.get(MIHOMO_URL, timeout=30)
        with open(MIHOMO_BIN + ".gz", "wb") as f:
            f.write(r.content)
        with gzip.open(MIHOMO_BIN + ".gz", "rb") as f_in, open(MIHOMO_BIN, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.chmod(MIHOMO_BIN, 0o755)
        os.remove(MIHOMO_BIN + ".gz")
        print("[info] Mihomo ready.")

    # Save temporary config
    temp_yaml = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    with open(temp_yaml, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": [node_dict]}, f, allow_unicode=True)

    try:
        proc = subprocess.Popen([MIHOMO_BIN, "-c", temp_yaml, "--http-proxy", "127.0.0.1:0", "--once", "--timeout", "5"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=15)
        # Fetch real IP
        r = requests.get("https://api.ipify.org/?format=json", timeout=5)
        real_ip = r.json().get("ip", "")
        return real_ip
    except Exception as e:
        print(f"[warn] Mihomo failed for {node_dict.get('server')}:{node_dict.get('port')} -> {e}")
        return None
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)

# ---------------- Correct node ----------------
def correct_node(node, country_counter):
    if isinstance(node, dict):
        host = str(node.get("server"))
        port = int(node.get("port", 443))
    else:
        return None

    # Skip invalid host
    if not host or host.startswith("#"):
        return None

    # latency check
    latency = tcp_latency_ms(host, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None

    # get real outbound IP via Mihomo
    real_ip = start_mihomo(node)
    if real_ip:
        cc_lower, cc_upper = geo_ip(real_ip)
    else:
        cc_lower, cc_upper = geo_ip(host)

    flag = country_to_flag(cc_upper)
    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    # Update node name
    node["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    node["port"] = port
    return node

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_nodes = []
    for url in sources:
        proxies = load_proxies(url)
        for p in proxies:
            # Accept only proper protocols
            if isinstance(p, dict):
                if p.get("type", "").lower() in ["vmess", "vless", "trojan", "ss", "socks", "hysteria2", "anytls"]:
                    all_nodes.append(p)

    print(f"[collect] total {len(all_nodes)} nodes collected")

    country_counter = defaultdict(int)
    corrected_nodes = []

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(correct_node, node, country_counter) for node in all_nodes]
        for f in futures:
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    # Load template
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # Convert proxies to YAML block
    proxies_yaml_block = yaml.dump(corrected_nodes, allow_unicode=True, default_flow_style=False)

    # Build proxy names block
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected_nodes])

    # Replace placeholders
    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

    # Write output
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

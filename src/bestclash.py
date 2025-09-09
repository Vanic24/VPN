import os
import sys
import yaml
import json
import time
import socket
import base64
import random
import requests
import subprocess
import concurrent.futures
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")

MIHOMO_BIN = "./mihomo"  # Mihomo must exist in repo
LATENCY_LIMIT = 100  # ms
VALID_PREFIXES = ("vmess://", "vless://", "trojan://", "hysteria2://", "anytls://", "ss://", "socks://")

# ---------------- Utils ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[error] {SOURCES_FILE} not found.")
        sys.exit(1)

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def fetch_url(url):
    try:
        print(f"[fetch] {url}")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        content = resp.text.strip()
        return content
    except Exception as e:
        print(f"[warn] failed to fetch {url}: {e}")
        return ""

def parse_subscription(content):
    """
    Parse subscription which may be raw (base64 vmess list),
    mixed node URLs, or Clash YAML.
    Returns: list of node urls
    """
    nodes = []

    # --- Try YAML parse ---
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            for p in data["proxies"]:
                # Dump back as clash format json string
                nodes.append(json.dumps(p, ensure_ascii=False))
            return nodes
    except Exception:
        pass

    # --- Raw base64 subscription (common for vmess/ss) ---
    try:
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        lines = decoded.splitlines()
        for line in lines:
            if line.strip().lower().startswith(VALID_PREFIXES):
                nodes.append(line.strip())
        if nodes:
            return nodes
    except Exception:
        pass

    # --- Raw text nodes ---
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith(VALID_PREFIXES):
            nodes.append(line)

    return nodes

def filter_valid_nodes(nodes):
    return [n for n in nodes if n.lower().startswith(VALID_PREFIXES)]

def ping_host(host, port, timeout=1):
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return None

def test_latency(node_url):
    """ Extract host/port and ping """
    try:
        if node_url.startswith("vmess://"):
            raw = base64.b64decode(node_url[8:]).decode()
            obj = json.loads(raw)
            host = obj.get("add")
            port = int(obj.get("port", 443))
        elif node_url.startswith(("vless://", "trojan://", "ss://", "socks://", "hysteria2://", "anytls://")):
            part = node_url.split("://", 1)[1]
            addr = part.split("@")[-1].split("#")[0]
            if ":" in addr:
                host, port = addr.split(":")[0], int(addr.split(":")[1].split("?")[0])
            else:
                return None
        else:
            return None

        latency = ping_host(host, port)
        return latency
    except Exception:
        return None

def run_mihomo_test(node_url):
    """ Start Mihomo with one node and get outbound IP """
    try:
        temp_yaml = "mihomo_temp.yaml"
        conf = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "Rule",
            "log-level": "silent",
            "proxies": [node_url],  # simplified
        }
        with open(temp_yaml, "w", encoding="utf-8") as f:
            yaml.dump(conf, f, allow_unicode=True)

        proc = subprocess.Popen([MIHOMO_BIN, "-f", temp_yaml], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)

        proxies = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
        ip = None
        for _ in range(5):
            try:
                r = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=5)
                if r.ok:
                    ip = r.json().get("ip")
                    break
            except Exception:
                time.sleep(1)

        proc.kill()
        os.remove(temp_yaml)
        return ip
    except Exception as e:
        print(f"[warn] Mihomo failed for node: {e}")
        return None

def get_country_flag(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        data = r.json()
        country = data.get("country_name", "Unknown")
        code = data.get("country_code", "UN")
        flag = chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))
        return code, flag, country
    except Exception:
        return "UN", "🏴", "Unknown"

# ---------------- Main ----------------
def main():
    all_nodes = []
    sources = load_sources()

    for url in sources:
        content = fetch_url(url)
        if not content:
            continue
        nodes = parse_subscription(content)
        nodes = filter_valid_nodes(nodes)
        all_nodes.extend(nodes)

    print(f"[info] Total nodes collected: {len(all_nodes)}")

    # Latency filter
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_map = {executor.submit(test_latency, n): n for n in all_nodes}
        for fut in concurrent.futures.as_completed(future_map):
            node = future_map[fut]
            latency = fut.result()
            if latency and latency <= LATENCY_LIMIT:
                print(f"[ok] {node[:40]}... -> {latency} ms")
                valid_nodes.append(node)
            else:
                print(f"[skip] {node[:40]}... too slow/unreachable")

    print(f"[info] Latency passed nodes: {len(valid_nodes)}")

    final_nodes = []
    for idx, node in enumerate(valid_nodes, start=1):
        ip = run_mihomo_test(node)
        if not ip:
            continue
        code, flag, country = get_country_flag(ip)
        name = f"{flag}{country}｜{idx:02d}｜原生IP"

        node_dict = {
            "name": name,
            "server": ip,
            "port": 443,
            "type": "auto",  # placeholder
            "sni": None,
            "up": None,
            "down": None,
            "skip-cert-verify": True,
            "password": None,
        }
        final_nodes.append(node_dict)

    print(f"[done] Final nodes: {len(final_nodes)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(final_nodes, f, allow_unicode=True, default_flow_style=False)

    print(f"[save] {OUTPUT_FILE} updated.")

if __name__ == "__main__":
    main()

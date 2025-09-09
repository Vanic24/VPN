import os
import sys
import json
import yaml
import time
import socket
import base64
import requests
import subprocess
import concurrent.futures
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")

VALID_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "hysteria2://", "anytls://")
PING_TIMEOUT = 2
PING_LIMIT = 100  # ms

# ---------------- Helpers ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[error] {SOURCES_FILE} not found")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def fetch_url(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
        return ""

def decode_base64(data):
    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def parse_subscription(content):
    """Detect whether content is raw nodes (base64/urls) or YAML config"""
    nodes = []

    # Try YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            for p in data["proxies"]:
                nodes.append(p)
            return nodes
    except Exception:
        pass

    # Try base64 (vmess/vless style subs)
    decoded = decode_base64(content.strip())
    if decoded and any(prefix in decoded for prefix in VALID_PREFIXES):
        for line in decoded.splitlines():
            if line.strip().startswith(VALID_PREFIXES):
                nodes.append(line.strip())
        return nodes

    # Raw plain text nodes
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith(VALID_PREFIXES):
            nodes.append(line)
    return nodes

def filter_valid_nodes(raw_nodes):
    valid_nodes = []
    for line in raw_nodes:
        if isinstance(line, str) and line.lower().startswith(VALID_PREFIXES):
            valid_nodes.append(line)
        elif isinstance(line, dict) and "type" in line and "server" in line:
            valid_nodes.append(line)
        else:
            print(f"[skip] invalid node skipped -> {str(line)[:50]}...")
    return valid_nodes

def ping_server(host):
    try:
        start = time.time()
        socket.gethostbyname(host)  # DNS check
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PING_TIMEOUT)
        s.connect((host, 80))
        s.close()
        latency = int((time.time() - start) * 1000)
        return latency
    except Exception:
        return None

def run_mihomo(proxy_conf):
    """Launch Mihomo to get outbound IP"""
    tmpfile = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    with open(tmpfile, "w", encoding="utf-8") as f:
        yaml.safe_dump({"proxies": [proxy_conf]}, f)

    try:
        result = subprocess.run(
            ["mihomo", "-f", tmpfile],
            capture_output=True,
            text=True,
            timeout=20
        )
        os.remove(tmpfile)
        return result.stdout
    except Exception as e:
        print(f"[warn] Mihomo failed for {proxy_conf.get('server')}:{proxy_conf.get('port')} -> {e}")
        return ""

def get_ip_info(ip):
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10).json()
        return resp.get("country_code", "XX"), resp.get("country_name", "Unknown")
    except Exception:
        return "XX", "Unknown"

def node_to_json(node, index, country_code, country_name):
    name = f"@SHFX | {country_name}｜{str(index).zfill(2)}"
    return {
        "name": name,
        "server": node.get("server"),
        "port": node.get("port"),
        "sni": node.get("sni") if "sni" in node else None,
        "up": None,
        "down": None,
        "skip-cert-verify": True,
        "type": node.get("type"),
        "password": node.get("password") if "password" in node else None
    }

# ---------------- Main ----------------
def main():
    print("[info] loading sources...")
    sources = load_sources()

    all_nodes = []
    for src in sources:
        content = fetch_url(src)
        if not content:
            continue
        nodes = parse_subscription(content)
        all_nodes.extend(nodes)

    print(f"[info] total raw nodes: {len(all_nodes)}")
    nodes = filter_valid_nodes(all_nodes)
    print(f"[info] valid nodes: {len(nodes)}")

    final_nodes = []
    index = 1

    for node in nodes:
        if isinstance(node, str):
            # TODO: convert url (vmess:// etc) into dict config
            continue  # skipping for now

        host = node.get("server")
        latency = ping_server(host)
        if not latency or latency > PING_LIMIT:
            continue

        out = run_mihomo(node)
        outbound_ip = None
        for line in out.splitlines():
            if "your ip" in line.lower():
                outbound_ip = line.split()[-1]
                break

        if not outbound_ip:
            continue

        cc, cname = get_ip_info(outbound_ip)
        json_node = node_to_json(node, index, cc, cname)
        final_nodes.append(json_node)
        index += 1

    print(f"[info] total filtered nodes: {len(final_nodes)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, ensure_ascii=False)

    print(f"[done] saved {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

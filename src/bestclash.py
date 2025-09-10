import os
import sys
import yaml
import base64
import requests
import socket
import concurrent.futures
import traceback
from urllib.parse import urlparse, unquote
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_TXT = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_YAML = os.path.join(REPO_ROOT, "nodes.yaml")
LATENCY_TIMEOUT = 3
MAX_WORKERS = 30

# --------------- Utils ------------------
def log(msg):
    print(f"[INFO] {msg}")

def load_sources():
    if not os.path.exists(SOURCES_TXT):
        log("sources.txt not found.")
        return []
    with open(SOURCES_TXT, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def fetch_url(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.text
        else:
            log(f"❌ Skipping {url} (HTTP {r.status_code})")
    except Exception as e:
        log(f"❌ Skipping {url} ({e})")
    return ""

def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def check_latency(server, port):
    try:
        with socket.create_connection((server, port), timeout=LATENCY_TIMEOUT):
            return True
    except Exception:
        return False

def geoip_country(ip):
    # Minimal placeholder
    return "US"

# ----------- Subscription Parser -----------
def parse_subscription(content):
    nodes = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.startswith("vmess://"):
                nodes.append(parse_vmess(line))
            elif line.startswith("vless://"):
                nodes.append(parse_vless(line))
            elif line.startswith("trojan://"):
                nodes.append(parse_trojan(line))
            elif line.startswith("ss://"):
                nodes.append(parse_ss(line))
            elif line.startswith("hysteria2://"):
                nodes.append(parse_hysteria2(line))
            elif line.startswith("anytls://"):
                nodes.append(parse_anytls(line))
            elif line.startswith("proxies:"):  # YAML style
                try:
                    y = yaml.safe_load(content)
                    if "proxies" in y:
                        for p in y["proxies"]:
                            nodes.append(p)
                except Exception:
                    pass
            else:
                log(f"⚠️ Skipping unknown format line: {line[:40]}")
        except Exception as e:
            log(f"⚠️ Error parsing line: {e}")
    return [n for n in nodes if n]

# ----------- Protocol Parsers -----------
def parse_vmess(line):
    raw = line[len("vmess://") :]
    data = decode_base64(raw)
    import json
    j = json.loads(data)
    return {
        "name": j.get("ps", "VMESS"),
        "type": "vmess",
        "server": j["add"],
        "port": int(j["port"]),
        "uuid": j["id"],
        "alterId": j.get("aid", 0),
        "cipher": "auto",
        "tls": j.get("tls", ""),
        "network": j.get("net", ""),
        "ws-opts": {"path": j.get("path", ""), "headers": {"Host": j.get("host", "")}},
    }

def parse_vless(line):
    u = urlparse(line)
    return {
        "name": u.fragment or "VLESS",
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "tls": "tls" if "tls" in u.query else "",
    }

def parse_trojan(line):
    u = urlparse(line)
    return {
        "name": u.fragment or "TROJAN",
        "type": "trojan",
        "server": u.hostname,
        "port": u.port,
        "password": u.username,
        "sni": u.query,
    }

def parse_ss(line):
    return {
        "name": "SS",
        "type": "ss",
        "server": "unknown",
        "port": 0,
        "cipher": "aes-128-gcm",
        "password": "none",
    }

def parse_hysteria2(line):
    u = urlparse(line)
    return {
        "name": u.fragment or "HYSTERIA2",
        "type": "hysteria2",
        "server": u.hostname,
        "port": u.port,
        "auth_str": u.username,
    }

def parse_anytls(line):
    u = urlparse(line)
    return {
        "name": u.fragment or "ANYTLS",
        "type": "anytls",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
    }

# ----------- Main Workflow -----------
def main():
    sources = load_sources()
    all_nodes = []

    for url in sources:
        log(f"Fetching {url}")
        content = fetch_url(url)
        if not content:
            log(f"⚠️ Empty subscription from {url}")
            continue

        # Base64 check
        if all(c.isalnum() or c in "+/=\n" for c in content.strip()):
            decoded = decode_base64(content.strip())
            if decoded:
                content = decoded

        nodes = parse_subscription(content)
        if not nodes:
            log(f"⚠️ No valid nodes from {url}")
            continue

        log(f"✅ Got {len(nodes)} nodes from {url}")
        all_nodes.extend(nodes)

    # Dedup by (server, port, type, uuid/pass)
    seen = set()
    unique_nodes = []
    for n in all_nodes:
        key = (n.get("server"), n.get("port"), n.get("type"), n.get("uuid", n.get("password")))
        if key not in seen:
            seen.add(key)
            unique_nodes.append(n)

    # Latency filtering
    alive_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut_map = {ex.submit(check_latency, n["server"], n["port"]): n for n in unique_nodes if n.get("server") and n.get("port")}
        for fut in concurrent.futures.as_completed(fut_map):
            n = fut_map[fut]
            try:
                if fut.result():
                    alive_nodes.append(n)
            except Exception:
                pass

    # Assign names
    proxies = []
    for idx, n in enumerate(alive_nodes, 1):
        cc = geoip_country(n.get("server"))
        n["name"] = f"🇺🇸|{cc}{idx}|@SHFX"
        proxies.append(n)

    yaml_dict = {"proxies": proxies}

    with open(OUTPUT_YAML, "w", encoding="utf-8") as f:
        yaml.dump(yaml_dict, f, allow_unicode=True, sort_keys=False)

    log(f"✅ Wrote {len(proxies)} proxies to {OUTPUT_YAML}")

if __name__ == "__main__":
    main()

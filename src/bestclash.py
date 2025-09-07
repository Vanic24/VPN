import sys
import os
import yaml
import requests
import socket
import concurrent.futures
import time
import subprocess
import json
import traceback

# ---------------- Paths ----------------
ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(ROOT, ".."))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
V2RAY_EXE = os.path.join(REPO_ROOT, "v2ray")  # Path to v2ray-core executable

# ---------------- DNS / Geo-IP ----------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def geo_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            country = r.json().get("country")
            if country:
                return country.lower()
    except:
        pass
    return None

# ---------------- Load / Parse ----------------
def load_sources():
    urls = []
    if not os.path.isfile(SOURCES_FILE):
        print(f"[warn] sources.txt not found at {SOURCES_FILE}")
        return urls
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                urls.append(u)
    return urls

def fetch_yaml(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[fetch] FAIL {url} -> {e}")
        return None

def parse_yaml(content, url=""):
    try:
        data = yaml.safe_load(content)
        if not data:
            print(f"[parse] {url} -> empty")
            return []
        if "proxies" in data:
            proxies = data["proxies"]
            print(f"[parse] {url} -> {len(proxies)} proxies (yaml)")
            return proxies
        else:
            print(f"[parse] {url} -> unsupported format, skipped")
            return []
    except Exception as e:
        print(f"[parse] {url} -> FAIL {e}")
        return []

# ---------------- V2Ray Node Test ----------------
def test_v2ray_node(node, timeout=10):
    """
    Test the node using v2ray-core with a short HTTP request.
    Returns latency in ms if success, else None.
    """
    # Create temporary config for this node
    config = {
        "inbounds": [{"port": 1081, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": node.get("type", "vmess"),
                       "settings": node,
                       "streamSettings": node.get("streamSettings", {})}]
    }
    tmp_config_path = "tmp_node_config.json"
    with open(tmp_config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False)

    start = time.time()
    try:
        # Run v2ray-core in test mode for 1 request to generate_204
        proc = subprocess.run([
            V2RAY_EXE, "-c", tmp_config_path, "--test", "https://www.gstatic.com/generate_204"
        ], capture_output=True, text=True, timeout=timeout)

        if proc.returncode == 0:
            latency = int((time.time() - start) * 1000)
            ip = resolve_ip(node.get("server")) or node.get("server")
            country = geo_ip(ip)
            if country:
                node["flag"] = country
            return (node, latency)
        else:
            return None
    except Exception as e:
        print(f"[v2ray-test] {node.get('server')} failed -> {e}")
        return None
    finally:
        if os.path.exists(tmp_config_path):
            os.remove(tmp_config_path)

# ---------------- Main ----------------
def main():
    urls = load_sources()
    print(f"[start] loaded {len(urls)} sources")

    all_proxies = []
    for url in urls:
        text = fetch_yaml(url)
        if text:
            all_proxies.extend(parse_yaml(text, url))

    print(f"[collect] total proxies: {len(all_proxies)}")

    # Deduplicate by server:port
    seen = set()
    unique = []
    for p in all_proxies:
        sid = f"{p.get('server')}:{p.get('port')}"
        if sid not in seen:
            seen.add(sid)
            unique.append(p)

    print(f"[dedupe] unique proxies: {len(unique)}")

    # Test nodes using v2ray-core in parallel
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(test_v2ray_node, p) for p in unique]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    # Filter latency <= 100ms
    filtered = [r for r in results if r[1] <= 100]
    filtered.sort(key=lambda x: x[1])

    print(f"[filter] {len(filtered)} working nodes ≤ 100ms latency")

    # Build YAML
    out = {"proxies": [r[0] for r in filtered]}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True)

    print(f"[done] wrote {len(filtered)} proxies to {OUTPUT_FILE}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")  # now expects repo root
OUTPUT_FILE = os.path.join(REPO_ROOT, "..", "proxies.yaml")

LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
USE_LATENCY_FILTER = os.environ.get("LATENCY_FILTER", "true").lower() == "true"

MIHOMO_BIN = os.path.join(REPO_ROOT, "..", "mihomo", "mihomo")

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

def ping(host, port=80, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def fetch_subscription(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        content = r.text.strip()

        # If YAML
        if content.startswith("proxies:") or content.startswith("Proxy:"):
            data = yaml.safe_load(content)
            if "proxies" in data:
                return data["proxies"]

        # Otherwise assume base64 / clash raw list
        lines = content.splitlines()
        return [l.strip() for l in lines if l.strip()]
    except Exception as e:
        print(f"[warn] Failed to fetch {url} -> {e}")
        return []

def test_latency(node):
    host = None
    port = None
    try:
        if isinstance(node, str):
            # URI based
            if "@" in node:
                part = node.split("@")[-1]
                if ":" in part:
                    host, port = part.split(":")[0], int(part.split(":")[1].split("?")[0])
        elif isinstance(node, dict):
            host, port = node.get("server"), node.get("port")
        if not host or not port:
            return None
        if ping(host, int(port), timeout=1.0):
            return 50  # fake ms, reachable
    except Exception:
        return None
    return None

def run_mihomo(node):
    try:
        # Build minimal Clash config
        temp_config = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
        with open(temp_config, "w", encoding="utf-8") as f:
            f.write("proxies:\n")
            if isinstance(node, str):
                f.write(f"  - {node}\n")
            else:
                f.write("  - " + yaml.safe_dump(node).strip() + "\n")

            f.write("proxy-groups:\n")
            f.write("  - name: test\n")
            f.write("    type: select\n")
            f.write("    proxies:\n")
            f.write("      - " + (node["name"] if isinstance(node, dict) and "name" in node else "auto") + "\n")

            f.write("rules:\n")
            f.write("  - MATCH,test\n")

        import subprocess, json, time
        api_port = 9090
        process = subprocess.Popen(
            [MIHOMO_BIN, "-d", REPO_ROOT, "-f", temp_config, "-ext-ctl", f"127.0.0.1:{api_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)

        # Test outbound IP
        proxies = {"http": f"http://127.0.0.1:7890", "https": f"http://127.0.0.1:7890"}
        ip_resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=8)
        outbound_ip = ip_resp.json().get("ip")

        process.terminate()
        return outbound_ip
    except Exception as e:
        print(f"[warn] Mihomo failed for {node} -> {e}")
        return None

def get_country(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        data = r.json()
        return data.get("country_name"), data.get("country_code")
    except Exception:
        return None, None

# --------------- Main ----------------
def main():
    sources = load_sources()
    all_nodes = []
    for src in sources:
        all_nodes.extend(fetch_subscription(src))

    filtered = []
    for node in all_nodes:
        latency = test_latency(node)
        if USE_LATENCY_FILTER and (latency is None or latency > LATENCY_THRESHOLD):
            continue
        filtered.append(node)

    results = []
    for node in filtered:
        outbound_ip = run_mihomo(node)
        if not outbound_ip:
            continue
        country, code = get_country(outbound_ip)
        if not country:
            continue
        if isinstance(node, dict):
            node["name"] = f"🇨🇷|{country}|@SHFX"
            node["outbound_ip"] = outbound_ip
            node["country"] = country
            node["country_code"] = code
            results.append(node)
        elif isinstance(node, str):
            results.append({
                "name": f"🇨🇷|{country}|@SHFX",
                "server": node,
                "outbound_ip": outbound_ip,
                "country": country,
                "country_code": code,
            })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": results}, f, allow_unicode=True, default_flow_style=False)

    print(f"✅ Wrote {len(results)} working proxies to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

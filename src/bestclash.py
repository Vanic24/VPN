import os
import sys
import yaml
import json
import requests
import socket
import subprocess
import concurrent.futures
import time
import traceback
import base64
from urllib.parse import urlparse, parse_qs, unquote

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"

# Mihomo download URL
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
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + \
           chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

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

# ---------------- Node parser ----------------
def parse_node_to_json(node_line, name_override=None):
    node_line = node_line.strip()
    if not node_line or not any(node_line.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://", "socks://", "hysteria2://", "anytls://"]):
        return None

    try:
        if node_line.startswith("vless://"):
            u = urlparse(node_line)
            qs = parse_qs(u.query)
            return {
                "name": name_override or (u.fragment or "VLESS Node"),
                "type": "vless",
                "server": u.hostname,
                "port": u.port,
                "uuid": u.username,
                "tls": qs.get("security", [""])[0].lower() == "tls",
                "servername": qs.get("host", [""])[0],
                "network": qs.get("type", ["tcp"])[0],
                "ws-opts": {
                    "path": unquote(qs.get("path", [""])[0]),
                    "headers": {"host": qs.get("host", [""])[0]}
                },
                "client-fingerprint": qs.get("fp", ["random"])[0]
            }
        elif node_line.startswith("vmess://"):
            b64 = node_line[8:]
            decoded = base64.b64decode(b64).decode()
            data = json.loads(decoded)
            return {
                "name": name_override or data.get("ps", "VMess Node"),
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port")),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "security": data.get("scy", "auto"),
                "tls": bool(data.get("tls")),
                "network": data.get("net", "tcp"),
                "ws-opts": {
                    "path": data.get("path", ""),
                    "headers": {"host": data.get("host", "")}
                }
            }
        elif node_line.startswith("trojan://"):
            u = urlparse(node_line)
            qs = parse_qs(u.query)
            return {
                "name": name_override or (u.fragment or "Trojan Node"),
                "type": "trojan",
                "server": u.hostname,
                "port": u.port,
                "password": u.username,
                "sni": qs.get("sni", [""])[0],
                "network": qs.get("type", ["tcp"])[0],
                "ws-opts": {
                    "path": unquote(qs.get("path", [""])[0]),
                    "headers": {"host": qs.get("host", [""])[0]}
                }
            }
        else:
            # For ss://, socks://, hysteria2://, anytls://
            return {"raw": node_line, "name": name_override or "Unknown Node"}
    except Exception as e:
        print(f"[warn] failed to parse node line -> {e}")
        return None

# ---------------- Mihomo ----------------
def download_mihomo():
    import gzip
    import shutil
    if not os.path.exists(MIHOMO_BIN):
        print("[info] downloading mihomo binary...")
        r = requests.get(MIHOMO_URL, timeout=30)
        r.raise_for_status()
        with open(MIHOMO_BIN + ".gz", "wb") as f:
            f.write(r.content)
        with gzip.open(MIHOMO_BIN + ".gz", "rb") as f_in:
            with open(MIHOMO_BIN, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.chmod(MIHOMO_BIN, 0o755)
        os.remove(MIHOMO_BIN + ".gz")

def get_outbound_ip(node_json):
    temp_yaml = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    try:
        # write temporary yaml for mihomo
        with open(temp_yaml, "w", encoding="utf-8") as f:
            yaml.dump([node_json], f, allow_unicode=True, default_flow_style=False)
        # run mihomo
        proc = subprocess.run([MIHOMO_BIN, "-c", temp_yaml, "--mode=http"], capture_output=True, timeout=15)
        if proc.returncode != 0:
            print(f"[warn] Mihomo failed for {node_json.get('server')}:{node_json.get('port')} -> {proc.stderr.decode()}")
            return None
        # get real outbound ip
        try:
            r = requests.get("https://api.ipify.org/?format=json", proxies={"http": f"http://{node_json.get('server')}:{node_json.get('port')}"}, timeout=10)
            return r.json().get("ip")
        except:
            return None
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)

# ---------------- Correct node ----------------
def correct_node(node_line, country_counter):
    node_json = parse_node_to_json(node_line)
    if not node_json:
        return None

    host = str(node_json.get("server"))
    port = int(node_json.get("port") or 443)
    latency = tcp_latency_ms(host, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None

    # get real outbound ip
    outbound_ip = get_outbound_ip(node_json)
    if outbound_ip:
        cc_lower, cc_upper = geo_ip(outbound_ip)
    else:
        cc_lower, cc_upper = geo_ip(host)

    flag = country_to_flag(cc_upper)
    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]
    node_json["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    return node_json

# ---------------- Main ----------------
def main():
    download_mihomo()
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_nodes_lines = []
    for url in sources:
        proxies = load_proxies(url)
        for p in proxies:
            if isinstance(p, str):
                all_nodes_lines.append(p)
            elif isinstance(p, dict) and "name" in p:
                all_nodes_lines.append(p.get("name"))

    print(f"[collect] total {len(all_nodes_lines)} nodes collected")

    country_counter = {}
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(correct_node, line, country_counter) for line in all_nodes_lines]
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

    # ---------------- Convert nodes to YAML ----------------
    proxies_yaml_block = yaml.dump(corrected_nodes, allow_unicode=True, default_flow_style=False)

    # ---------------- Proxy names block ----------------
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

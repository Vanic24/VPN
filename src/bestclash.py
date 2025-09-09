import os
import sys
import requests
import socket
import concurrent.futures
import traceback
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"

USE_LATENCY = os.environ.get("LATENCY_FILTER", "false").lower() == "true"
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
        import time
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

# ---------------- Parse proxy line ----------------
def parse_proxy_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith("vmess://"):
            b64_data = line[8:]
            missing_padding = len(b64_data) % 4
            if missing_padding != 0:
                b64_data += "=" * (4 - missing_padding)
            decoded = base64.b64decode(b64_data).decode("utf-8")
            j = json.loads(decoded)
            return {
                "name": j.get("ps") or line,
                "type": "vmess",
                "server": j.get("add") or "",
                "port": int(j.get("port") or 443),
                "uuid": j.get("id") or "",
                "alterId": int(j.get("aid") or 0),
                "cipher": j.get("scy") or "auto",
                "tls": "tls" if j.get("tls") == "tls" else "",
                "network": j.get("net") or "",
                "ws-opts": {"path": j.get("path") or "", "headers": {"Host": j.get("host") or ""}}
            }
        elif line.startswith(("trojan://", "vless://", "anytls://", "hysteria://")):
            u = urlparse(line)
            query = parse_qs(u.query)
            return {
                "name": unquote(u.fragment) if u.fragment else line,
                "type": u.scheme,
                "server": u.hostname or "",
                "port": u.port or 443,
                "uuid": u.username or "",
                "alterId": 0,
                "cipher": "auto",
                "tls": "tls" if query.get("security", [""])[0] == "tls" else "",
                "network": query.get("type", [""])[0],
                "ws-opts": {"path": query.get("path", [""])[0], "headers": {"Host": query.get("sni", [""])[0]}}
            }
        elif line.startswith("ss://"):
            if "@" in line:
                ss_info = line[5:]
                creds, hostport = ss_info.split("@")
                password, cipher = base64.b64decode(creds).decode().split(":")
                host, port = hostport.split(":")
                return {
                    "name": line,
                    "type": "ss",
                    "server": host,
                    "port": int(port),
                    "uuid": password,
                    "alterId": 0,
                    "cipher": cipher,
                    "tls": "",
                    "network": "",
                    "ws-opts": {"path": "", "headers": {"Host": ""}}
                }
    except Exception:
        return None
    return None

# ---------------- Load proxies ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        proxies = []
        for line in r.text.splitlines():
            node = parse_proxy_line(line)
            if node:
                proxies.append(node)
        return proxies
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
        return []

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    host = str(p.get("server"))
    try:
        port = int(p.get("port", 443))
    except ValueError:
        port = 443
    ip = resolve_ip(host) or host
    cc_lower, cc_upper = geo_ip(ip)
    flag = country_to_flag(cc_upper)
    latency = tcp_latency_ms(host, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None
    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]
    p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    p["port"] = port
    return p

# ---------------- Convert nodes to YAML manually ----------------
def build_yaml_node(p):
    lines = []
    lines.append(f"- name: {p.get('name','')}")
    lines.append(f"  type: {p.get('type','')}")
    lines.append(f"  server: {p.get('server','')}")
    lines.append(f"  port: {p.get('port',443)}")
    lines.append(f"  uuid: {p.get('uuid','')}")
    lines.append(f"  alterId: {p.get('alterId',0)}")
    lines.append(f"  cipher: {p.get('cipher','auto')}")
    lines.append(f"  tls: '{p.get('tls','')}'")
    lines.append(f"  network: {p.get('network','')}")
    ws = p.get("ws-opts", {})
    path = ws.get("path","")
    host = ws.get("headers",{}).get("Host","")
    lines.append(f"  ws-opts:")
    lines.append(f"    path: {path}")
    lines.append(f"    headers:")
    lines.append(f"      Host: '{host}'")
    return "\n".join(lines)

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    proxies_yaml_block = "\n".join([build_yaml_node(p) for p in corrected_nodes])
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected_nodes])

    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"[done] wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", e)
        traceback.print_exc()
        sys.exit(1)

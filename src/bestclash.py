import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
import base64
import json
import subprocess
import time
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
    proxies = []
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text

        # YAML format
        try:
            data = yaml.safe_load(text)
            if "proxies" in data:
                proxies.extend(data["proxies"])
        except:
            pass

        # Raw URL lines
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//") or line.startswith("["):
                continue
            if any(line.startswith(proto) for proto in ["vmess://","vless://","trojan://","ss://","socks://","hysteria2://","anytls://"]):
                proxies.append({"raw": line})
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return proxies

# ---------------- Parse raw URL into dict ----------------
def parse_raw_node(raw):
    try:
        if raw.startswith("vmess://"):
            content = base64.b64decode(raw[8:]).decode()
            data = json.loads(content)
            node = {
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "security": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "ws-opts": {
                    "path": data.get("path","/"),
                    "headers": {"host": data.get("host","")}
                } if data.get("net")=="ws" else None,
                "tls": data.get("tls","")!="",
                "name": data.get("ps","vmess-node")
            }
            return node

        elif raw.startswith("vless://"):
            import urllib.parse
            parts = raw[7:].split("@")
            if len(parts) != 2:
                return None
            uuid = parts[0]
            server_port = parts[1].split("?",1)
            server, port = server_port[0].split(":")
            params = urllib.parse.parse_qs(server_port[1]) if len(server_port)>1 else {}
            node = {
                "type":"vless",
                "server":server,
                "port":int(port),
                "uuid":uuid,
                "network": params.get("type",["tcp"])[0],
                "tls": params.get("security",["none"])[0].lower()=="tls",
                "servername": params.get("host",[""])[0],
                "ws-opts": {"path":params.get("path",["/"])[0],"headers":{"host":params.get("host",[""])[0]}} if params.get("type",["tcp"])[0]=="ws" else None,
                "name":"vless-node"
            }
            return node

        elif raw.startswith("trojan://"):
            import urllib.parse
            # trojan://password@host:port?params#name
            parts = raw[9:].split("@")
            if len(parts)!=2:
                return None
            password = parts[0]
            host_port = parts[1].split("?",1)
            host_port_only = host_port[0].split(":")
            if len(host_port_only)!=2:
                return None
            server = host_port_only[0]
            port = int(host_port_only[1])
            params = urllib.parse.parse_qs(host_port[1]) if len(host_port)>1 else {}
            node = {
                "type":"trojan",
                "server":server,
                "port":port,
                "password":password,
                "network": params.get("type",["tcp"])[0],
                "tls": params.get("security",["none"])[0].lower()=="tls",
                "servername": params.get("host",[""])[0],
                "ws-opts": {"path":params.get("path",["/"])[0],"headers":{"host":params.get("host",[""])[0]}} if params.get("type",["tcp"])[0]=="ws" else None,
                "name":"trojan-node"
            }
            return node

        # Other protocols can be added similarly
        else:
            return None

    except Exception as e:
        return None

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    if "raw" in p:
        node = parse_raw_node(p["raw"])
        if not node:
            return None
    else:
        node = p

    host = node.get("server")
    port = int(node.get("port",443))

    ip = resolve_ip(host) or host
    cc_lower, cc_upper = geo_ip(ip)
    flag = country_to_flag(cc_upper)

    # latency check
    latency = tcp_latency_ms(host, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None

    # Mihomo outbound IP detection
    try:
        temp_yaml = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
        with open(temp_yaml,"w",encoding="utf-8") as f:
            yaml.dump([node], f, allow_unicode=True, default_flow_style=False)
        mihomo_proc = subprocess.Popen([os.path.join(REPO_ROOT,"mihomo"), "-c", temp_yaml, "--http"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        mihomo_proc.kill()
        # Here you can implement reading real outbound IP if Mihomo provides
        # For now skip, keep node info
    except:
        pass

    # Rename
    country_counter[cc_upper]+=1
    index = country_counter[cc_upper]
    node["name"]=f"{flag}|{cc_upper}{index}|@SHFX"

    return node

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
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

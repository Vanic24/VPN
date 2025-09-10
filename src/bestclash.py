import os
import sys
import yaml
import requests
import socket
import base64
import concurrent.futures
import traceback
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

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

# ---------------- Subscription parsing ----------------
def parse_vmess(uri):
    try:
        decoded = base64.b64decode(uri[8:], validate=True).decode("utf-8", errors="ignore")
        data = yaml.safe_load(decoded) if decoded.strip().startswith("{") else {}
        if not data:
            return None
        return {
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "tls": data.get("tls", ""),
            "name": "tmp"
        }
    except:
        return None

def parse_ss(uri):
    try:
        # ss://method:password@host:port#name
        u = uri[5:]
        if "@" not in u:
            decoded = base64.b64decode(u.split("#")[0]).decode("utf-8", errors="ignore")
            u = decoded + "@" + u.split("#")[-1]
        method_pwd, server_port = u.split("@")
        method, pwd = method_pwd.split(":")
        host, port = server_port.split(":")
        return {
            "type": "ss",
            "server": host,
            "port": int(port.split("#")[0]),
            "cipher": method,
            "password": pwd,
            "udp": True,
            "name": "tmp"
        }
    except:
        return None

def parse_trojan(uri):
    try:
        # trojan://password@host:port
        u = uri[9:]
        pwd, rest = u.split("@", 1)
        host, port = rest.split(":")
        return {
            "type": "trojan",
            "server": host,
            "port": int(port.split("?")[0]),
            "password": pwd,
            "udp": True,
            "name": "tmp"
        }
    except:
        return None

def parse_vless(uri):
    try:
        # vless://uuid@host:port?encryption=none
        u = urlparse(uri)
        return {
            "type": "vless",
            "server": u.hostname,
            "port": int(u.port or 443),
            "uuid": u.username,
            "udp": True,
            "name": "tmp"
        }
    except:
        return None

def parse_raw_line(line):
    if line.startswith("vmess://"):
        return parse_vmess(line)
    elif line.startswith("ss://"):
        return parse_ss(line)
    elif line.startswith("trojan://"):
        return parse_trojan(line)
    elif line.startswith("vless://"):
        return parse_vless(line)
    return None

def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text.strip()
        # try yaml first
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                return data["proxies"]
        except:
            pass
        # try base64 subscription
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            lines = decoded.splitlines()
        except:
            lines = text.splitlines()

        proxies = []
        for line in lines:
            node = parse_raw_line(line.strip())
            if node:
                proxies.append(node)
        return proxies
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return []

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    try:
        host = str(p.get("server"))
        raw_port = str(p.get("port", ""))
        if "/" in raw_port:
            raw_port = raw_port.split("/")[0]
        try:
            port = int(raw_port)
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
    except:
        return None

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

    seen = set()  # for deduplication
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    key = (res.get("type"), res.get("server"), res.get("port"),
                           res.get("uuid", ""), res.get("password", ""))
                    if key not in seen:
                        seen.add(key)
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

    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected_nodes])

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

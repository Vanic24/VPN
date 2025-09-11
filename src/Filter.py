import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
from collections import defaultdict
import base64
import re
import json
import urllib.parse

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "Filter")   # changed from proxies.yaml → Filter
SOURCES_FILE = os.path.join(REPO_ROOT, "Filter_Sources")  # changed from sources.txt → Filter_Sources
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"
TEXTDB_API = "https://textdb.online/update/?key=Filter_SHFX&value={}"   # TextDB upload endpoint

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
        print(f"[FATAL] Filter_Sources not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not sources:
        print(f"[FATAL] Filter_Sources is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

# ---------------- Vmess parser ----------------
def parse_vmess(line):
    try:
        if line.startswith("vmess://"):
            b64 = line[8:].strip()
            padded = b64 + "=" * (-len(b64) % 4)
            json_str = base64.b64decode(padded).decode('utf-8')
            data = json.loads(json_str)
            node = {
                "name": data.get("ps") or "",
                "type": "vmess",
                "server": data["add"],
                "port": int(data["port"]),
                "uuid": data["id"],
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto"),
                "tls": data.get("tls", "").lower() == "tls",
                "network": data.get("net", "tcp"),
            }
            if node["network"] == "ws":
                node["ws-opts"] = {
                    "path": data.get("path", "/"),
                    "headers": {"Host": data.get("host", "")}
                }
            return node
    except:
        return None
    return None

# ---------------- Vless parser ----------------
def parse_vless(line):
    try:
        if line.startswith("vless://"):
            m = re.match(r"vless://([0-9a-fA-F-]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?", line)
            if m:
                uuid, host, port, query, name = m.groups()
                node = {
                    "name": name or "",
                    "type": "vless",
                    "server": host,
                    "port": int(port),
                    "uuid": uuid,
                    "tls": False,
                    "network": "tcp"
                }
                if query:
                    params = dict([p.split("=", 1) for p in query.split("&") if "=" in p])
                    node["tls"] = params.get("security", "").lower() == "tls"
                    node["network"] = params.get("type", "tcp")
                    if node["network"] == "ws":
                        node["ws-opts"] = {
                            "path": params.get("path", "/"),
                            "headers": {"Host": params.get("host", "")}
                        }
                return node
    except:
        return None
    return None

# ---------------- Trojan parser ----------------
def parse_trojan(line):
    try:
        if line.startswith("trojan://"):
            m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)#?(.*)", line)
            if m:
                password, host, port, name = m.groups()
                node = {
                    "name": name or "",
                    "type": "trojan",
                    "server": host,
                    "port": int(port),
                    "password": password,
                }
                return node
    except:
        return None
    return None

# ---------------- Hysteria2 parser ----------------
def parse_hysteria2(line):
    try:
        if line.startswith("hysteria2://"):
            m = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)#?(.*)", line)
            if m:
                password, host, port, name = m.groups()
                node = {
                    "name": name or "",
                    "type": "hysteria2",
                    "server": host,
                    "port": int(port),
                    "password": password,
                }
                return node
    except:
        return None
    return None

# ---------------- Anytls parser ----------------
def parse_anytls(line):
    try:
        if line.startswith("anytls://"):
            m = re.match(r"anytls://([^@]+)@([^:]+):(\d+)#?(.*)", line)
            if m:
                password, host, port, name = m.groups()
                node = {
                    "name": name or "",
                    "type": "anytls",
                    "server": host,
                    "port": int(port),
                    "password": password,
                }
                return node
    except:
        return None
    return None

# ---------------- Shadowsocks (SS) parser ----------------
def decode_b64(data: str) -> str | None:
    try:
        data = data.replace("-", "+").replace("_", "/")
        padding = "=" * (-len(data) % 4)
        return base64.b64decode(data + padding).decode("utf-8")
    except Exception:
        return None

# (keeping the rest unchanged… parsers, main loop, etc.)

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from Filter_Sources")

    # (logic unchanged … collect, filter, correct, build template)

    # ---------------- Write output ----------------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"[done] wrote {OUTPUT_FILE}")

    # ---------------- Upload to TextDB ----------------
    try:
        encoded = urllib.parse.quote(output_text)
        url = TEXTDB_API.format(encoded)
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            print("[done] uploaded to TextDB successfully")
        else:
            print(f"[warn] TextDB upload failed: {r.status_code}")
    except Exception as e:
        print(f"[error] TextDB upload exception: {e}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

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
import base64
import urllib.parse
import yaml

def parse_ss_url(ss_url):
    """
    Parse a single ss:// URL into Clash YAML dictionary.
    """
    ss_url = ss_url.strip()
    if not ss_url.startswith("ss://"):
        return None

    # Remove the ss:// prefix
    ss_url = ss_url[5:]

    # Split name/comment if exists
    if "#" in ss_url:
        ss_part, name = ss_url.split("#", 1)
        name = urllib.parse.unquote(name)
    else:
        ss_part = ss_url
        name = "SS Node"

    # Check if plugin query exists
    if "/?" in ss_part:
        ss_core, query = ss_part.split("/?", 1)
        query_params = urllib.parse.parse_qs(query)
    else:
        ss_core = ss_part
        query_params = {}

    # Check for port after last colon
    if ":" in ss_core:
        # Could be base64 encoded with server:port after @
        if "@" in ss_core:
            b64_part, server_port = ss_core.split("@", 1)
            decoded = base64.urlsafe_b64decode(b64_part + "=" * (-len(b64_part) % 4)).decode()
            if ":" in decoded:
                cipher, password = decoded.split(":", 1)
            else:
                cipher = "aes-256-cfb"
                password = decoded
            server, port = server_port.split(":")
        else:
            # Plain ss://cipher:password@server:port style
            decoded = base64.urlsafe_b64decode(ss_core + "=" * (-len(ss_core) % 4)).decode()
            cipher, password, server, port = decoded.split(":")
    else:
        # Only base64 part
        decoded = base64.urlsafe_b64decode(ss_core + "=" * (-len(ss_core) % 4)).decode()
        cipher, password, server, port = decoded.split(":")

    # Plugin parsing
    plugin = None
    plugin_opts = None
    if "plugin" in query_params:
        plugin_full = query_params["plugin"][0]
        if ";" in plugin_full:
            plugin_parts = plugin_full.split(";")
            plugin = plugin_parts[0]
            plugin_opts = {}
            for part in plugin_parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    plugin_opts[k] = v
        else:
            plugin = plugin_full

    # Build dictionary
    node = {
        "name": name,
        "type": "ss",
        "server": server.strip(),
        "port": int(port.strip()),
        "cipher": cipher,
        "password": password
    }
    if plugin:
        node["plugin"] = plugin
    if plugin_opts:
        node["plugin-opts"] = plugin_opts

    return node


def parse_ss_list(ss_list):
    """
    Parse a list of ss:// URLs into Clash YAML format.
    """
    proxies = []
    for line in ss_list:
        line = line.strip()
        if line:
            try:
                node = parse_ss_url(line)
                if node:
                    proxies.append(node)
            except Exception as e:
                print(f"Error parsing: {line}\n{e}")
    return {"proxies": proxies}


# Example usage
if __name__ == "__main__":
    with open("ss_links.txt", "r", encoding="utf-8") as f:
        ss_list = f.readlines()

    clash_config = parse_ss_list(ss_list)

    with open("clash_config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)

    print("Clash YAML file generated: clash_config.yaml")

# ---------------- ShadowsocksR (SSR) parser ----------------
def parse_ssr(line):
    try:
        if not line.startswith("ssr://"):
            return None
        b64 = line[6:].strip()
        padded = b64 + "=" * (-len(b64) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")

        # SSR format: server:port:protocol:method:obfs:password_base64/?params
        parts = decoded.split("/")
        main_part = parts[0]
        if "?" in main_part:
            main_part, query_string = main_part.split("?", 1)
        else:
            query_string = ""

        items = main_part.split(":")
        if len(items) < 6:
            return None
        server, port, protocol, method, obfs, password_b64 = items[:6]
        password = base64.urlsafe_b64decode(password_b64 + "=" * (-len(password_b64) % 4)).decode()

        node = {
            "name": "",
            "type": "ssr",
            "server": server,
            "port": int(port),
            "protocol": protocol,
            "cipher": method,
            "obfs": obfs,
            "password": password
        }

        # Parse query string parameters
        if query_string:
            qs = urllib.parse.parse_qs(query_string)
            if "remarks" in qs:
                node["name"] = urllib.parse.unquote(qs["remarks"][0])
            if "obfsparam" in qs:
                node["obfs_param"] = base64.urlsafe_b64decode(qs["obfsparam"][0] + "=" * (-len(qs["obfsparam"][0]) % 4)).decode()
            if "protoparam" in qs:
                node["protocol_param"] = base64.urlsafe_b64decode(qs["protoparam"][0] + "=" * (-len(qs["protoparam"][0]) % 4)).decode()
        return node
    except Exception:
        return None

def parse_node_line(line):
    parsers = [parse_vmess, parse_vless, parse_trojan, parse_hysteria2, parse_anytls, parse_ss, parse_ssr]
    for parser in parsers:
        node = parser(line)
        if node:
            return node
    return None

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    host = str(p.get("server"))
    raw_port = str(p.get("port", ""))

    try:
        port = int(raw_port)
    except ValueError:
        port = 443

    ip = resolve_ip(host) or host
    cc_lower, cc_upper = geo_ip(ip)
    flag = country_to_flag(cc_upper)

    p["port"] = port

    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    return p

# ---------------- Load and parse proxies ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        lines = r.text.splitlines()
        nodes = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            node = parse_node_line(line)
            if node:
                nodes.append(node)
            else:
                print(f"[skip] invalid or unsupported line -> {line[:60]}...")
        return nodes
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return []

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_nodes = []
    for url in sources:
        nodes = load_proxies(url)
        print(f"[source] {url} -> {len(nodes)} valid nodes")
        all_nodes.extend(nodes)

    print(f"[collect] total {len(all_nodes)} nodes before filtering")

    # ---------------- Filter duplicates ----------------
    unique_set = set()
    unique_nodes = []
    for n in all_nodes:
        key = (n.get("type"), n.get("server"), n.get("port"), n.get("uuid", n.get("password", "")))
        if key not in unique_set:
            unique_set.add(key)
            unique_nodes.append(n)
    print(f"[filter] {len(unique_nodes)} nodes after deduplication")

    # ---------------- Latency filter ----------------
    if USE_LATENCY:
        print(f"[latency] filtering nodes > {LATENCY_THRESHOLD} ms")
        country_counter = defaultdict(int)
        filtered_nodes = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(tcp_latency_ms, n.get("server"), n.get("port")) for n in unique_nodes]
            for n, f in zip(unique_nodes, futures):
                latency = f.result()
                if latency <= LATENCY_THRESHOLD:
                    filtered_nodes.append(n)
        print(f"[latency] {len(filtered_nodes)} nodes after latency filtering")
    else:
        filtered_nodes = unique_nodes
        country_counter = defaultdict(int)

    # ---------------- Correct nodes ----------------
    corrected_nodes = []
    for n in filtered_nodes:
        corrected_nodes.append(correct_node(n, country_counter))

    print(f"[done] final {len(corrected_nodes)} nodes ready")

    # ---------------- Load template ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert to YAML ----------------
    proxies_yaml_block = yaml.dump(corrected_nodes, allow_unicode=True, default_flow_style=False)
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected_nodes])

    # ---------------- Replace placeholders ----------------
    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = template_text.replace("{{PROXY_NAMES}}", proxy_names_block)

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

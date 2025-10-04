import os
import sys
import time
import yaml
import requests
import socket
import concurrent.futures
import traceback
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta, timezone
import base64
import re
import json
import urllib.parse
from urllib.parse import unquote, urlparse, parse_qs

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "MIX")
SOURCES_FILE = os.path.join(REPO_ROOT, "SUB_MIX")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"
TEXTDB_API = "https://textdb.online/update/?key=MIX_SHFX&value={}"
URL_MIX = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/MIX"
CN_TO_CC = json.loads(os.getenv("CN_TO_CC", "{}"))
USE_ONLY_GEOIP = os.getenv("USE_ONLY_GEOIP", "false").lower() == "true"

# ---------------- Inputs ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"

try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

# ---------------- Helper ----------------
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
    """Convert ISO 3166 two-letter code to emoji flag"""
    if not cc or len(cc) != 2:
        return "🏳️"
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

def flag_to_country_code(flag):
    """Convert emoji flag to ISO 3166 code"""
    if not flag or len(flag) < 2:
        return None
    try:
        first, second = flag[0], flag[1]
        return chr(ord(first) - 0x1F1E6 + 65) + chr(ord(second) - 0x1F1E6 + 65)
    except:
        return None

def load_cn_to_cc():
    secret_data = os.environ.get("CN_TO_CC", "{}")
    try:
        return json.loads(secret_data)
    except Exception as e:
        print(f"[error] 😭 Failed to parse CN_TO_CC secret: {e}")
        return {}

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] ⚠️ Source not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not sources:
        print(f"[FATAL] 🕵️ Source is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

# -----------------------------------------------------------
# Helper: Safe base64 decode
# -----------------------------------------------------------
def decode_b64(b64str):
    try:
        padded = b64str + "=" * (-len(b64str) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8")
    except Exception:
        return ""

# -----------------------------------------------------------
# Helper: Generic dynamic query merger
# -----------------------------------------------------------
def merge_dynamic_fields(node, query):
    """Attach all unrecognized query fields dynamically."""
    known = set(node.keys())
    for k, v in query.items():
        if k not in known and v is not None:
            # If multiple values, use first unless it’s a list of unique items
            node[k] = v if not isinstance(v, list) else v[0]
    return node

# -----------------------------------------------------------
# VMESS Parser
# -----------------------------------------------------------
def parse_vmess(line):
    try:
        if not line.startswith("vmess://"):
            return None
        raw = line[8:].strip()
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))
        node = {
            "type": "vmess",
            "name": data.get("ps") or "",
            "server": data.get("add", ""),
            "port": int(data.get("port", 0)),
            "uuid": data.get("id", ""),
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
        # dynamic fields
        node = merge_dynamic_fields(node, data)
        return node
    except Exception as e:
        print(f"[warn] ❗Vmess parse error -> {e}")
        return None

# -----------------------------------------------------------
# VLESS Parser
# -----------------------------------------------------------
def parse_vless(line):
    try:
        if not line.startswith("vless://"):
            return None

        # Split name fragment
        name = ""
        if "#" in line:
            line, name = line.split("#", 1)
            name = urllib.parse.unquote(name)

        core = line[len("vless://"):]
        if "@" not in core:
            return None
        uuid, rest = core.split("@", 1)

        query = {}
        if "?" in rest:
            host_port, q = rest.split("?", 1)
            query = dict(urllib.parse.parse_qsl(q))
        else:
            host_port = rest

        if ":" not in host_port:
            return None
        host, port = host_port.split(":", 1)

        node = {
            "type": "vless",
            "name": name or "VLESS Node",
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "encryption": query.get("encryption", "none"),
        }

        # Security (TLS / Reality)
        if query.get("security") == "tls":
            node["tls"] = True
            node["servername"] = query.get("sni", "")
            node["skip-cert-verify"] = query.get("allowInsecure", "0") in ("1", "true", "yes")
            if "fp" in query:
                node["client-fingerprint"] = query["fp"]
        elif query.get("security") == "reality":
            node["reality-opts"] = {
                "public-key": query.get("pbk", ""),
                "short-id": query.get("sid", ""),
                "server-name": query.get("sni", "")
            }
            node["tls"] = True

        # Network
        if "type" in query:
            node["network"] = query["type"]

        if node.get("network") == "ws":
            ws_opts = {"path": urllib.parse.unquote(query.get("path", "/"))}
            if "host" in query:
                ws_opts["headers"] = {"Host": query["host"]}
            node["ws-opts"] = ws_opts

        if node.get("network") == "grpc":
            node["grpc-opts"] = {"grpc-service-name": query.get("serviceName", "")}

        node = merge_dynamic_fields(node, query)
        return node

    except Exception as e:
        print(f"[warn] ❗VLESS parse error -> {e}")
        return None

# -----------------------------------------------------------
# TROJAN Parser
# -----------------------------------------------------------
def parse_trojan(line):
    try:
        if not line.startswith("trojan://"):
            return None

        name = ""
        if "#" in line:
            line, name = line.split("#", 1)
            name = urllib.parse.unquote(name.strip())

        core = line[len("trojan://"):]
        if "@" not in core:
            return None
        password, rest = core.split("@", 1)

        query = {}
        if "?" in rest:
            host_port, q = rest.split("?", 1)
            query = dict(urllib.parse.parse_qsl(q))
        else:
            host_port = rest

        if ":" not in host_port:
            return None
        host, port = host_port.split(":", 1)

        node = {
            "type": "trojan",
            "name": name or "Trojan Node",
            "server": host.strip(),
            "port": int(port.strip()),
            "password": urllib.parse.unquote(password.strip()),
        }

        node["skip-cert-verify"] = query.get("allowInsecure", "0") in ("1", "true", "yes")
        node["security"] = query.get("security", "tls")
        sni = query.get("sni") or query.get("peer")
        if sni:
            node["sni"] = sni
            node["servername"] = sni

        if "type" in query:
            node["network"] = query["type"]

        if node.get("network") == "ws":
            ws_opts = {"path": urllib.parse.unquote(query.get("path", "/"))}
            if "host" in query:
                ws_opts["headers"] = {"Host": query["host"]}
            node["ws-opts"] = ws_opts

        elif node.get("network") == "grpc":
            node["grpc-opts"] = {"grpc-service-name": query.get("serviceName", "")}

        node = merge_dynamic_fields(node, query)
        return node
    except Exception as e:
        print(f"[warn] ❗Trojan parse error -> {e}")
        return None

# -----------------------------------------------------------
# HYSTERIA2 Parser
# -----------------------------------------------------------
def parse_hysteria2(line):
    try:
        if not (line.startswith("hysteria2://") or line.startswith("hy2://")):
            return None
        if line.startswith("hy2://"):
            line = "hysteria2://" + line[len("hy2://"):]

        parsed = urllib.parse.urlparse(line)
        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "")

        node = {
            "type": "hysteria2",
            "name": name,
            "server": host,
            "port": int(port or 0),
            "password": password,
            "skip-cert-verify": True
        }

        if "sni" in query:
            node["tls"] = {"enabled": True, "server_name": query["sni"]}
        if "insecure" in query:
            node["tls"]["insecure"] = query["insecure"].lower() in ("1", "true", "yes")

        node = merge_dynamic_fields(node, query)
        return node
    except Exception as e:
        print(f"[warn] ❗Hysteria2 parse error -> {e}")
        return None

# -----------------------------------------------------------
# ANYTLS Parser
# -----------------------------------------------------------
def parse_anytls(line):
    try:
        if not line.startswith("anytls://"):
            return None
        parsed = urllib.parse.urlparse(line)
        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "")

        node = {
            "type": "anytls",
            "name": name,
            "server": host,
            "port": int(port or 0),
            "password": password,
        }
        node = merge_dynamic_fields(node, query)
        return node
    except Exception as e:
        print(f"[warn] ❗Anytls parse error -> {e}")
        return None

# -----------------------------------------------------------
# TUIC Parser
# -----------------------------------------------------------
def parse_tuic(line):
    try:
        if not line.startswith("tuic://"):
            return None
        parsed = urllib.parse.urlparse(line)
        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "")
        node = {
            "type": "tuic",
            "name": name,
            "server": host,
            "port": int(port or 0),
            "password": password,
        }
        node = merge_dynamic_fields(node, query)
        return node
    except Exception as e:
        print(f"[warn] ❗TUIC parse error -> {e}")
        return None

# -----------------------------------------------------------
# SHADOWSOCKS (SS) Parser
# -----------------------------------------------------------
def parse_ss(line):
    try:
        if not line.startswith("ss://"):
            return None
        line = line[5:]
        name = ""
        if "#" in line:
            line, name = line.split("#", 1)
            name = urllib.parse.unquote(name)
        plugin = None
        plugin_opts = None
        if "/?" in line:
            core, q = line.split("/?", 1)
            qd = urllib.parse.parse_qs(q)
            if "plugin" in qd:
                plugin_full = qd["plugin"][0]
                if ";" in plugin_full:
                    parts = plugin_full.split(";")
                    plugin = parts[0]
                    plugin_opts = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                else:
                    plugin = plugin_full
        else:
            core = line
        if "@" in core:
            b64, srvp = core.split("@", 1)
            decoded = decode_b64(b64)
            cipher, password = decoded.split(":", 1)
            server, port = srvp.split(":")
        else:
            decoded = decode_b64(core)
            userinfo, srvp = decoded.split("@", 1)
            cipher, password = userinfo.split(":")
            server, port = srvp.split(":")
        node = {
            "type": "ss",
            "name": name or "SS Node",
            "server": server,
            "port": int(port),
            "cipher": cipher,
            "password": password,
        }
        if plugin:
            node["plugin"] = plugin
        if plugin_opts:
            node["plugin-opts"] = plugin_opts
        return node
    except Exception as e:
        print(f"[warn] ❗SS parse error -> {e}")
        return None

# -----------------------------------------------------------
# SHADOWSOCKSR (SSR) Parser
# -----------------------------------------------------------
def parse_ssr(line):
    try:
        if not line.startswith("ssr://"):
            return None
        decoded = decode_b64(line[6:])
        main, *tail = decoded.split("/?")
        parts = main.split(":")
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, pwd_b64 = parts[:6]
        password = decode_b64(pwd_b64)
        qs = dict(urllib.parse.parse_qsl(tail[0])) if tail else {}
        node = {
            "type": "ssr",
            "name": urllib.parse.unquote(decode_b64(qs.get("remarks", [""])[0])) if "remarks" in qs else "",
            "server": server,
            "port": int(port),
            "protocol": protocol,
            "cipher": method,
            "obfs": obfs,
            "password": password
        }
        node = merge_dynamic_fields(node, qs)
        return node
    except Exception as e:
        print(f"[warn] ❗SSR parse error -> {e}")
        return None

# -----------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------
def parse_node_line(line):
    parsers = [
        parse_vmess,
        parse_vless,
        parse_trojan,
        parse_hysteria2,
        parse_anytls,
        parse_tuic,
        parse_ss,
        parse_ssr
    ]
    for fn in parsers:
        node = fn(line.strip())
        if node:
            return node
    return None

# ---------------- Rename node ----------------
def rename_node(p, country_counter, CN_TO_CC):
    """
    Assign a standardized name to the node without changing any other fields.
    Skip nodes with forbidden emojis or empty names.
    If USE_ONLY_GEOIP is True, assign name by GeoIP only.
    Preserves all original fields to maintain connectivity.
    """

    # Original name
    original_name = str(p.get("name", "") or "").strip()
    host = p.get("server") or p.get("add") or ""

    # Define forbidden emojis (any emoji you want to filter out)
    FORBIDDEN_EMOJIS = {"🔒", "❌", "⚠️", "🚀", "🎁"}

    # Extract grapheme clusters (so multi-codepoint emojis like ⚠️ are kept together)
    graphemes = list(original_name)

    # Skip nodes with empty names or containing any forbidden emoji
    if not original_name or any(g in FORBIDDEN_EMOJIS for g in graphemes):
        return None

    # Decode %xx escapes in case node name came from URL fragment
    name_for_match = unquote(original_name)

    cc = None
    flag = None

    # 🚨 If option is set, only do GeoIP
    if USE_ONLY_GEOIP:
        ip = resolve_ip(host) or host
        cc_lower, cc_upper = geo_ip(ip)
        if cc_upper and cc_upper != "UN":
            cc = cc_upper
            flag = country_to_flag(cc)
            country_counter[cc] += 1
            index = country_counter[cc]
            p["name"] = f"{flag} {cc}-{index} | MIX"
            return p
        return None

    # 1️⃣ Chinese mapping (substring match)
    for cn_name, code in CN_TO_CC.items():
        if cn_name and cn_name in name_for_match:
            cc = code.upper()
            flag = country_to_flag(cc)
            country_counter[cc] += 1
            index = country_counter[cc]
            # Only update the name field
            p["name"] = f"{flag} {cc}-{index} | MIX"
            return p

    # 2️⃣ Emoji flag in name
    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', name_for_match)
    if flag_match:
        flag = flag_match.group(0)
        cc = flag_to_country_code(flag)
        if cc:
            cc = cc.upper()
            country_counter[cc] += 1
            index = country_counter[cc]
            p["name"] = f"{flag} {cc}-{index} | MIX"
            return p

    # 3️⃣ Two-letter ISO code (UPPER CASE)
    iso_match = re.search(r'\b([A-Z]{2})\b', original_name)
    if iso_match:
        cc = iso_match.group(1).upper()
        flag = country_to_flag(cc)
        country_counter[cc] += 1
        index = country_counter[cc]
        p["name"] = f"{flag} {cc}-{index} | MIX"
        return p

    # 4️⃣ GeoIP fallback
    ip = resolve_ip(host) or host
    cc_lower, cc_upper = geo_ip(ip)
    if cc_upper and cc_upper != "UN":
        cc = cc_upper
        flag = country_to_flag(cc)
        country_counter[cc] += 1
        index = country_counter[cc]
        p["name"] = f"{flag} {cc}-{index} | MIX"
        return p

    # 5️⃣ Skip node entirely if no assignment possible
    return None

# ---------------- Load proxies ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text.strip()

        print(f"[fetch] 📥 {len(text.splitlines())} lines fetched from subscription link")
        for line in text.splitlines()[:5]:
            print("       ", line[:80])

        nodes = []

        # Base64 decode if single line and looks like Base64
        if len(text.splitlines()) == 1 and re.match(r'^[A-Za-z0-9+/=]+$', text):
            try:
                decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
                text = decoded
                print(f"[decode] 🔓 Base64 decoded -> {len(text.splitlines())} lines")
            except Exception as e:
                print(f"[warn] 😭 Base64 decode failed for {url}: {e}")

        # Parse as YAML (Clash format)
        if text.startswith("proxies:") or "proxies:" in text:
            try:
                data = yaml.safe_load(text)
                if data and "proxies" in data:
                    for p in data["proxies"]:
                        nodes.append(p)
                        print(f"[parse] 🔎 YAML node: {p.get('name', '')}")
                else:
                    print(f"[warn] 😭 YAML structure invalid or empty: {url}")
            except Exception as e:
                print(f"[warn] 😭 YAML parsing failed for {url}: {e}")
        else:
            # Parse as individual subscription lines (Vmess/Vless/Trojan/etc.)
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    node = parse_node_line(line)
                    if node:
                        print(f"[parsed] 🔎 {json.dumps(node, ensure_ascii=False)}")
                        nodes.append(node)
                    else:
                        print(f"[skip] ⛔ Invalid or unsupported line -> {line[:60]}...")
                except Exception as e:
                    print(f"[warn] 😭 Error parsing line: {e}")

        return nodes

    except Exception as e:
        print(f"[warn] 😭 Failed to fetch {url} -> {e}")
        return []

# ---------------- Main ----------------
def main():
    try:
        sources = load_sources()
        print(f"[start] 🖥️ Loaded {len(sources)} subscription links from source")

        all_nodes = []
        for url in sources:
            nodes = load_proxies(url)
            print(f"[source] 📝 {len(nodes)} nodes parsed from current subscription")
            all_nodes.extend(nodes)

        print(f"[collect] 📋 Total {len(all_nodes)} nodes successfully parsed from all subscriptions")

        # ---------------- Latency filter ----------------
        if USE_LATENCY:
            print(f"[latency] 🚫 Filtering nodes > {LATENCY_THRESHOLD} ms")
            country_counter = defaultdict(int)
            filtered_nodes = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                futures = [ex.submit(tcp_latency_ms, n.get("server"), n.get("port")) for n in all_nodes]
                for n, f in zip(all_nodes, futures):
                    latency = f.result()
                    if latency <= LATENCY_THRESHOLD:
                        filtered_nodes.append(n)

            num_filtered = len(all_nodes) - len(filtered_nodes)
            print(f"[latency] ❗Filtered {num_filtered} nodes due to latency")
            print(f"[latency]  🖨️ Total {len(filtered_nodes)} nodes remain after latency filtering")
        else:
            filtered_nodes = all_nodes
            country_counter = defaultdict(int)
            print(f"[latency] 🚀 Latency filtering 🚫, {len(filtered_nodes)} nodes remain")

        # ---------------- Renamed nodes ----------------
        renamed_nodes = []
        cn_to_cc = load_cn_to_cc()
        skipped_nodes = 0
        for n in filtered_nodes:
            res = rename_node(n, country_counter, cn_to_cc)
            if res:
                renamed_nodes.append(res)
            else:
                skipped_nodes += 1

        if skipped_nodes > 0:
            print(f"[rename] ⚠️ Skipped {skipped_nodes} nodes that could not be assigned a name or include forbidden emoji")
        print(f"[rename] 🖨️ Final {len(renamed_nodes)} nodes remain after name correction")

        if not renamed_nodes:
            print("[FATAL] 🅾️ valid nodes after processing. Abort upload.")
            sys.exit(1)

        # ---------------- Load template ----------------
        try:
            r = requests.get(TEMPLATE_URL, timeout=15)
            r.raise_for_status()
            template_text = r.text
        except Exception as e:
            print(f"[FATAL] ⚠️ Failed to fetch ClashTemplate -> {e}")
            sys.exit(1)

        # ---------------- Preferred key order ----------------
        INFO_ORDER = [
            "name", "type", "server", "port", "uuid", "password",
            "encryption", "network", "security", "sni", "servername",
            "skip-cert-verify", "alpn", "fp", "client-fingerprint",
            "path", "ws-opts", "grpc-opts", "h2-opts"
        ]
        
        # ---------------- Function to reorder keys ----------------
        def reorder_info(node, key_order=INFO_ORDER):
            ordered = OrderedDict()
            for key in key_order:
                if key in node:
                    ordered[key] = node[key]
            # append extra keys that aren't in preferred order
            for key in node:
                if key not in ordered:
                    ordered[key] = node[key]
            return ordered

        # ---------------- Convert to YAML ----------------
        nodes_ordered = [reorder_info(n) for n in renamed_nodes]
        nodes_clean = [dict(n) for n in nodes_ordered]
        proxies_yaml_block = yaml.dump(nodes_clean, allow_unicode=True, default_flow_style=False)
        proxy_names_block = "\n".join([f"      - {unquote(p['name'])}" for p in nodes_clean])

        # ---------------- Replace placeholders ----------------
        output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
        output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

        # ---------------- Prepare timestamp ----------------
        offset = timedelta(hours=6, minutes=30)
        utc_now = datetime.now(timezone.utc)
        local_time = utc_now + offset
        timestamp = local_time.strftime("%d.%m.%Y %H:%M:%S")

        # ---------------- Write output ----------------
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Last update: {timestamp}\n" + output_text)
        print(f"[done] 💾 Wrote {OUTPUT_FILE}")

        # Upload to textdb only after all upper processes successful processing
        upload_to_textdb()

    except Exception as e:
        print("[⚠️FATAL ERROR in main]", str(e))
        traceback.print_exc()
        sys.exit(1)

# ---------------- Upload to TextDB ----------------
def upload_to_textdb():
    try:
        # Step 1: Read freshly generated Filter file (local, not GitHub raw)
        with open("MIX", "r", encoding="utf-8") as f:
            output_text = f.read()

        # Step 2: Delete old data
        delete_resp = requests.post(TEXTDB_API, data={"value": ""})
        if delete_resp.status_code == 200:
            print("[info] 🗑️ Successfully deleteded old data on textdb")
        else:
            print(f"[warn] ❌ Failed to delete old data on textdb: {delete_resp.status_code}")
            print(f"[warn] ❗Response: {delete_resp.text}")

        # Wait 3 seconds
        time.sleep(3)

        # Step 3: Upload new data
        upload_resp = requests.post(TEXTDB_API, data={"value": output_text})
        if upload_resp.status_code == 200:
            print("[info] 📤 Successfully uploaded new data on textdb")
        else:
            print(f"[warn] ❌Failed to upload new data on textdb: {upload_resp.status_code}")
            print(f"[warn] ❗Response: {upload_resp.text}")

    except Exception as e:
        print(f"[error] ⛔ Unexpected error: {e}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    main()

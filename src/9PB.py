import os
import sys
import time
import yaml
import requests
import socket
import concurrent.futures
import traceback
from babel import Locale
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import base64
import re
import pycountry
import json
import urllib.parse
from urllib.parse import unquote

# ---------------- Config ----------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUTPUT_FILE = os.path.join(REPO_ROOT, "9PB")
SOURCES_FILE = os.path.join(REPO_ROOT, "SUB_9PB")
TEMPLATE_URL = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/ClashTemplate.ini"
TEXTDB_API = "https://textdb.online/update/?key=9PB_SHFX&value={}"
URL9PB = "https://raw.githubusercontent.com/Vanic24/VPN/refs/heads/main/9PB"
CN_TO_CC = json.loads(os.getenv("CN_TO_CC", "{}"))

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
        print(f"[error] failed to parse CN_TO_CC secret: {e}")
        return {}

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] SUB_9PB not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not sources:
        print(f"[FATAL] SUB_9PB is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

# ---------------- Vmess parsers ----------------
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
def parse_vless(line: str) -> dict | None:
    try:
        if not line.startswith("vless://"):
            return None

        # Split off name/comment
        name_fragment = ""
        if "#" in line:
            line, name_fragment = line.split("#", 1)
            name_fragment = urllib.parse.unquote(name_fragment)

        # Remove scheme
        line = line[len("vless://"):]

        # Split UUID and rest
        if "@" not in line:
            return None
        uuid, rest = line.split("@", 1)

        # Split host:port and query
        if "?" in rest:
            server_port, query_str = rest.split("?", 1)
            query = dict(urllib.parse.parse_qsl(query_str))
        else:
            server_port = rest
            query = {}

        if ":" not in server_port:
            return None
        server, port = server_port.split(":", 1)

        # --- Build node dict ---
        node = {
            "name": name_fragment or "VLESS Node",
            "type": "vless",
            "server": server.strip(),
            "port": int(port.strip()),
            "uuid": uuid.strip(),
        }

        # Encryption (default none)
        if "encryption" in query:
            node["encryption"] = query.get("encryption", "none")
        else:
            node["encryption"] = "none"

        # TLS
        if query.get("security") == "tls":
            node["tls"] = True
            node["servername"] = query.get("sni", "")
            # keep skip-cert-verify default False
            node["skip-cert-verify"] = query.get("allowInsecure", "0") == "1"
            if "fp" in query:
                node["client-fingerprint"] = query["fp"]
        else:
            node["tls"] = False

        # Flow (for reality / xtls-rprx-vision etc.)
        if "flow" in query:
            node["flow"] = query["flow"]

        # Network
        if "type" in query:
            node["network"] = query["type"]

        # WS options
        if node.get("network") == "ws":
            ws_opts = {}
            if "path" in query:
                # Preserve exact path without double-encoding
                ws_opts["path"] = urllib.parse.unquote(query["path"])
            headers = {}
            if "host" in query:
                headers["Host"] = query["host"]
            if headers:
                ws_opts["headers"] = headers
            if ws_opts:
                node["ws-opts"] = ws_opts

        return node

    except Exception as e:
        print(f"[warn] VLESS parse error -> {e}")
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
    """
    Robust, backward-compatible hysteria2 parser.
    - Primary parsing via a single regex similar to your original.
    - Captures optional query string and fragment (name).
    - Only adds optional fields if they exist (doesn't force defaults that could break import).
    - Always returns keys minimal clients expect: name, type, server, port, password.
    """
    try:
        if not line.startswith("hysteria2://"):
            return None

        # regex: capture password, host, port, optional query, optional fragment(name)
        m = re.match(r'hysteria2://([^@]+)@([^:\/?#]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$', line)
        password = host = port = query_str = frag = None

        if m:
            password, host, port, query_str, frag = m.groups()
        else:
            # fallback: try urlparse if regex fails (covers some odd variants)
            parsed = urllib.parse.urlparse(line)
            # parsed.username may be encoded; use split on netloc if needed
            password = urllib.parse.unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port or None
            query_str = parsed.query or ""
            frag = urllib.parse.unquote(parsed.fragment or "")

        if not host or not port:
            # couldn't get host/port -> invalid
            return None

        # Basic node structure (keep same keys your clients accept)
        name = urllib.parse.unquote(frag or "") if frag else ""
        node = {
            "name": name,
            "type": "hysteria2",
            "server": host,
            "port": int(port),
            "password": urllib.parse.unquote(password or ""),
        }

        # Parse query string into dict of lists
        qdict = {}
        if query_str:
            qdict = urllib.parse.parse_qs(query_str)

        # OPTIONAL: include extra fields ONLY if present in the query
        # (these won't be added if absent, keeping backward compatibility)
        if "insecure" in qdict or "sni" in qdict:
            tls_obj = {"enabled": True}
            if "insecure" in qdict:
                v = qdict.get("insecure", ["true"])[0]
                tls_obj["insecure"] = str(v).lower() in ("1", "true", "yes")
            if "sni" in qdict:
                tls_obj["server_name"] = qdict.get("sni", [host])[0]
            node["tls"] = tls_obj

        if "udp" in qdict:
            v = qdict.get("udp", [""])[0]
            node["udp"] = str(v).lower() in ("1", "true", "yes")

        # Keep the same field name your clients may expect for 'server_port' as well,
        # but only add it if you want; comment out next line if it causes problems.
        # node["server_port"] = int(port)

        # Additional optional metadata if present
        for fld in ("groupid", "outlet_ip", "outlet_region", "latency", "domain_resolver"):
            if fld in qdict:
                node[fld] = qdict.get(fld, [""])[0]

        return node

    except Exception as e:
        # keep the error log brief and include line prefix so you can trace problematic ones
        print(f"[warn] hysteria2 parse error: {e} -> {line[:120]}")
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

# ---------------- Base64 parser ----------------
def decode_b64(data: str) -> str | None:
    try:
        data = data.replace("-", "+").replace("_", "/")
        padding = "=" * (-len(data) % 4)
        return base64.b64decode(data + padding).decode("utf-8")
    except Exception:
        return None

import base64, re, urllib.parse

# ---------------- Shadowsocks (SS) parser ----------------
def decode_b64(data: str) -> str | None:
    try:
        data = data.replace("-", "+").replace("_", "/")
        padding = "=" * (-len(data) % 4)
        return base64.b64decode(data + padding).decode("utf-8")
    except Exception:
        return None

def parse_ss(ss_url: str) -> dict | None:
    try:
        ss_url = ss_url.strip()
        if not ss_url.startswith("ss://"):
            return None

        ss_url = ss_url[5:]

        # Extract name/comment if exists
        name_fragment = ""
        if "#" in ss_url:
            ss_url, name_fragment = ss_url.split("#", 1)
            name_fragment = urllib.parse.unquote(name_fragment)

        # Extract plugin query if exists
        plugin = None
        plugin_opts = None
        if "/?" in ss_url:
            ss_core, query = ss_url.split("/?", 1)
            query_params = urllib.parse.parse_qs(query)
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
        else:
            ss_core = ss_url

        if "@" in ss_core:
            b64_part, server_port = ss_core.split("@", 1)
            decoded = decode_b64(b64_part)
            if decoded and ":" in decoded:
                cipher, password = decoded.split(":", 1)
            else:
                cipher = "aes-256-cfb"
                password = decoded or ""
            if ":" not in server_port:
                return None
            server, port = server_port.rsplit(":", 1)
        else:
            decoded = decode_b64(ss_core)
            if not decoded or "@" not in decoded:
                return None
            userinfo, server_port = decoded.split("@", 1)
            if ":" not in userinfo or ":" not in server_port:
                return None
            cipher, password = userinfo.split(":", 1)
            server, port = server_port.rsplit(":", 1)

        node = {
            "name": name_fragment or "SS Node",
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
    except Exception:
        return None

# ---------------- ShadowsocksR (SSR) parser ----------------
def parse_ssr(line):
    try:
        if not line.startswith("ssr://"):
            return None
        b64 = line[6:].strip()
        padded = b64 + "=" * (-len(b64) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")

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
def correct_node(p, country_counter, CN_TO_CC):
    """
    Assign a standardized name to the node without changing any other fields.
    Preserves all original fields to maintain connectivity.
    """

    # Original name
    original_name = str(p.get("name", "") or "").strip()
    host = p.get("server") or p.get("add") or ""

    # Skip locked or empty names
    if not original_name or "🔒" in original_name:
        return None

    cc = None
    flag = None

    # Decode %xx escapes in case node name came from URL fragment
    name_for_match = unquote(original_name)

    # 1️⃣ Chinese mapping (substring match)
    for cn_name, code in CN_TO_CC.items():
        if cn_name and cn_name in name_for_match:
            cc = code.upper()
            flag = country_to_flag(cc)
            country_counter[cc] += 1
            index = country_counter[cc]
            # Only update the name field
            p["name"] = f"{flag}|{cc}{index}-StarLink"
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
            p["name"] = f"{flag}|{cc}{index}-StarLink"
            return p

    # 3️⃣ Two-letter ISO code
    iso_match = re.search(r'\b([A-Z]{2})\b', original_name)
    if iso_match:
        cc = iso_match.group(1).upper()
        flag = country_to_flag(cc)
        country_counter[cc] += 1
        index = country_counter[cc]
        p["name"] = f"{flag}|{cc}{index}-StarLink"
        return p

    # 4️⃣ GeoIP fallback
    ip = resolve_ip(host) or host
    cc_lower, cc_upper = geo_ip(ip)
    if cc_upper and cc_upper != "UN":
        cc = cc_upper
        flag = country_to_flag(cc)
        country_counter[cc] += 1
        index = country_counter[cc]
        p["name"] = f"{flag}|{cc}{index}-StarLink"
        return p

    # 5️⃣ Give up if nothing matched (return original node unchanged)
    return p

# ---------------- Load proxies ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text.strip()

        print(f"[fetch] {url} -> {len(text.splitlines())} lines fetched")
        for line in text.splitlines()[:5]:
            print("       ", line[:80])

        nodes = []

        # Base64 decode if single line and looks like Base64
        if len(text.splitlines()) == 1 and re.match(r'^[A-Za-z0-9+/=]+$', text):
            try:
                decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
                text = decoded
                print(f"[decode] Base64 decoded -> {len(text.splitlines())} lines")
            except Exception:
                print(f"[warn] failed Base64 decode for {url}")

        # Parse as YAML
        if text.startswith("proxies:") or "proxies:" in text:
            try:
                data = yaml.safe_load(text)
                if "proxies" in data:
                    for p in data["proxies"]:
                        nodes.append(p)
                        print(f"[parse] YAML node: {p.get('name','')}")
            except Exception as e:
                print(f"[warn] failed YAML parse {url}: {e}")
        else:
            # Parse as individual subscription lines
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                node = parse_node_line(line)
                if node:
                    print(f"[parsed] {json.dumps(node, ensure_ascii=False)}")
                    nodes.append(node)
                else:
                    print(f"[skip] invalid or unsupported line -> {line[:60]}...")

        return nodes

    except Exception as e:
        print(f"[warn] failed fetch {url} -> {e}")
        return []

# ---------------- Upload to TextDB ----------------
def upload_to_textdb(output_text):
    try:
        # Step 1: Delete old record
        delete_resp = requests.post(TEXTDB_API, data={"value": ""})
        if delete_resp.status_code != 200:
            print(f"[warn] Failed to delete old record: {delete_resp.status_code}")
            return False

        time.sleep(3)

        # Step 2: Upload new
        upload_resp = requests.post(TEXTDB_API, data={"value": output_text})
        if upload_resp.status_code == 200:
            print("[info] Successfully uploaded on textdb")
            return True
        else:
            print(f"[warn] Failed to upload on textdb: {upload_resp.status_code}")
            return False

    except Exception as e:
        print(f"[error] Unexpected error: {e}")
        return False

# ---------------- Main ----------------
def main():
    try:
        sources = load_sources()
        print(f"[start] loaded {len(sources)} sources from Filter_Sources")

        all_nodes = []
        for url in sources:
            nodes = load_proxies(url)
            print(f"[source] {url} -> {len(nodes)} valid nodes")
            all_nodes.extend(nodes)

        print(f"[collect] total {len(all_nodes)} nodes before filtering")

        # ---------------- Latency filter ----------------
        if USE_LATENCY:
            print(f"[latency] filtering nodes > {LATENCY_THRESHOLD} ms")
            country_counter = defaultdict(int)
            filtered_nodes = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                futures = [ex.submit(tcp_latency_ms, n.get("server"), n.get("port")) for n in all_nodes]
                for n, f in zip(all_nodes, futures):
                    latency = f.result()
                    if latency <= LATENCY_THRESHOLD:
                        filtered_nodes.append(n)
            print(f"[latency] {len(filtered_nodes)} nodes after latency filtering")
        else:
            filtered_nodes = all_nodes
            country_counter = defaultdict(int)

        # ---------------- Correct nodes ----------------
        corrected_nodes = []
        cn_to_cc = load_cn_to_cc()
        for n in filtered_nodes:
            res = correct_node(n, country_counter, cn_to_cc)
            if res:
                corrected_nodes.append(res)

        if not corrected_nodes:
            print("[FATAL] No valid nodes after processing. Abort upload.")
            sys.exit(1)

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
        proxy_names_block = "\n".join([f"      - {unquote(p['name'])}" for p in corrected_nodes])

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
        print(f"[done] wrote {OUTPUT_FILE}")

        # ---------------- Upload ----------------
        success = upload_to_textdb(output_text)
        if not success:
            print("[warn] Upload failed. Check TextDB API.")
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

# ---------------- Entry ----------------
if __name__ == "__main__":
    main()

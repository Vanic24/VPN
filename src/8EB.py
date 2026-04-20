import os
import sys
import time
import yaml
import requests
import socket
import threading
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
OUTPUT_FILE = os.path.join(REPO_ROOT, "8EB")
SOURCES_FILE = os.path.join(REPO_ROOT, "SUB_8EB")
CLASH_TEMPLATE = os.path.join(REPO_ROOT, "ClashTemplate.ini")
TEXTDB_API = "https://textdb.online/update/?key=8EB_SHFX&value={}"
USE_ONLY_GEOIP = os.getenv("USE_ONLY_GEOIP", "false").lower() == "true"

# ---------------- Inputs ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"

try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

use_dup_env = os.environ.get("DUPLICATE_FILTER", "false").lower()
USE_DUPLICATE_FILTER = use_dup_env == "true"

# ---------------- Requests session ----------------
session = requests.Session()
session.headers.update({"User-Agent": "Subscription-Updater/1.0"})

# ---------------- Helper ----------------
geoip_lock = threading.Lock()
counter_lock = threading.Lock()

geoip_cache = {}
country_counter = defaultdict(int)

def resolve_ip(host):
    try:
        infos = socket.getaddrinfo(host, None)

        # Prefer IPv4
        for info in infos:
            ip = info[4][0]
            if ":" not in ip:
                return ip

        # fallback to IPv6
        if infos:
            return infos[0][4][0]

        return None

    except Exception:
        return None

def tcp_latency_ms(host, port, timeout=2.0):
    try:
        ip = resolve_ip(host)
        if not ip:
            return 9999

        start = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.close()
        return int((time.time() - start) * 1000)

    except Exception:
        return 9999

def deduplicate_nodes(nodes):
    """
    Remove duplicate nodes based on:
    - (server, port, uuid) OR
    - (server, port, password)

    Server string must match EXACTLY.
    """
    seen = set()
    unique_nodes = []
    removed = 0

    for n in nodes:
        server = str(n.get("server", "")).strip()
        port = int(n.get("port", 0))
        uuid = str(n.get("uuid", "")).strip()
        password = str(n.get("password", "")).strip()

        # Build key
        if uuid:
            key = ("uuid", server, port, uuid)
        elif password:
            key = ("password", server, port, password)
        else:
            # No dedup key → keep it
            unique_nodes.append(n)
            continue

        if key in seen:
            removed += 1
            continue

        seen.add(key)
        unique_nodes.append(n)

    return unique_nodes, removed

def geo_ip(host_or_ip):
    ip = None

    try:
        if not host_or_ip:
            return None, None

        # check cache by hostname
        with geoip_lock:
            if host_or_ip in geoip_cache:
                return geoip_cache[host_or_ip]

        import ipaddress
        try:
            ipaddress.ip_address(host_or_ip)
            ip = host_or_ip
        except:
            ip = resolve_ip(host_or_ip)

        if not ip:
            with geoip_lock:
                geoip_cache[host_or_ip] = ("unknown", "UN")
            return "unknown", "UN"

        # check cache by IP
        with geoip_lock:
            if ip in geoip_cache:
                geoip_cache[host_or_ip] = geoip_cache[ip]
                return geoip_cache[ip]

        r = session.get(f"https://ipinfo.io/{ip}/json", timeout=5)

        if r.status_code != 200:
            with geoip_lock:
                geoip_cache[host_or_ip] = ("unknown", "UN")
                geoip_cache[ip] = ("unknown", "UN")
            return "unknown", "UN"

        data = r.json()
        country = data.get("country", "")

        if not country:
            with geoip_lock:
                geoip_cache[host_or_ip] = ("unknown", "UN")
                geoip_cache[ip] = ("unknown", "UN")
            return "unknown", "UN"

        cc_lower = country.lower()
        cc_upper = country.upper()

        with geoip_lock:
            geoip_cache[host_or_ip] = (cc_lower, cc_upper)
            geoip_cache[ip] = (cc_lower, cc_upper)

        return cc_lower, cc_upper

    except Exception:
        with geoip_lock:
            geoip_cache[host_or_ip] = ("unknown", "UN")
            if ip:
                geoip_cache[ip] = ("unknown", "UN")

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

def build_name(flag, cc, index, ipv6_tag=False):
    suffix = " [ipv6]" if ipv6_tag else ""
    return f"{flag} {cc}-{index}{suffix} | 8EB"

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
    """Attach all unrecognized query fields dynamically, without injecting defaults."""
    known = set(node.keys())
    for k, v in query.items():
        if k not in known and v:  # only non-empty
            v_decoded = urllib.parse.unquote(v)
            if k == "alpn":  # only ALPN is a list
                v_list = [x.strip() for x in v_decoded.split(",") if x.strip()]
                if v_list:
                    node[k] = v_list
            else:  # everything else stays as string
                node[k] = v_decoded
    return node

# -----------------------------------------------------------
# VMESS Parser
# -----------------------------------------------------------
def parse_vmess(line, line_number=None):
    try:
        if not line.startswith("vmess://"):
            return None
        raw = line[8:].strip().replace("\n", "").replace(" ", "")
        missing_padding = len(raw) % 4
        if missing_padding:
            raw += "=" * (4 - missing_padding)
        decoded = base64.b64decode(raw).decode("utf-8")
        data = json.loads(decoded)
        tls_value = str(data.get("tls", "")).lower()

        node = {
            "type": "vmess",
            "name": data.get("ps", "VMESS Node"),
            "server": data.get("add", ""),
            "port": int(data.get("port", 0)),
            "uuid": data.get("id", ""),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "tls": tls_value in ("tls", "1", "true", "yes"),
            "network": data.get("net", "tcp"),
        }

        # ---------------- WS ----------------
        if node["network"] == "ws":
            node["ws-opts"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}

        # ---------------- gRPC ----------------
        if node["network"] == "grpc":
            node["grpc-opts"] = {"grpc-service-name": data.get("path", "")}

        # ---------------- HTTP/2 ----------------
        if node["network"] == "h2":
            node["h2-opts"] = {"path": data.get("path", "/"), "host": [data.get("host", "")]}

        # ---------------- TLS Server Name ----------------
        if node["tls"]:
            node["servername"] = data.get("sni") or data.get("host", "")

        # dynamic fields
        node = merge_dynamic_fields(node, data)

        return node

    except Exception:
        print(f"[warn] ❗Vmess parse error -> Line {line_number}")
        return None

# -----------------------------------------------------------
# VLESS Parser
# -----------------------------------------------------------
def parse_vless(line, line_number=None):
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

        # ---------------- IPv6 / IPv4 handling ----------------
        if host_port.startswith("["):  # IPv6
            end = host_port.find("]")
            if end == -1:
                return None
        
            host = host_port[1:end]
            if len(host_port) <= end + 2:
                return None
        
            port = host_port[end + 2:]
        
        else:  # IPv4 / domain
            if ":" not in host_port:
                return None
            host, port = host_port.rsplit(":", 1)

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
            node["reality-opts"] = {"public-key": query.get("pbk", ""), "short-id": query.get("sid", ""), "server-name": query.get("sni", "")}
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
        if line_number:
            print(f"[warn] ❗VLESS parse error -> Line {line_number}")
        else:
            print(f"[warn] ❗VLESS parse error -> {e}")
        return None

# -----------------------------------------------------------
# TROJAN Parser
# -----------------------------------------------------------
def parse_trojan(line, line_number=None):
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

        # ---------------- IPv6 / IPv4 handling ----------------
        if host_port.startswith("["):  # IPv6
            end = host_port.find("]")
            if end == -1:
                return None

            host = host_port[1:end]

            if len(host_port) <= end + 2:
                return None

            port = host_port[end + 2:]

        else:
            if ":" not in host_port:
                return None
            host, port = host_port.rsplit(":", 1)

        node = {
            "type": "trojan",
            "name": name or "Trojan Node",
            "server": host.strip(),
            "port": int(port.strip()),
            "password": urllib.parse.unquote(password.strip()),
        }

        # TLS / Security
        node["skip-cert-verify"] = query.get("allowInsecure", "0") in ("1", "true", "yes")
        node["security"] = query.get("security", "tls")

        sni = query.get("sni") or query.get("peer")
        if sni:
            node["sni"] = sni
            node["servername"] = sni

        # Network
        if "type" in query:
            node["network"] = query["type"]

        # WS
        if node.get("network") == "ws":
            ws_opts = {"path": urllib.parse.unquote(query.get("path", "/"))}
            if "host" in query:
                ws_opts["headers"] = {"Host": query["host"]}
            node["ws-opts"] = ws_opts

        # gRPC
        elif node.get("network") == "grpc":
            node["grpc-opts"] = {
                "grpc-service-name": query.get("serviceName", "")
            }

        node = merge_dynamic_fields(node, query)

        return node

    except Exception:
        print(f"[warn] ❗Trojan parse error -> Line {line_number}")
        return None

# -----------------------------------------------------------
# HYSTERIA2 Parser
# -----------------------------------------------------------
def parse_hysteria2(line, line_number=None):
    try:
        if not (line.startswith("hysteria2://") or line.startswith("hy2://")):
            return None

        # normalize
        if line.startswith("hy2://"):
            line = "hysteria2://" + line[len("hy2://"):]

        parsed = urllib.parse.urlparse(line)

        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "Hysteria2 Node")

        if not host or not port:
            return None

        node = {
            "type": "hysteria2",
            "name": name,
            "server": host,
            "port": int(port),
            "password": password,
        }

        # ---------------- TLS ----------------
        tls = {}

        if "sni" in query:
            tls["server_name"] = query["sni"]

        if "insecure" in query:
            tls["insecure"] = query["insecure"].lower() in ("1", "true", "yes")

        if tls:
            tls["enabled"] = True
            node["tls"] = tls
            node["skip-cert-verify"] = tls.get("insecure", False)

        # ---------------- OBFS ----------------
        if "obfs" in query:
            node["obfs"] = query["obfs"]

        if "obfs-password" in query:
            node["obfs-password"] = query["obfs-password"]

        # ---------------- ALPN ----------------
        if "alpn" in query:
            node["alpn"] = query["alpn"].split(",")

        # ---------------- Speed ----------------
        if "up" in query:
            node["up"] = query["up"]

        if "down" in query:
            node["down"] = query["down"]

        node = merge_dynamic_fields(node, query)

        return node

    except Exception:
        print(f"[warn] ❗Hysteria2 parse error -> Line {line_number}")
        return None
# -----------------------------------------------------------
# ANYTLS Parser
# -----------------------------------------------------------
def parse_anytls(line, line_number=None):
    try:
        if not line.startswith("anytls://"):
            return None

        parsed = urllib.parse.urlparse(line)

        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "AnyTLS Node")

        if not host or not port:
            return None

        node = {
            "type": "anytls",
            "name": name,
            "server": host,
            "port": int(port),
            "password": password,
        }

        # ---------------- TLS ----------------
        tls = {}

        if "sni" in query:
            tls["server_name"] = query["sni"]
            node["servername"] = query["sni"]

        if "insecure" in query:
            tls["insecure"] = query["insecure"].lower() in ("1", "true", "yes")

        if "allowInsecure" in query:
            tls["insecure"] = query["allowInsecure"].lower() in ("1", "true", "yes")

        if tls:
            tls["enabled"] = True
            node["tls"] = tls
            node["skip-cert-verify"] = tls.get("insecure", False)

        # ---------------- ALPN ----------------
        if "alpn" in query:
            node["alpn"] = query["alpn"].split(",")

        # ---------------- Fingerprint ----------------
        if "fp" in query:
            node["client-fingerprint"] = query["fp"]

        # dynamic fields
        node = merge_dynamic_fields(node, query)

        return node

    except Exception as e:
        print(f"[warn] ❗Anytls parse error -> Line {line_number}")
        return None

# -----------------------------------------------------------
# TUIC Parser
# -----------------------------------------------------------
def parse_tuic(line, line_number=None):
    try:
        if not line.startswith("tuic://"):
            return None

        parsed = urllib.parse.urlparse(line)

        uuid = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname
        port = parsed.port
        query = dict(urllib.parse.parse_qsl(parsed.query))
        name = urllib.parse.unquote(parsed.fragment or "TUIC Node")

        if not host or not port or not uuid:
            return None

        node = {
            "type": "tuic",
            "name": name,
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "password": password,
        }

        # ---------------- TLS ----------------
        tls = {}

        if "sni" in query:
            tls["server_name"] = query["sni"]
            node["servername"] = query["sni"]

        if "insecure" in query:
            tls["insecure"] = query["insecure"].lower() in ("1", "true", "yes")

        if "allowInsecure" in query:
            tls["insecure"] = query["allowInsecure"].lower() in ("1", "true", "yes")

        if tls:
            tls["enabled"] = True
            node["tls"] = tls
            node["skip-cert-verify"] = tls.get("insecure", False)

        # ---------------- ALPN ----------------
        if "alpn" in query:
            node["alpn"] = query["alpn"].split(",")

        # ---------------- congestion ----------------
        if "congestion_control" in query:
            node["congestion-controller"] = query["congestion_control"]

        # ---------------- udp relay ----------------
        if "udp_relay_mode" in query:
            node["udp-relay-mode"] = query["udp_relay_mode"]

        # ---------------- reduce rtt ----------------
        if "reduce_rtt" in query:
            node["reduce-rtt"] = query["reduce_rtt"].lower() in ("1", "true", "yes")

        # ---------------- disable sni ----------------
        if "disable_sni" in query:
            node["disable-sni"] = query["disable_sni"].lower() in ("1", "true", "yes")

        node = merge_dynamic_fields(node, query)

        return node

    except Exception as e:
        print(f"[warn] ❗TUIC parse error -> Line {line_number}")
        return None

# -----------------------------------------------------------
# SHADOWSOCKS (SS) Parser
# -----------------------------------------------------------
def decode_b64(data: str) -> str:
    try:
        data = data.strip()
        data += '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception:
        raise ValueError("Invalid base64 encoding")

def smart_cast(value: str):
    v = value.strip().lower()

    # bool handling
    if v in ["1", "true"]:
        return True
    if v in ["0", "false"]:
        return False

    # int
    if v.isdigit():
        return int(v)

    return value.strip()

def parse_plugin(plugin_str: str):
    plugin_str = urllib.parse.unquote(plugin_str)
    plugin_str = plugin_str.replace("\\=", "=")

    parts = plugin_str.split(";")
    plugin = parts[0].strip()

    opts = {}
    for p in parts[1:]:
        if not p:
            continue

        if "=" in p:
            k, v = p.split("=", 1)
            opts[k.strip()] = smart_cast(v)
        else:
            opts[p.strip()] = True

    return plugin, opts

def normalize_plugin_for_clash(plugin, opts):
    """
    Only fix types, DO NOT change structure
    """
    if not opts:
        return plugin, opts

    fixed = {}

    for k, v in opts.items():
        # enforce correct types only
        if k in ["mux", "tls"]:
            fixed[k] = bool(v)
        else:
            fixed[k] = v

    return plugin, fixed
    
# ---------------- IPv6 safe ----------------
def parse_server_port(srvp: str):
    srvp = srvp.strip()
    if srvp.startswith("["):
        end = srvp.find("]")
        if end == -1:
            raise ValueError("Invalid IPv6 format")

        server = srvp[1:end]
        port = srvp[end + 2:]
    else:
        if ":" not in srvp:
            raise ValueError("Missing port")

        server, port = srvp.rsplit(":", 1)

    return server, int(port)

# -----------------------------------------------------------
# Main Parser
# -----------------------------------------------------------
def parse_ss(line, line_number=None):
    try:
        if not line or not line.startswith("ss://"):
            return None

        raw = line[5:].strip()

        # ---------------- name ----------------
        name = ""
        if "#" in raw:
            raw, name = raw.split("#", 1)
            name = urllib.parse.unquote(name.strip())

        # ---------------- query ----------------
        plugin = None
        plugin_opts = None

        if "?" in raw:
            core, query = raw.split("?", 1)
            params = urllib.parse.parse_qs(query, keep_blank_values=True)

            if "plugin" in params:
                plugin, plugin_opts = parse_plugin(params["plugin"][0])

                # 🔥 normalize for Clash
                plugin, plugin_opts = normalize_plugin_for_clash(plugin, plugin_opts)
        else:
            core = raw

        core = core.strip()

        # ---------------- decode ----------------
        if "@" in core:
            b64_part, srvp = core.split("@", 1)
            decoded = decode_b64(b64_part)

            if ":" not in decoded:
                raise ValueError("Invalid userinfo")

            cipher, password = decoded.split(":", 1)

        else:
            decoded = decode_b64(core)

            if "@" not in decoded:
                raise ValueError("Invalid SIP002 format")

            userinfo, srvp = decoded.split("@", 1)

            if ":" not in userinfo:
                raise ValueError("Invalid userinfo")

            cipher, password = userinfo.split(":", 1)

        # ---------------- server / port ----------------
        server, port = parse_server_port(srvp)

        # ---------------- build node ----------------
        node = {
            "type": "ss",
            "name": name or "SS Node",
            "server": server,
            "port": port,
            "cipher": cipher,
            "password": password,
            "udp": True,  # Clash compatibility
        }

        if plugin:
            node["plugin"] = plugin

        if plugin_opts:
            node["plugin-opts"] = plugin_opts

        return node

    except Exception as e:
        print(f"[warn] ❗SS parse error -> Line {line_number}: {e}")
        return None
        
# -----------------------------------------------------------
# SHADOWSOCKSR (SSR) Parser
# -----------------------------------------------------------
def parse_ssr(line, line_number=None):
    try:
        if not line.startswith("ssr://"):
            return None

        decoded = decode_b64(line[6:]).strip()

        if "/?" in decoded:
            main, query_str = decoded.split("/?", 1)
            qs = dict(urllib.parse.parse_qsl(query_str))
        else:
            main = decoded
            qs = {}

        # ---------------- IPv6 safe ----------------
        if main.count(":") < 5:
            return None

        server, port, protocol, method, obfs, pwd_b64 = main.rsplit(":", 5)

        password = decode_b64(pwd_b64)

        name = ""

        if "remarks" in qs:
            name = urllib.parse.unquote(decode_b64(qs["remarks"]))

        node = {
            "type": "ssr",
            "name": name or "SSR Node",
            "server": server,
            "port": int(port),
            "protocol": protocol,
            "cipher": method,
            "obfs": obfs,
            "password": password
        }

        # ---------------- optional fields ----------------
        if "group" in qs:
            node["group"] = decode_b64(qs["group"])

        if "obfsparam" in qs:
            node["obfs-param"] = decode_b64(qs["obfsparam"])

        if "protoparam" in qs:
            node["protocol-param"] = decode_b64(qs["protoparam"])

        node = merge_dynamic_fields(node, qs)

        return node

    except Exception as e:
        print(f"[warn] ❗SSR parse error -> Line {line_number}")
        return None

# -----------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------
def parse_node_line(line, line_number=None):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    try:
        if line.startswith("vmess://"):
            return parse_vmess(line, line_number)
        
        if line.startswith("vless://"):
            return parse_vless(line, line_number)
        
        if line.startswith("trojan://"):
            return parse_trojan(line, line_number)
        
        if line.startswith("hysteria2://") or line.startswith("hy2://"):
            return parse_hysteria2(line, line_number)
        
        if line.startswith("anytls://"):
            return parse_anytls(line, line_number)
        
        if line.startswith("tuic://"):
            return parse_tuic(line, line_number)
        
        if line.startswith("ss://"):
            return parse_ss(line, line_number)
        
        if line.startswith("ssr://"):
            return parse_ssr(line, line_number)

        return None

    except Exception as e:
        print(f"[warn] ❗Dispatcher error -> Line {line_number}")
        return None

# ----------------------------
# Global counters for rename fallback
# ----------------------------
geoip_primary_fail = 0   # counts nodes where GeoIP mode failed but fallback succeeded
name_primary_fail = 0    # counts nodes where name-based mode failed but fallback succeeded

# ---------------- Rename node ----------------
def rename_node(p, country_counter, CN_TO_CC):
    global geoip_primary_fail, name_primary_fail
    """
    Assign a standardized name to the node without changing any other fields.
    Skip nodes with forbidden emojis or empty names.
    If USE_ONLY_GEOIP is True, assign name by GeoIP only.
    Preserves all original fields to maintain connectivity.
    """

    # Original name
    original_name = str(p.get("name", "") or "").strip()
    host = p.get("server") or p.get("add") or ""

    # Detect ipv6 tag
    ipv6_tag = False
    if re.search(r'[\(\[\{]?\s*ipv6\s*[\)\]\}]?', original_name, flags=re.IGNORECASE):
        ipv6_tag = True

    # Define forbidden emojis (any emoji you want to filter out)
    FORBIDDEN_EMOJIS = {"🔒", "❌", "⚠️", "🚀", "🎁"}

    # Skip nodes with empty names or containing any forbidden emoji
    if any(g in original_name for g in FORBIDDEN_EMOJIS) or not original_name:
        return None

    # ---------- Prepare ----------
    name_for_match = unquote(original_name)
    cc = None
    flag = None

    # Initialize fallback flags for counters
    geoip_failed = False
    name_failed = False

    # ----------If GEOIP-ONLY Mode Is Set----------
    if USE_ONLY_GEOIP:

        # 1️⃣ GeoIP first
        ip = resolve_ip(host) or host
        cc_lower, cc_upper = geo_ip(ip)
        if cc_upper and cc_upper != "UN":
            cc = cc_upper
            flag = country_to_flag(cc)
        else:
            geoip_failed = True

        # 2️⃣ Emoji flag mapping
        if not cc:
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', name_for_match)
            if flag_match:
                flag = flag_match.group(0)
                cc = flag_to_country_code(flag)
                if cc:
                    cc = cc.upper()

        # 3️⃣ Chinese name mapping
        if not cc:
            for cn_name, code in CN_TO_CC.items():
                if not cn_name:
                    continue
                if cn_name in name_for_match:
                    cc = code.upper()
                    flag = country_to_flag(cc)
                    break

        # 4️⃣ Two-letter ISO code (context-aware, unit-safe)
        if not cc:
            iso_iter = re.finditer(r'\b([A-Z]{2})\b', original_name)
            for iso_match in iso_iter:
                iso = iso_match.group(1)
                before = original_name[:iso_match.start()]
                # Avoid some two letters which are identical to two-letters ISO code
                if re.search(r'\d\s*$', before):
                    continue
                cc = iso
                flag = country_to_flag(cc)
                break

        # Final validation
        if not cc or not flag:
            return None    # ❌ truly unnameable → skip

        # 📊 GeoIP fallback success count
        if geoip_failed:
            geoip_primary_fail += 1

        # ----------Final naming----------
        with counter_lock:
            country_counter[cc] += 1
            index = country_counter[cc]
            p["name"] = build_name(flag, cc, index, ipv6_tag)
            return p

    # ----------If GEOIP-ONLY Mode Is Not Set----------
    else:
        # 1️⃣ Emoji flag mapping
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', name_for_match)
        if flag_match:
            flag = flag_match.group(0)
            cc = flag_to_country_code(flag)
            if cc:
                cc = cc.upper()

        # 2️⃣ Chinese name mapping
        if not cc:
            for cn_name, code in CN_TO_CC.items():
                if not cn_name:
                    continue
                if cn_name in name_for_match:
                    cc = code.upper()
                    flag = country_to_flag(cc)
                    break

        # 3️⃣ Two-letter ISO code (unit-safe)
        if not cc:
            iso_iter = re.finditer(r'\b([A-Z]{2})\b', original_name)
            for iso_match in iso_iter:
                iso = iso_match.group(1)
                before = original_name[:iso_match.start()]
                # Avoid some two letters which are identical to two-letters ISO code
                if re.search(r'\d\s*$', before):
                    continue
                cc = iso
                flag = country_to_flag(cc)
                break

        # ---------- GeoIP fallback ----------
        if not cc:
            ip = resolve_ip(host) or host
            if ip:
                cc_lower, cc_upper = geo_ip(ip)
                if cc_upper and cc_upper != "UN":
                    cc = cc_upper
                    flag = country_to_flag(cc)
                    name_primary_fail += 1
        
        # ---------- Final validation ----------
        if not cc or not flag:
            return None    # ❌ truly unnameable → skip

        # ----------Final naming----------
        with counter_lock:
            country_counter[cc] += 1
            index = country_counter[cc]
            p["name"] = build_name(flag, cc, index, ipv6_tag)
            return p

# ---------------- Load proxies ----------------
def load_proxies(url, retries=5):
    attempt = 0
    while attempt < retries:
        try:
            r = session.get(url, timeout=10)
            r.raise_for_status()
            text = r.text.strip()
            nodes = []
            sub_type = None

            # ---------- For Base64 (single-line subscription) decode ----------
            lines = text.splitlines()

            if len(lines) == 1 and re.match(r'^[A-Za-z0-9+/=]+$', text.strip()):
                try:
                    decoded = base64.b64decode(
                        text.strip() + "=" * (-len(text.strip()) % 4)
                    ).decode("utf-8", errors="ignore")

                    decoded_lines = decoded.splitlines()

                    if len(decoded_lines) > 3 and "://" in decoded:
                        text = decoded
                        sub_type = "BASE64"

                        print("[fetch] 📥 Base64 subscription detected", flush=True)

                    else:
                        print("[warn] 😭 Not valid Base64 subscription", flush=True)

                except Exception:
                    print("[warn] 😭 Base64 decode failed", flush=True)

            # ---------- For YAML decode ----------
            if not sub_type and ("proxies:" in text or text.startswith("proxies:")):
                sub_type = "YAML"
                print("[fetch] 📥 YAML subscription detected", flush=True)

            # ---------- For V2Ray decode ----------
            if not sub_type:
                sub_type = "V2RAY"
                print("[fetch] 📥 V2Ray subscription detected", flush=True)

            # ---------- Parse YAML ----------
            if sub_type == "YAML":
                try:
                    data = yaml.safe_load(text)

                    if data and "proxies" in data:
                        for idx, p in enumerate(data["proxies"], start=1):
                            original_name = str(p.get("name", "") or "").strip()

                            if not original_name:
                                p["name"] = f"Node-{idx}"
                            nodes.append(p)
                            protocol = str(p.get("type", "NODE")).upper()

                            print(
                                f"[parse] 🔎 YAML to {protocol} node: {idx} parsed",
                                flush=True
                            )

                    else:
                        print("[warn] 😭 YAML structure invalid or empty", flush=True)

                except Exception:
                    print("[warn] 😭 YAML parsing failed", flush=True)

            # ---------- Parse Base64 or V2Ray ----------
            else:
                for idx, line in enumerate(text.splitlines(), start=1):
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        node = parse_node_line(line, idx)

                        if node:
                            nodes.append(node)
                            protocol = (
                                line.split("://")[0].upper()
                                if "://" in line
                                else "NODE"
                            )

                            if sub_type == "BASE64":
                                print(
                                    f"[parse] 🔎 Base64 to {protocol} node: {idx} parsed", flush=True )
                            else:
                                print(f"[parse] 🔎 {protocol} node: {idx} parsed", flush=True )

                        else:
                            print(f"[skip] ⛔ Invalid or unsupported line ({idx})", flush=True)

                    except Exception:
                        print(
                            f"[warn] 😭 Error parsing line ({idx})", flush=True)

            return nodes

        except Exception:
            attempt += 1
            print("[warn] 😭 Failed to fetch from current subscription link", flush=True)
            print(f"[attempt] 🔄️ Try to fetch again (attempt {attempt}/{retries})", flush=True)
            if attempt >= retries:
                print("[abort] 🚫 Max retries reached. Aborting process.", flush=True)
                exit(1)

# ---------------- Main ----------------
def main():
    try:
        CN_TO_CC = load_cn_to_cc()
        sources = load_sources()
        print(f"[start] 🖥️ Loaded ({len(sources)}) subscription links from source")

        all_nodes = []
        for url in sources:
            nodes = load_proxies(url)
            print(f"[source] 📝 [{len(nodes)}] nodes parsed from current subscription")
            all_nodes.extend(nodes)

        print(f"[collect] 📋 Total [{len(all_nodes)}] nodes successfully parsed and collected from all subscriptions")

        # ---------------- Latency filter ----------------
        if USE_LATENCY:
            print(f"[latency] 🚫 Filtering nodes > {LATENCY_THRESHOLD} ms")
            filtered_nodes = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                futures = [ex.submit(tcp_latency_ms, n.get("server"), n.get("port")) for n in all_nodes]
                for n, f in zip(all_nodes, futures):
                    latency = f.result()
                    if latency <= LATENCY_THRESHOLD:
                        filtered_nodes.append(n)

            num_filtered = len(all_nodes) - len(filtered_nodes)
            print(f"[latency] ❗Filtered {num_filtered} nodes due to latency")
            print(f"[latency]  🖨️ Total [{len(filtered_nodes)}] nodes remain after latency filtering")
        else:
            filtered_nodes = all_nodes
            print(f"[latency] 🚀 Latency filtering disabled, ({len(filtered_nodes)}) nodes remain")

        # ---------------- Duplicate filter ----------------
        if USE_DUPLICATE_FILTER:
            print("[dedup] 🧹 Removing duplicate nodes (server + port + uuid/password)")
            before = len(filtered_nodes)
            filtered_nodes, removed = deduplicate_nodes(filtered_nodes)
            after = len(filtered_nodes)
            print(f"[dedup] ®️emoved ({removed}) duplicate nodes")
            print(f"[dedup] 🖨️ Total [{after}] nodes remain after deduplication")
        else:
            print("[dedup] 🈁 Duplicate filtering disabled")

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

        if USE_ONLY_GEOIP:
            print(
                f"[rename] 🌍 GeoIP-only mode: Failed to rename {geoip_primary_fail} nodes and fallback to Name-based detection"
            )
        else:
            print(
                f"[rename] 🏷️ Name-based mode: Failed to rename ({name_primary_fail}) nodes and fallback to GeoIP detection"
            )

        if skipped_nodes > 0:
            print(f"[rename] ⚠️ Skipped ({skipped_nodes}) nodes that could not be assigned a name or include forbidden emoji")
        print(f"[rename] 🖨️ Final [{len(renamed_nodes)}] nodes remain after name correction")

        if not renamed_nodes:
            print("[FATAL] 🅾️ valid nodes after processing. Abort upload.")
            sys.exit(1)

        # ---------------- Load template ----------------
        try:
            with open(CLASH_TEMPLATE, "r", encoding="utf-8") as f:
                template_text = f.read()
            print("[INFO] Loaded ClashTemplate from local file")
        except Exception as e_local:
            print(f"[FATAL] ⚠️ Failed to load ClashTemplate -> {e_local}")
            sys.exit(1)

        # ---------------- Preferred key order ----------------
        INFO_ORDER = [
            "name", "type", "server", "port", "uuid", "password",
            "encryption", "network", "security", "sni", "servername",
            "skip-cert-verify", "fp", "client-fingerprint",
            "path", "ws-opts", "grpc-opts", "h2-opts"
        ]
        
        # ---------------- Function to reorder keys ----------------
        def reorder_info(node):
            ordered = OrderedDict()
            # Add preferred keys only if they exist in the node
            for key in INFO_ORDER:
                if key in node:
                    val = node[key]
                    # Convert string to list only if original value is a list or comma string
                    if key in ("alpn") and isinstance(val, str):
                        # Only split if val is not empty
                        val_list = [x.strip() for x in val.split(",") if x.strip()]
                        ordered[key] = val_list if val_list else val
                    else:
                        ordered[key] = val
            # Append extra keys not in preferred order
            for key in node:
                if key not in ordered:
                    ordered[key] = node[key]
            return ordered
        
        # Apply to all renamed nodes
        info_ordered = [reorder_info(n) for n in renamed_nodes]
        info_ordered_dicts = [dict(n) for n in info_ordered]

        # Line by line YAML proxies output format
        def make_single_line_yaml(proxies):
            lines = []
            for p in proxies:
                # Convert nested dicts safely
                def to_yaml_value(v):
                    if isinstance(v, dict):
                        inner = ", ".join(f"{k}: {json.dumps(vv, ensure_ascii=False)}" for k, vv in v.items())
                        return "{" + inner + "}"
                    else:
                        return json.dumps(v, ensure_ascii=False)
        
                parts = []
                for k, v in p.items():
                    parts.append(f"{k}: {to_yaml_value(v)}")
        
                line = "- {" + ", ".join(parts) + "}"
                lines.append(line)
        
            return "\n".join(lines)

        # ---------------- Convert to YAML ----------------
        proxies_yaml_block = make_single_line_yaml(info_ordered_dicts)    #If multiple lines format is needed, Delete Line by line YAML proxies output format code block, proxies_yaml_block = yaml.dump(info_ordered_dicts, allow_unicode=True, default_flow_style=False, sort_keys=False)
        proxy_names_block = "\n".join([f"      - {unquote(p['name'])}" for p in info_ordered_dicts])

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
        # Step 1: Read freshly generated subscription file (local, not GitHub raw)
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            output_text = f.read()

        # Step 2: Delete old data
        delete_resp = session.post(TEXTDB_API, data={"value": ""})
        if delete_resp.status_code == 200:
            print("[info] 🗑️ Successfully deleted old data on textdb")
        else:
            print(f"[warn] ❌ Failed to delete old data on textdb: {delete_resp.status_code}")
            print(f"[warn] ❗Response: {delete_resp.text}")

        # Wait 3 seconds
        time.sleep(3)

        # Step 3: Upload new data
        upload_resp = session.post(TEXTDB_API, data={"value": output_text})
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
    

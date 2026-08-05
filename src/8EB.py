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
import re, copy
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

def normalize_node(n):
    """
    Advanced non-destructive normalizer.
    Purpose:
    - Duplicate detection only
    - Never used for final export
    - Supports Clash + Sing-box/Karing formats
    Original node remains untouched.
    """
    if not isinstance(n, dict):
        return None
    n = copy.deepcopy(n)

    # Safe nested objects
    tls_obj = n.get("tls")
    if not isinstance(tls_obj, dict):
        tls_obj = {}
    transport_obj = n.get("transport")

    if not isinstance(transport_obj, dict):
        transport_obj = {}
    ws_opts = n.get("ws-opts")

    if not isinstance(ws_opts, dict):
        ws_opts = {}
    grpc_opts = n.get("grpc-opts")

    if not isinstance(grpc_opts, dict):
        grpc_opts = {}
    reality_opts = n.get("reality-opts")

    if not isinstance(reality_opts, dict):
        reality_opts = {}
    plugin_opts = n.get("plugin-opts")

    if not isinstance(plugin_opts, dict):
        plugin_opts = {}

    # Server normalization
    server = (n.get("server") or n.get("host") or "")
    n["server"] = (str(server).strip().lower().rstrip("."))

    # Port normalization
    try:
        n["port"] = int(n.get("port") or n.get("server_port") or 0)
    except Exception:
        n["port"] = 0

    # Protocol
    n["type"] = (str(n.get("type") or "").strip().lower())

    # ---------------------------------------------------
    # Authentication
    # VMESS -> uuid
    # VLESS -> uuid
    # Trojan/HY2/SS -> password
    # ---------------------------------------------------
    auth = (n.get("uuid") or n.get("password") or "")
    n["_auth"] = (str(auth).strip())

    # Security detection
    if reality_opts:
        n["_security"] = "reality"

    elif tls_obj:
        n["_security"] = "tls"

    elif n.get("security"):
        n["_security"] = str(n.get("security")).lower()

    else:
        n["_security"] = ""

    # SNI detection
    sni = (n.get("sni") or n.get("servername") or n.get("server_name") or tls_obj.get("server_name") or "")
    n["_sni"] = str(sni).strip().lower()

    # Network detection
    network = (n.get("network") or transport_obj.get("type") or "")
    if not network:
        if ws_opts:
            network = "ws"

        elif grpc_opts:
            network = "grpc"

        else:
            network = "tcp"
    n["_network"] = (str(network).strip().lower())

    # Path / service normalization
    path = ""
    if n["_network"] == "ws":
        path = (ws_opts.get("path") or transport_obj.get("path") or n.get("path") or "")

    elif n["_network"] == "grpc":
        path = (grpc_opts.get("grpc-service-name") or grpc_opts.get("serviceName") or transport_obj.get("service_name") or n.get("serviceName") or "")
    n["_path"] = (str(path).strip().lower())

    # Reality public key / short id
    reality_key = (reality_opts.get("public-key") or reality_opts.get("pbk") or n.get("pbk") or "")
    reality_sid = (reality_opts.get("short-id") or reality_opts.get("sid") or n.get("sid") or "")
    n["_reality_key"] = str(reality_key).strip()
    n["_reality_sid"] = str(reality_sid).strip()

    # HY2 special handling
    n.pop("mport", None)
    n.pop("server_ports", None)

    # Remove unstable fields
    for key in (
        "name",
        "tag",
        "remark",
        "ps",
        "metadata",
        "_original",
        "_key_order"
    ):
        n.pop(key, None)

    return n

def deduplicate_nodes(nodes):
    seen = set()
    unique_nodes = []
    removed = 0

    for raw_node in nodes:
        normalized = normalize_node(raw_node)
        if not normalized:
            continue

        # Build stable duplicate key
        key = (
            normalized.get("type", ""),
            normalized.get("server", ""),
            normalized.get("port", ""),

            # authentication
            normalized.get("_auth", ""),

            # TLS / Reality
            normalized.get("_security", ""),
            normalized.get("_sni", ""),

            # transport
            normalized.get("_network", ""),
            normalized.get("_path", ""),

            # Reality
            normalized.get("_reality_key", ""),
            normalized.get("_reality_sid", ""),
        )

        if key in seen:
            removed += 1
            continue 
        seen.add(key)

        # Keep original node, not normalized copy
        unique_nodes.append(raw_node)

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
def decode_base64(data: str) -> str:
    try:
        data = urllib.parse.unquote(data.strip())
        data += "=" * (-len(data) % 4)

        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    except Exception:
        return ""

def safe_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default

# -----------------------------------------------------------
# Helper: Generic dynamic query merger
# -----------------------------------------------------------
def merge_dynamic_fields(node, data):
    """
    Universal dynamic field merger:
    - Works for BOTH JSON (vmess) and URL query (vless/trojan/ss/etc.)
    - Safe against None, int, bool
    - Supports ALPN parsing
    - Supports URL decoding
    """
    # ---------------- remove metadata universally ---------------- 
    node.pop("metadata", None)

    # Reserved / normalized keys
    reserved = {
        # common normalized fields
        "name", "server", "port", "uuid", "password",
        "cipher", "network", "tls", "alterId", "fp", "client-fingerprint",
        "type", "encryption", "headerType", "quicSecurity", "server_ports", "mport",

        # tls / security fields
        "sni", "servername", "server_name", "insecure", "allowInsecure", "security", "flow",
        
        # raw fields (already normalized)
        "v", "ps", "add", "id", "aid", "net",
        "scy", "host", "path", "pbk", "sid",

        # ignore metadata
        "metadata"
    }

    known = set(node.keys()) | reserved

    for k, v in data.items():

        # Ignore metadata completely
        if k.lower() == "metadata":
            continue

        if k in known:
            continue

        # Skip empty / None
        if v is None or v == "":
            continue

        # Convert to string safely
        if not isinstance(v, str):
            v = str(v)

        # URL decode
        v = urllib.parse.unquote(v)

        # Special handling
        if k.lower() == "alpn":
            v_list = [x.strip() for x in v.split(",") if x.strip()]
            if v_list:
                node[k] = v_list
        else:
            node[k] = v

    return node

# -----------------------------------------------------------
# VMESS Parser
# -----------------------------------------------------------
def normalize_vmess_json(data):
    normalized = {}

    for k, v in data.items():
        if v is None:
            normalized[k] = ""

        elif isinstance(v, (str, int, float, bool, list, dict)):
            normalized[k] = v

        else:
            normalized[k] = str(v)

    return normalized

# ---------------- Main VMESS parser ----------------
def parse_vmess(line, line_number=None):
    try:
        if not line or not line.startswith("vmess://"):
            return None

        # VMESS URI FORMAT
        if "@" in line:
            parsed = urllib.parse.urlparse(line)
            uuid = urllib.parse.unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
            name = urllib.parse.unquote(parsed.fragment or "VMESS Node")

            if not uuid or not host or not port:
                return None

            node = {
                "type": "vmess",
                "name": name,
                "server": host,
                "port": int(port),
                "uuid": uuid,
                "alterId": 0,
                "cipher": query.get("encryption", "auto"),
                "network": query.get("type", "tcp"),
                "udp": True,
            }

            # TLS
            security = query.get("security")
            if security == "tls": node["tls"] = {"enabled": True}

            # TCP
            if node["network"] == "tcp": node["network"] = "tcp"
            node = merge_dynamic_fields(node, query)
            node["_key_order"] = list(node.keys())

            return node

        # Decode
        raw = line[8:]
        decoded = decode_base64(raw)

        if not decoded:
            raise ValueError("Empty decode result")

        data = json.loads(decoded)
        data = normalize_vmess_json(data)

        # ---------------- Core ----------------
        network = (data.get("net") or data.get("type") or "tcp")
        node = {
            "type": "vmess",
            "name": data.get("ps") or "VMESS Node",
            "server": data.get("add") or "",
            "port": safe_int(data.get("port")),
            "uuid": data.get("id") or "",
            "alterId": safe_int(data.get("aid")),
            "cipher": data.get("scy") or "auto",
            "network": network,
            "udp": True,
        }

        # ---------------- TLS ----------------
        tls_val = data.get("tls")
        tls_enabled = False
        
        if isinstance(tls_val, str):
            tls_enabled = tls_val.lower() in (
                "tls",
                "1",
                "true",
                "yes"
            )

        elif isinstance(tls_val, bool):
            tls_enabled = tls_val

        if tls_enabled:
            tls = {"enabled": True}
            sni = (data.get("sni") or data.get("host"))

            if sni:
                tls["server_name"] = sni
            node["tls"] = tls

        # ---------------- Fingerprint ----------------
        if data.get("fp"):
            node["client-fingerprint"] = data["fp"]

        # ---------------- Network ----------------
        if network == "ws":
            ws_opts = {"path": data.get("path") or "/", "headers": {"Host": data.get("host") or ""}}
            node["ws-opts"] = ws_opts

        elif network == "grpc":
            node["grpc-opts"] = {"grpc-service-name": data.get("path") or ""}

        elif network == "h2":
            node["h2-opts"] = {"path": data.get("path") or "/", "host": [data.get("host") or ""]}

        # ---------------- Remove raw duplicate keys ----------------
        for key in (
            "ps",
            "add",
            "port",
            "id",
            "aid",
            "net",
            "type",
            "tls"
        ):

            data.pop(key, None)

        # ---------------- Dynamic ----------------
        node = merge_dynamic_fields(node, data)
        node["_key_order"] = list(node.keys())
        
        return node

    except Exception as e:
        print(f"[warn] ❗Vmess parse error -> Line {line_number}: {e}")

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

        host_port = host_port.strip().rstrip("/")

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

        try:
            port = int(port)
        except ValueError:
            port = int(port.strip("/"))

        node = {
            "type": "vless",
            "name": name or "VLESS Node",
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "udp": True,
        }
        
        # preserve important raw fields
        for key in ["flow"]:
            if key in query and query[key]:
                node[key] = query[key]

        # Security (TLS / Reality)
        if query.get("security") == "tls":
            node["tls"] = True
            node["skip-cert-verify"] = (query.get("allowInsecure", "0") in ("1", "true"))
        
            sni = query.get("sni") or query.get("peer")
            if sni:
                node["servername"] = sni
            if query.get("fp"):
                node["client-fingerprint"] = query["fp"]

        elif query.get("security") == "reality":
            node["tls"] = True
            node["skip-cert-verify"] = (query.get("insecure", "0") in ("1", "true"))
        
            if query.get("sni"):
                node["servername"] = query["sni"]
        
            if query.get("fp"):
                node["client-fingerprint"] = query["fp"]
        
            node["reality-opts"] = {"public-key": query.get("pbk", ""), "short-id": query.get("sid", "")}
            
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

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        if line_number:
            print(f"[warn] ❗VLESS parse error -> Line {line_number}: {e}")
        return None
        
# -----------------------------------------------------------
# TROJAN Parser
# -----------------------------------------------------------
def parse_trojan(line, line_number=None):
    try:
        if not line.startswith("trojan://"):
            return None

        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port
        password = unquote(parsed.username or "")
        query = {k: v[-1] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        name = unquote(parsed.fragment) if parsed.fragment else ""

        node = {
            "type": "trojan",
            "name": name or "Trojan Node",
            "server": host.strip(),
            "port": int(port),
            "password": password.strip(),
        }

        # TLS
        node["skip-cert-verify"] = query.get("allowInsecure", "0") in ("1", "true", "yes")
        node["security"] = query.get("security", "tls")
        sni = query.get("sni") or query.get("peer")
        
        if sni:
            node["sni"] = sni
            node["servername"] = sni

        # uTLS
        if query.get("fp"):
            node["client-fingerprint"] = query["fp"]

        # Network
        network = query.get("type")

        if network:
            node["network"] = network

        # WebSocket
        if network == "ws":
            ws_opts = {"path": urllib.parse.unquote(query.get("path", "/"))}
            host_header = (query.get("host") or sni)

            if host_header: ws_opts["headers"] = {"Host": host_header}
            node["ws-opts"] = ws_opts

        # gRPC
        elif network == "grpc":
            node["grpc-opts"] = {"grpc-service-name": query.get("serviceName", "")}

        # Dynamic fields
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        print(f"[warn] ❗Trojan parse error -> Line {line_number}: {e}")
        return None
        
# -----------------------------------------------------------
# HYSTERIA2 Parser
# -----------------------------------------------------------
def parse_hysteria2(line, line_number=None):
    try:
        if not (line.startswith("hysteria://") or line.startswith("hysteria2://") or line.startswith("hy2://")):
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

        # ---------------------------------------------------
        # Port hopping support (port=0 + mport)
        # ---------------------------------------------------
        if port == 0 and "mport" in query:
            rng = query["mport"]

            if "-" in rng:
                port = safe_int(rng.split("-", 1)[0])
            else:
                port = safe_int(rng)

        if not host or port is None:
            return None

        node = {
            "type": "hysteria2",
            "name": name,
            "server": host,
            "port": int(port),
            "password": password,
            "udp": True,
        }

        # ---------------------------------------------------
        # mport / server_ports
        # ---------------------------------------------------
        if "mport" in query:
            node["ports"] = query["mport"]
            node["mport"] = query["mport"]

        # ---------------------------------------------------
        # TLS/SNI handeling
        # ---------------------------------------------------
        if query.get("sni"):
            node["sni"] = query["sni"]
                
        # Certificate fingerprint
        if query.get("pinSHA256"):
            node["fingerprint"] = query["pinSHA256"]
        
        # Insecure TLS
        insecure = False
        
        if query.get("insecure", "").lower() in ("1", "true", "yes"):
            insecure = True
        
        if query.get("allowInsecure", "").lower() in ("1", "true", "yes"):
            insecure = True
        
        # pinSHA256 usually works with insecure mode
        if query.get("pinSHA256"):
            insecure = True
        
        if insecure:
            node["skip-cert-verify"] = True

        # ---------------------------------------------------
        # OBFS
        # ---------------------------------------------------
        if "obfs" in query:
            node["obfs"] = query["obfs"]

        if "obfs-password" in query:
            node["obfs-password"] = query["obfs-password"]

        # ---------------------------------------------------
        # ALPN
        # ---------------------------------------------------
        if "alpn" in query:
            node["alpn"] = [
                x.strip()
                for x in query["alpn"].split(",")
                if x.strip()
            ]

        # ---------------------------------------------------
        # Speed
        # ---------------------------------------------------
        if "up" in query:
            node["up"] = query["up"]

        if "down" in query:
            node["down"] = query["down"]

        # Preserve original HY2 fields
        for key, value in query.items():
            if key not in node:
                node[key] = value

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)       
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        print(f"[warn] ❗Hysteria2 parse error -> Line {line_number}: {e}")
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
            "udp": True,
        }

        # ---------------- TLS / SNI ----------------
        if "sni" in query:
            node["sni"] = query["sni"]
        
        if "insecure" in query:
            node["skip-cert-verify"] = (
                query["insecure"].lower()
                in ("1", "true", "yes")
            )
        
        # ---------------- ALPN ----------------
        if "alpn" in query:
            node["alpn"] = query["alpn"].split(",")

        # ---------------- Fingerprint ----------------
        if "fp" in query:
            node["client-fingerprint"] = query["fp"]

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
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
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
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
        tls = {"enabled": True}
        sni = query.get("sni")

        if sni:
            tls["server_name"] = sni
        insecure = (query.get("insecure") or query.get("allowInsecure") or "false")
        tls["insecure"] = str(insecure).lower() in ("1", "true", "yes")

        # uTLS fingerprint support
        if query.get("fp"):
            tls["utls"] = {"enabled": True}
            node["client-fingerprint"] = query["fp"]
        node["tls"] = tls

        if tls["insecure"]:
            node["skip-cert-verify"] = True

        # ---------------- ALPN ----------------
        if "alpn" in query:
            node["alpn"] = [x.strip() for x in query["alpn"].split(",") if x.strip()]

        # ---------------- Congestion ----------------
        if "congestion_control" in query:
            node["congestion-controller"] = (query["congestion_control"])

        # ---------------- UDP relay ----------------
        if "udp_relay_mode" in query:
            node["udp-relay-mode"] = (query["udp_relay_mode"])

        # ---------------- Reduce RTT ----------------
        if "reduce_rtt" in query:
            node["reduce-rtt"] = str(query["reduce_rtt"]).lower() in ("1", "true", "yes")

        # ---------------- Disable SNI ----------------
        if "disable_sni" in query:
            node["disable-sni"] = str(query["disable_sni"]).lower() in ("1", "true", "yes")

        # ---------------- Remove converted fields ----------------
        for key in (
            "sni",
            "insecure",
            "allowInsecure",
            "fp",
            "alpn",
            "congestion_control",
            "udp_relay_mode",
            "reduce_rtt",
            "disable_sni"
        ):
            query.pop(key, None)

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        print(
            f"[warn] ❗TUIC parse error -> Line {line_number}: {e}"
        )
        return None

# -----------------------------------------------------------
# SHADOWSOCKS (SS) Parser
# -----------------------------------------------------------
def smart_cast(value: str):
    v = value.strip().lower()

    if v in ["true"]:
        return True
    if v in ["false"]:
        return False

    if v.isdigit():
        return int(v)

    return value.strip()

# ---------------- Plugin parser ----------------
def parse_plugin(plugin_str: str):
    # 🔥 handle double-encoded links
    for _ in range(2):
        plugin_str = urllib.parse.unquote(plugin_str)

    # 🔥 fix escaped chars
    plugin_str = plugin_str.replace("\\=", "=").replace("\\\\", "\\")
    parts = plugin_str.split(";")
    plugin = parts[0].strip()
    opts = {}

    for p in parts[1:]:
        if not p:
            continue

        if "=" in p:
            k, v = p.split("=", 1)
            key = k.strip()
            val = v.strip()

            # ✅ type safety for critical fields
            if key == "tls":
                opts[key] = val.lower() in ["1", "true"]
            
            elif key == "mux":
                v = str(val).lower()
            
                if v in ["0", "false"]:
                    opts[key] = 0
                elif v in ["1", "true"]:
                    opts[key] = 1
                else:
                    opts[key] = smart_cast(val)
        else:
            opts[p.strip()] = True
    return plugin, opts

# ---------------- Server / Port ----------------
def parse_server_port(srvp: str):
    srvp = srvp.strip().rstrip("/")

    # IPv6
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

# ---------------- Main SS parser ----------------
def parse_ss(line, line_number=None):
    try:
        if not line or not line.startswith("ss://"):
            return None

        raw = line[5:].strip()

        # -------- name --------
        name = ""
        if "#" in raw:
            raw, name = raw.split("#", 1)
            name = urllib.parse.unquote(name.strip())

        # -------- query --------
        plugin = None
        plugin_opts = None
        query = {}

        if "?" in raw:
            core, query_raw = raw.split("?", 1)
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(query_raw, keep_blank_values=True).items()}
        
            if "plugin" in query:
                plugin, plugin_opts = parse_plugin(query["plugin"])
                query.pop("plugin", None)
        
        else:
            core = raw
        core = core.strip()

        # -------- decode --------
        if "@" in core:
            # base64(method:password)@server:port
            b64_part, srvp = core.split("@", 1)
            decoded = decode_base64(b64_part)
        
            if ":" not in decoded:
                raise ValueError("Invalid userinfo")
            cipher, password = decoded.split(":", 1)
        
        else:
            # SIP002 full base64
            decoded = decode_base64(core)
        
            if "@" not in decoded:
                raise ValueError("Invalid SS format")
            userinfo, srvp = decoded.split("@", 1)
        
            if ":" not in userinfo:
                raise ValueError("Invalid userinfo")
            cipher, password = userinfo.split(":", 1)

        # -------- server / port --------
        server, port = parse_server_port(srvp)

        # -------- build node --------
        node = {
            "type": "ss",
            "name": name or "SS Node",
            "server": server,
            "port": port,
            "cipher": cipher,
            "password": password,
            "udp": True,
        }

        if plugin:
            node["plugin"] = plugin

        if plugin_opts:
            node["plugin-opts"] = plugin_opts

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
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
        decoded = decode_base64(line[6:]).strip()

        if not decoded:
            return None

        # ---------------- Query ----------------
        if "/?" in decoded:
            main, query_str = decoded.split("/?", 1)
            qs = {k: v[-1] for k, v in urllib.parse.parse_qs(query_str,keep_blank_values=True).items()}

        else:
            main = decoded
            qs = {}

        # ---------------- Parse Core ----------------
        try:
            server, port, protocol, method, obfs, pwd_b64 = (main.rsplit(":", 5))

        except ValueError:
            return None

        password = decode_base64(pwd_b64)
        name = ""

        if "remarks" in qs:
            name = urllib.parse.unquote(decode_base64(qs["remarks"]))

        node = {
            "type": "ssr",
            "name": name or "SSR Node",
            "server": server,
            "port": safe_int(port),
            "protocol": protocol,
            "cipher": method,
            "obfs": obfs,
            "password": password,
        }

        # ---------------- Optional Fields ----------------
        if "group" in qs:
            node["group"] = decode_base64(qs["group"])

        if "obfsparam" in qs:
            node["obfs-param"] = decode_base64(qs["obfsparam"])

        if "protoparam" in qs:
            node["protocol-param"] = decode_base64(qs["protoparam"])

        # ---------------- Remove Converted Fields ----------------
        for key in (
            "remarks",
            "group",
            "obfsparam",
            "protoparam"
        ):
            qs.pop(key, None)

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, qs)
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        print(f"[warn] ❗SSR parse error -> Line {line_number}: {e}")
        return None

# -----------------------------------------------------------
# SOCKS / SOCKS5 Parser
# -----------------------------------------------------------
def parse_socks(line, line_number=None):
    try:
        if line.startswith("socks5://"):
            raw = line[len("socks5://"):].strip()

        elif line.startswith("socks://"):
            raw = line[len("socks://"):].strip()

        else:
            return None

        # -------- tag --------
        tag = ""

        if "#" in raw:
            raw, tag = raw.split("#", 1)
            tag = urllib.parse.unquote(tag.strip())
        raw = raw.strip()
        username = ""
        password = ""

        # -------- query --------
        query = {}

        if "?" in raw:
            raw, query_raw = raw.split("?", 1)
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(query_raw, keep_blank_values=True).items()}

        # -------- auth --------
        if "@" in raw:
            auth, srvp = raw.rsplit("@", 1)
            auth = urllib.parse.unquote(auth)

            if ":" in auth:
                username, password = auth.split(":", 1)
            else:
                username = auth

        else:
            srvp = raw

        # -------- server / port --------
        server, port = parse_server_port(srvp)

        node = {
            "type": "socks",
            "name": tag or "SOCKS Node",
            "server": server,
            "port": port,
            "username": username,
            "password": password,
        }

        # Remove empty auth fields
        if not username:
            node.pop("username", None)

        if not password:
            node.pop("password", None)

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())
        return node

    except Exception as e:
        print(f"[warn] ❗SOCKS parse error -> Line {line_number}: {e}")
        return None

# -----------------------------------------------------------
# HTTP / HTTPS Proxy Parser
# -----------------------------------------------------------
def parse_http(line, line_number=None):
    try:
        if not (
            line.startswith("http://")
            or line.startswith("https://")
        ):
            return None

        # ---------------- Parse URL ----------------
        parsed = urllib.parse.urlparse(line)
        host = parsed.hostname
        port = parsed.port

        if not host:
            return None

        # Default ports
        if not port:
            if parsed.scheme == "https":
                port = 443

            else:
                port = 80

        # ---------------- Authentication ----------------
        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")

        # ---------------- Name ----------------
        name = urllib.parse.unquote(parsed.fragment or "HTTP Node")
        node = {
            "type": "http",
            "name": name,
            "server": host,
            "port": int(port),
        }

        # ---------------- Auth ----------------
        if username:
            node["username"] = username

        if password:
            node["password"] = password

        # ---------------- TLS ----------------
        if parsed.scheme == "https": node["tls"] = {"enabled": True}

        # ---------------- Query fields ----------------
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}

        # ---------------- Dynamic Fields ----------------
        node = merge_dynamic_fields(node, query)
        node["_key_order"] = list(node.keys())

        return node

    except Exception as e:
        print(f"[warn] ❗HTTP parse error -> Line {line_number}: {e}")
        return None

# -----------------------------------------------------------
# Normalize MUX
# -----------------------------------------------------------
def normalize_mux(node):
    try:
        if "plugin-opts" in node and isinstance(node["plugin-opts"], dict):
            mux_val = node["plugin-opts"].get("mux")

            if mux_val is not None:
                v = str(mux_val).lower()

                if v in ["0", "false"]:
                    node["plugin-opts"]["mux"] = 0
                elif v in ["1", "true"]:
                    node["plugin-opts"]["mux"] = 1
                else:
                    node["plugin-opts"]["mux"] = int(v) if v.isdigit() else 0

    except Exception:
        pass

    return node

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
        
        if line.startswith(("hysteria://", "hysteria2://", "hy2://")):
            return parse_hysteria2(line, line_number)
        
        if line.startswith("anytls://"):
            return parse_anytls(line, line_number)
        
        if line.startswith("tuic://"):
            return parse_tuic(line, line_number)
        
        if line.startswith("ss://"):
            return parse_ss(line, line_number)
        
        if line.startswith("ssr://"):
            return parse_ssr(line, line_number)

        if line.startswith(("socks://", "socks5://")):
            return parse_socks(line, line_number)

        if line.startswith(("http://", "https://")):
            return parse_http(line, line_number)

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
    backup = copy.deepcopy(p)
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

            # Restore everything except name
            old_name = p["name"]
            p.clear()
            p.update(backup)
            p["name"] = old_name
            
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
                    decoded = base64.b64decode(text.strip() + "=" * (-len(text.strip()) % 4)).decode("utf-8", errors="ignore")
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
            
                            p.pop("metadata", None)
                            nodes.append(p)
                            protocol = str(p.get("type", "NODE")).upper()
                            print(f"[parse] 🔎 YAML to {protocol} node: {idx} parsed", flush=True)
            
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
                            # Preserve original parsed data
                            node["_original"] = copy.deepcopy(node)
                        
                            nodes.append(node)
                            protocol = (
                                line.split("://")[0].upper()
                                if "://" in line
                                else "NODE"
                            )

                            if sub_type == "BASE64":
                                print(f"[parse] 🔎 Base64 to {protocol} node: {idx} parsed", flush=True )
                            else:
                                print(f"[parse] 🔎 {protocol} node: {idx} parsed", flush=True )

                        else:
                            print(f"[skip] ⛔ Invalid or unsupported line ({idx})", flush=True)

                    except Exception:
                        print(f"[warn] 😭 Error parsing line ({idx})", flush=True)

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

        if USE_ONLY_GEOIP:
            print(f"[rename] 🌍 GeoIP-only mode: Failed to rename {geoip_primary_fail} nodes and fallback to Name-based detection")
            
        else:
            print(f"[rename] 🏷️ Name-based mode: Failed to rename ({name_primary_fail}) nodes and fallback to GeoIP detection")

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
            print("[INFO] Loaded ClashTemplate")
        except Exception as e_local:
            print(f"[FATAL] ⚠️ Failed to load ClashTemplate -> {e_local}")
            sys.exit(1)
  
        # ---------------- Remove empyt fields ----------------
        def remove_empty_fields(obj):
            if isinstance(obj, dict):
                cleaned = {}
        
                for k, v in obj.items():
                    v = remove_empty_fields(v)
        
                    if v is None:
                        continue
        
                    if isinstance(v, str) and v == "":
                        continue
        
                    if isinstance(v, dict) and not v:
                        continue
        
                    cleaned[k] = v
        
                return cleaned
        
            elif isinstance(obj, list):
                return [
                    remove_empty_fields(x)
                    for x in obj
                    if x is not None
                ]
        
            return obj
            
        # ---------------- Function to reorder keys ----------------
        def reorder_info(node):
            node = copy.deepcopy(node)
            ordered = OrderedDict()
            original_order = node.get("_key_order", [])
        
            # Restore original parser order
            for key in original_order:
                if key in node:
                    ordered[key] = node[key]
        
            # Add fields without recorded order
            for key in node:
                if key not in ordered and key != "_key_order":
                    ordered[key] = node[key]
        
            # remove internal field
            ordered.pop("_key_order", None)
            return ordered
        
        # Apply to all renamed nodes
        normalized_nodes = [normalize_mux(copy.deepcopy(n)) for n in renamed_nodes]
        info_ordered = [reorder_info(n) for n in normalized_nodes]
        info_ordered_dicts = [remove_empty_fields(dict(n)) for n in info_ordered]

        # Remove internal parser metadata before final export
        for n in info_ordered_dicts:
            n.pop("_original", None)
            n.pop("_key_order", None)
        
            # Remove raw HY2 URL-only fields
            if n.get("type") == "hysteria2":
                n.pop("insecure", None)
                n.pop("pinSHA256", None)

        # Line by line YAML proxies output format
        def make_single_line_yaml(proxies):
            lines = []
            for p in proxies:
                # Convert nested dicts safely
                def to_yaml_value(v):

                    if isinstance(v, dict):
                        inner = ", ".join(f"{k}: {to_yaml_value(vv)}" for k, vv in v.items())
                        return "{" + inner + "}"
                
                    elif isinstance(v, list):
                        return "[" + ", ".join(json.dumps(x, ensure_ascii=False) for x in v) + "]"
                
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

        # ---------------- Final output ----------------
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Last update: {timestamp}\n" + output_text)
        print(f"[done] 💾 Final subscription generated using clash template")

        # Upload to textdb only after all upper processes successful processing
        upload_to_textdb()

    except Exception as e:
        print("[⚠️ FATAL ERROR in main]", str(e))
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
            print(f"[warn] ❌ Failed to upload new data on textdb: {upload_resp.status_code}")
            print(f"[warn] ❗Response: {upload_resp.text}")

    except Exception as e:
        print(f"[error] ⛔ Unexpected error: {e}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    main()

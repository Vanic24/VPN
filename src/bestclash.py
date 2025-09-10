#!/usr/bin/env python3
# src/bestclash.py
import os
import sys
import yaml
import requests
import socket
import concurrent.futures
import traceback
import base64
import json
import re
from urllib.parse import urlparse, unquote, parse_qs
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

# ---------------- Base64 helper ----------------
def safe_b64decode(s):
    """
    Try to decode base64 string s robustly (handles URL-safe and missing padding).
    Returns bytes or None.
    """
    if s is None:
        return None
    if isinstance(s, str):
        s = s.strip()
        # Replace URL-safe characters
        s = s.replace('-', '+').replace('_', '/')
        # Remove whitespace/newlines that sometimes break decoding
        s = re.sub(r'\s+', '', s)
        # Add padding
        pad = (-len(s)) % 4
        s += "=" * pad
        try:
            return base64.b64decode(s)
        except Exception:
            try:
                return base64.urlsafe_b64decode(s)
            except Exception:
                return None
    return None

# ---------------- Parsers for various link types ----------------
def parse_vmess(line):
    """
    Parse vmess://base64(json) and return a dict with fields.
    """
    try:
        payload = line
        if line.startswith("vmess://"):
            payload = line[8:]
        b = safe_b64decode(payload)
        if not b:
            # sometimes users give raw JSON without vmess://
            if line.strip().startswith("{"):
                s = line.strip()
                data = json.loads(s)
            else:
                return None
        else:
            s = b.decode("utf-8", errors="strict")
            data = json.loads(s)
        server = data.get("add") or data.get("server")
        port = int(data.get("port") or data.get("p") or 443)
        return {
            "name": data.get("ps") or data.get("name") or server,
            "server": server,
            "port": port,
            "uuid": (data.get("id") or data.get("uuid") or ""),
            "alterId": int(data.get("aid")) if data.get("aid") else data.get("alterId"),
            "cipher": data.get("scy") or data.get("cipher"),
            "network": data.get("net"),
            "_type": "vmess",
            "raw": data
        }
    except Exception:
        return None

def parse_vless(line):
    """
    Parse vless://UUID@host:port?params#name
    """
    try:
        if not line.startswith("vless://"):
            return None
        parsed = urlparse(line)
        if parsed.scheme != "vless":
            return None
        uuid = parsed.username or ""
        host = parsed.hostname
        port = parsed.port or 443
        name = unquote(parsed.fragment) if parsed.fragment else parsed.netloc
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return {
            "name": name or host,
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "_type": "vless",
            "params": params
        }
    except Exception:
        return None

def parse_trojan(line):
    """
    parse trojan://password@host:port#name
    """
    try:
        parsed = urlparse(line)
        if parsed.scheme != "trojan":
            return None
        password = parsed.username or ""
        host = parsed.hostname
        port = parsed.port or 443
        name = unquote(parsed.fragment) if parsed.fragment else parsed.netloc
        return {
            "name": name or host,
            "server": host,
            "port": int(port),
            "password": password,
            "_type": "trojan",
        }
    except Exception:
        return None

def parse_ssr(line):
    """
    Parse ssr://base64(...) format and return a dict.
    SSR decoded string: server:port:protocol:method:obfs:base64(passwd)/?params
    """
    try:
        payload = line
        if line.startswith("ssr://"):
            payload = line[6:]
        b = safe_b64decode(payload)
        if not b:
            return None
        s = b.decode("utf-8", errors="strict")
        main, _, params = s.partition("/?")
        parts = main.split(":")
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, pwd_b64 = parts[:6]
        pwd_bytes = safe_b64decode(pwd_b64) or b""
        try:
            passwd = pwd_bytes.decode("utf-8", errors="strict")
        except:
            passwd = ""
        p = {
            "name": server,
            "server": server,
            "port": int(port),
            "password": passwd,
            "protocol": protocol,
            "method": method,
            "obfs": obfs,
            "_type": "ssr",
        }
        if params:
            qs = parse_qs(params)
            for k in ("remarks", "obfsparam", "group", "protoparam"):
                if k in qs:
                    try:
                        v = qs[k][0]
                        dec = safe_b64decode(v)
                        if dec:
                            v_dec = dec.decode("utf-8", errors="ignore")
                            if k == "remarks":
                                p["name"] = v_dec
                            else:
                                p[k] = v_dec
                    except Exception:
                        pass
        return p
    except Exception:
        return None

def parse_ss(line):
    """
    Parse Shadowsocks (ss://) in common variants.
    """
    try:
        content = line
        if line.startswith("ss://"):
            content = line[5:]
        name = None
        if "#" in content:
            content, frag = content.split("#", 1)
            name = unquote(frag)
        if "@" in content:
            left, right = content.rsplit("@", 1)
            creds = left
            if ":" not in creds:
                dec = safe_b64decode(creds)
                if not dec:
                    return None
                creds = dec.decode("utf-8", errors="strict")
            method, password = creds.split(":", 1)
            hostport = right
            if "/" in hostport:
                hostport = hostport.split("/", 1)[0]
            if ":" in hostport:
                server, port = hostport.split(":", 1)
            else:
                server, port = hostport, 8388
            return {
                "name": name or server,
                "server": server,
                "port": int(port),
                "password": password,
                "method": method,
                "_type": "ss",
            }
        else:
            dec = safe_b64decode(content)
            if not dec:
                return None
            s = dec.decode("utf-8", errors="strict")
            if "@" not in s:
                return None
            creds, hostport = s.split("@", 1)
            method, password = creds.split(":", 1)
            if ":" in hostport:
                server, port = hostport.split(":", 1)
            else:
                server, port = hostport, 8388
            return {
                "name": name or server,
                "server": server,
                "port": int(port),
                "password": password,
                "method": method,
                "_type": "ss",
            }
    except Exception:
        return None

def parse_generic_scheme(line):
    """
    Attempt to parse other scheme-based links (hysteria, hysteria2, anytls, etc.)
    We'll extract username/password, host, port, fragment as name, and store scheme as _type.
    """
    try:
        parsed = urlparse(line)
        if not parsed.scheme:
            return None
        scheme = parsed.scheme.lower()
        # Only accept known-ish schemes or treat unknown scheme generically
        if scheme not in ("hysteria", "hysteria2", "anytls", "anytls2", "vless", "trojan", "ss", "ssr", "vmess"):
            # still accept as generic if it has host and port
            if not parsed.hostname:
                return None
        name = unquote(parsed.fragment) if parsed.fragment else parsed.netloc
        entry = {
            "name": name or parsed.hostname,
            "server": parsed.hostname,
            "port": parsed.port or 0,
            "_type": scheme,
        }
        # username/password/token
        if parsed.username:
            entry["user"] = parsed.username
        if parsed.password:
            entry["password"] = parsed.password
        # Add query params to params dict
        if parsed.query:
            entry["params"] = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return entry
    except Exception:
        return None

def parse_vmess_or_maybe_json(line):
    """
    Helper: if the line is JSON-like, try to parse it as vmess JSON.
    """
    try:
        txt = line.strip()
        if txt.startswith("{") and "add" in txt:
            return parse_vmess(txt)
    except Exception:
        pass
    return None

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        print(f"[FATAL] sources.txt not found at {SOURCES_FILE}")
        sys.exit(1)
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = []
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            sources.append(line)
    if not sources:
        print(f"[FATAL] sources.txt is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

# ---------------- Load proxies from URLs (robust) ----------------
def load_proxies(url):
    """
    Fetch a source (which may be a clash YAML, or a text list of vmess/ss/ssr/trojan/vless/hysteria lines)
    Returns a list of proxy dicts.
    """
    proxies = []
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text or ""
        text = text.strip()
        # 1) Try YAML (clash) first
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                print(f"[info] {url} detected as YAML (clash) with {len(data['proxies'])} proxies")
                return data["proxies"]
        except Exception:
            pass

        # 2) Some providers base64-encode the entire subscription (which then contains vmess:// or plain lines)
        decoded_whole = safe_b64decode(text)
        if decoded_whole:
            try:
                decoded_text = decoded_whole.decode("utf-8", errors="ignore")
                # prefer decoded text if it looks like a subscription
                if any(scheme in decoded_text for scheme in ("vmess://", "ss://", "ssr://", "trojan://", "vless://", "hysteria://", "anytls://")):
                    text = decoded_text
            except Exception:
                pass

        # 3) split into lines and parse each
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        for ln in lines:
            # skip comments and obviously broken lines
            if ln.startswith("#") or "\ufffd" in ln:
                continue
            p = None
            lower = ln.lower()
            if lower.startswith("vmess://"):
                p = parse_vmess(ln)
            elif lower.startswith("vless://"):
                p = parse_vless(ln)
            elif lower.startswith("ssr://"):
                p = parse_ssr(ln)
            elif lower.startswith("trojan://"):
                p = parse_trojan(ln)
            elif lower.startswith("ss://"):
                p = parse_ss(ln)
            elif any(lower.startswith(s + "://") for s in ("hysteria", "hysteria2", "anytls", "anytls2")):
                p = parse_generic_scheme(ln)
            else:
                # try decode base64-only vmess/payload
                maybe = parse_vmess_or_maybe_json(ln)
                if maybe:
                    p = maybe
                else:
                    # try decode as base64 block containing many lines
                    b = safe_b64decode(ln)
                    if b:
                        try:
                            s = b.decode("utf-8", errors="ignore")
                            # split and re-run parsing for each inner line
                            for sub in s.splitlines():
                                sub = sub.strip()
                                if not sub:
                                    continue
                                # recursion limited — only try known schemes
                                pp = None
                                lowsub = sub.lower()
                                if lowsub.startswith("vmess://"):
                                    pp = parse_vmess(sub)
                                elif lowsub.startswith("vless://"):
                                    pp = parse_vless(sub)
                                elif lowsub.startswith("ssr://"):
                                    pp = parse_ssr(sub)
                                elif lowsub.startswith("ss://"):
                                    pp = parse_ss(sub)
                                elif lowsub.startswith("trojan://"):
                                    pp = parse_trojan(sub)
                                elif any(lowsub.startswith(s + "://") for s in ("hysteria", "hysteria2", "anytls", "anytls2")):
                                    pp = parse_generic_scheme(sub)
                                if pp and pp.get("server") and pp.get("port"):
                                    proxies.append(pp)
                            continue
                        except Exception:
                            pass
                    # fallback: try naive host:port
                    m = re.match(r"^([0-9a-zA-Z\.-]+):([0-9]{1,5})$", ln)
                    if m:
                        p = {"name": ln, "server": m.group(1), "port": int(m.group(2)), "_type": "generic"}
                    else:
                        # attempt generic scheme parse if it looks like URL
                        parsed_try = parse_generic_scheme(ln)
                        if parsed_try and parsed_try.get("server"):
                            p = parsed_try
            if p:
                if p.get("server") and p.get("port"):
                    proxies.append(p)
                else:
                    # invalid parsed object -> skip
                    pass
            else:
                # couldn't parse -> skip
                pass
    except Exception as e:
        print(f"[warn] failed to fetch/parse {url} -> {e}")
    return proxies

# ---------------- Latency filtering (after parsing) ----------------
def filter_by_latency(proxies):
    """
    Given a list of parsed proxies, perform TCP latency checks (concurrent).
    Returns list of proxies which pass latency threshold (or all if LATENCY disabled).
    """
    if not USE_LATENCY:
        print("[latency] LATENCY_FILTER disabled; skipping latency checks")
        return proxies

    print(f"[latency] running latency checks (threshold {LATENCY_THRESHOLD} ms) on {len(proxies)} proxies")
    alive = []
    # run concurrency to speed up
    def check(p):
        host = p.get("server")
        try:
            raw_port = p.get("port", 0)
            if isinstance(raw_port, str) and "/" in raw_port:
                raw_port = raw_port.split("/")[0]
            port = int(raw_port or 443)
        except Exception:
            port = 443
        latency = tcp_latency_ms(host, port)
        p["_latency"] = latency
        return p if latency <= LATENCY_THRESHOLD else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(check, p) for p in proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    alive.append(res)
            except Exception as e:
                # ignore individual errors
                pass
    print(f"[latency] {len(alive)}/{len(proxies)} proxies passed latency filter")
    return alive

# ---------------- Duplicate removal (after latency filtering) ----------------
def dedupe_proxies(proxies):
    """
    Remove duplicates. Keep different UUIDs for vmess/vless etc.
    Duplicate key rules:
    - vmess: ('vmess', server, port, uuid)  -> keep if uuid different
    - vless: ('vless', server, port, uuid)
    - trojan: ('trojan', server, port, password)
    - ssr: ('ssr', server, port, password)
    - ss: ('ss', server, port, method, password)
    - generic / others: ('proto', server, port)
    """
    seen = set()
    out = []
    for p in proxies:
        try:
            server = (p.get("server") or "").lower()
            port = int(p.get("port") or 0)
            ptype = (p.get("_type") or "").lower()
            if ptype == "vmess":
                uid = (p.get("uuid") or "").lower()
                key = ("vmess", server, port, uid)
            elif ptype == "vless":
                uid = (p.get("uuid") or "").lower()
                key = ("vless", server, port, uid)
            elif ptype == "trojan":
                key = ("trojan", server, port, p.get("password", ""))
            elif ptype == "ssr":
                key = ("ssr", server, port, p.get("password", ""))
            elif ptype == "ss":
                key = ("ss", server, port, p.get("method", ""), p.get("password", ""))
            else:
                key = (ptype or "generic", server, port)
        except Exception:
            key = ("generic", str(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    if len(proxies) != len(out):
        print(f"[dedupe] reduced {len(proxies)} -> {len(out)} proxies (duplicates removed)")
    else:
        print(f"[dedupe] no duplicates found ({len(out)} proxies)")
    return out

# ---------------- Assign GeoIP and naming ----------------
def assign_geo_and_name(proxies):
    """
    Resolve host -> ip, lookup geoip, and assign name as '{flag}|{CC}{index}|@SHFX'
    Index increments per country uppercase code.
    """
    country_counter = defaultdict(int)
    corrected = []

    def process(p):
        host = p.get("server")
        try:
            raw_port = p.get("port", "")
            if isinstance(raw_port, str) and "/" in raw_port:
                raw_port = raw_port.split("/")[0]
            port = int(raw_port or 443)
        except Exception:
            port = 443

        ip = resolve_ip(host) or host
        cc_lower, cc_upper = geo_ip(ip)
        flag = country_to_flag(cc_upper)

        country_counter[cc_upper] += 1
        index = country_counter[cc_upper]

        p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
        p["port"] = port
        # keep latency if available (optional) but don't include in name by default
        return p

    # process sequentially to keep deterministic indexing order (country_counter increments in order)
    for p in proxies:
        try:
            cp = process(p)
            corrected.append(cp)
        except Exception:
            pass

    return corrected

# ---------------- Convert proxies to one-line YAML block ----------------
def proxies_to_one_line_yaml(proxies):
    """
    Convert list of proxy dicts into YAML block where each item is a single-line flow mapping:
    - { name: '🇺🇸|US1|@SHFX', type: ss, server: example, port: 1234, ... }
    Returns a string suitable to replace {{PROXIES}} in your template.
    """
    lines = []
    for p in proxies:
        # Build a safe dict to dump (remove keys that are not Clash fields, but keep common ones)
        entry = {}
        # keep 'name' and protocol-specific mapping
        name = p.get("name") or p.get("ps") or p.get("server")
        entry["name"] = name
        # map protocol (use _type heuristic)
        proto = (p.get("_type") or "").lower()
        # map generic types to clash-friendly type names
        if proto in ("vmess",):
            entry["type"] = "vmess"
            # vmess fields
            # Clash expects: server, port, uuid, alterId, cipher, network, tls, ws-path, etc.
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                entry["port"] = int(p.get("port"))
            if p.get("uuid"):
                entry["uuid"] = p.get("uuid")
            if p.get("alterId") is not None:
                entry["alterId"] = p.get("alterId")
            if p.get("cipher"):
                entry["cipher"] = p.get("cipher")
            if p.get("network"):
                entry["network"] = p.get("network")
            # include raw params if present
            if p.get("raw"):
                # avoid dumping huge raw; include useful fields if present
                for k in ("tls", "sni", "path", "host"):
                    if p["raw"].get(k) is not None:
                        entry[k] = p["raw"].get(k)
        elif proto in ("vless",):
            entry["type"] = "vless"
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                entry["port"] = int(p.get("port"))
            if p.get("uuid"):
                entry["uuid"] = p.get("uuid")
            if p.get("params"):
                for k, v in p.get("params").items():
                    entry[k] = v
        elif proto in ("trojan",):
            entry["type"] = "trojan"
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                entry["port"] = int(p.get("port"))
            if p.get("password"):
                entry["password"] = p.get("password")
        elif proto in ("ss", "shadowsocks"):
            entry["type"] = "ss"
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                entry["port"] = int(p.get("port"))
            if p.get("method"):
                entry["cipher"] = p.get("method")
            if p.get("password"):
                entry["password"] = p.get("password")
            # some clients use 'udp' flag
            if p.get("udp") is True or p.get("udp") == "true":
                entry["udp"] = True
        elif proto in ("ssr",):
            entry["type"] = "ssr"
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                entry["port"] = int(p.get("port"))
            if p.get("password"):
                entry["password"] = p.get("password")
            if p.get("method"):
                entry["method"] = p.get("method")
            if p.get("protocol"):
                entry["protocol"] = p.get("protocol")
            if p.get("obfs"):
                entry["obfs"] = p.get("obfs")
        else:
            # generic: try to preserve as much as possible
            entry["type"] = p.get("_type") or "generic"
            if p.get("server"):
                entry["server"] = p.get("server")
            if p.get("port"):
                try:
                    entry["port"] = int(p.get("port"))
                except Exception:
                    entry["port"] = p.get("port")
            # include user/password if present
            if p.get("user"):
                entry["user"] = p.get("user")
            if p.get("password"):
                entry["password"] = p.get("password")
            # merge params
            if p.get("params"):
                for k, v in p["params"].items():
                    entry[k] = v

        # Use yaml.safe_dump for the single mapping in flow style
        dumped = yaml.safe_dump(entry, default_flow_style=True, allow_unicode=True)
        # yaml.safe_dump will produce something like: "{name: '...', type: ss, ...}\n"
        dumped = dumped.strip()
        lines.append(f"- {dumped}")
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

    print(f"[collect] total {len(all_proxies)} proxies parsed")

    # ---------------- Latency filter (after parsing) ----------------
    alive_proxies = filter_by_latency(all_proxies)

    # ---------------- Deduplicate (after latency) ----------------
    unique_proxies = dedupe_proxies(alive_proxies)

    # ---------------- Assign geoip and names ----------------
    corrected_nodes = assign_geo_and_name(unique_proxies)

    print(f"[done] final {len(corrected_nodes)} nodes after latency/dedupe/geoip")

    # ---------------- Load template as text ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert proxies to one-line YAML block ----------------
    proxies_yaml_block = proxies_to_one_line_yaml(corrected_nodes)

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
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

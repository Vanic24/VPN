#!/usr/bin/env python3
# src/bestclash.py
"""
Extended bestclash.py supporting many subscription formats with verbose logging:
- clash/YAML
- vmess (base64 JSON)
- vless (URI)
- trojan (URI)
- ss (shadowsocks)
- ssr (SSR)
- hysteria / hysteria2 (URI-style generic)
- anytls / anytls2 (URI-style generic)
- generic URL-schemes (attempt parse)
- plain "host:port" fallback

Behavior:
- Load sources from SOURCES_FILE (sources.txt)
- Parse all subscriptions (skip invalid lines; log reasons)
- Apply latency filter AFTER parsing (if LATENCY_FILTER=true)
- Deduplicate (keeping different UUIDs)
- GeoIP (ipinfo.io) and name assignment {flag}|{CC}{index}|@SHFX
- Output proxies in one-line YAML flow entries and proxy names list
- Merge into ClashTemplate.ini placeholders {{PROXIES}} and {{PROXY_NAMES}}
"""

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

# ---------------- Inputs (env) ----------------
use_latency_env = os.environ.get("LATENCY_FILTER", "false").lower()
USE_LATENCY = use_latency_env == "true"

try:
    LATENCY_THRESHOLD = int(os.environ.get("LATENCY_THRESHOLD", "100"))
except ValueError:
    LATENCY_THRESHOLD = 100

# ---------------- Helpers ----------------
def log(msg):
    print(msg, flush=True)

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def tcp_latency_ms(host, port, timeout=2.0):
    try:
        import time
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return 9999

def geo_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            cc = data.get("country")
            if cc:
                return cc.lower(), cc.upper()
    except Exception:
        pass
    return "unknown", "UN"

def country_to_flag(cc):
    if not cc or len(cc) != 2:
        return "🏳️"
    return chr(0x1F1E6 + (ord(cc[0].upper()) - 65)) + chr(0x1F1E6 + (ord(cc[1].upper()) - 65))

# Robust base64 decoder for many provider variations
def safe_b64decode(s):
    """Robust base64 decode; returns bytes or None"""
    if s is None:
        return None
    if isinstance(s, bytes):
        return s
    s = s.strip()
    if not s:
        return None
    # strip URI scheme (if mistakenly passed)
    s = re.sub(r'^[a-zA-Z0-9+\-_/]+=*$', lambda m: m.group(0), s)
    # Replace URL-safe characters and remove whitespace/newlines
    s = s.replace('-', '+').replace('_', '/')
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

# ---------------- Protocol parsers ----------------
# Each parser returns a dict with at least: server, port, _type
# They may also include protocol-specific keys like uuid, password, method, cipher, params, raw, name

def parse_vmess(line):
    """vmess://<base64_json> or raw JSON text"""
    try:
        payload = line
        if line.startswith("vmess://"):
            payload = line[8:]
        b = safe_b64decode(payload)
        if b:
            try:
                s = b.decode("utf-8", errors="strict")
            except Exception:
                s = b.decode("utf-8", errors="ignore")
            # JSON might be standard or single object or list
            try:
                data = json.loads(s)
            except Exception:
                # sometimes it is newline-separated vmess lines; skip here
                return None
        else:
            # maybe raw JSON
            if line.strip().startswith("{"):
                try:
                    data = json.loads(line)
                except Exception:
                    return None
            else:
                return None
        server = data.get("add") or data.get("server")
        port = int(data.get("port") or data.get("p") or 443)
        return {
            "_type": "vmess",
            "server": server,
            "port": port,
            "uuid": data.get("id") or data.get("uuid") or "",
            "alterId": data.get("aid") or data.get("alterId"),
            "cipher": data.get("scy") or data.get("cipher"),
            "network": data.get("net"),
            "tls": data.get("tls"),
            "raw": data,
            "name": data.get("ps") or data.get("name") or server
        }
    except Exception:
        return None

def parse_vless(line):
    """vless://uuid@host:port?params#name"""
    try:
        if not line.startswith("vless://"):
            return None
        parsed = urlparse(line)
        if parsed.scheme != "vless":
            return None
        return {
            "_type": "vless",
            "server": parsed.hostname,
            "port": int(parsed.port or 443),
            "uuid": parsed.username or "",
            "params": {k: v[0] for k, v in parse_qs(parsed.query).items()},
            "name": unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        }
    except Exception:
        return None

def parse_trojan(line):
    """trojan://password@host:port#name"""
    try:
        parsed = urlparse(line)
        if parsed.scheme != "trojan":
            return None
        return {
            "_type": "trojan",
            "server": parsed.hostname,
            "port": int(parsed.port or 443),
            "password": parsed.username or "",
            "params": {k: v[0] for k, v in parse_qs(parsed.query).items()},
            "name": unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        }
    except Exception:
        # fallback manual parse
        try:
            s = line[9:]
            if "@" not in s:
                return None
            pwd, rest = s.split("@", 1)
            hostport = rest.split("#", 1)[0]
            if ":" in hostport:
                host, port = hostport.split(":", 1)
            else:
                host, port = hostport, 443
            return {"_type": "trojan", "server": host, "port": int(port), "password": pwd, "name": host}
        except Exception:
            return None

def parse_ss(line):
    """Shadowsocks ss:// URI in common forms"""
    try:
        content = line
        if line.startswith("ss://"):
            content = line[5:]
        name = None
        if "#" in content:
            content, frag = content.split("#", 1)
            name = unquote(frag)
        # If left side contains '@', credentials exist
        if "@" in content:
            left, right = content.rsplit("@", 1)
            creds = left
            # creds might be base64
            if ":" not in creds:
                dec = safe_b64decode(creds)
                if dec:
                    creds = dec.decode("utf-8", errors="ignore")
            if ":" not in creds:
                return None
            method, password = creds.split(":", 1)
            hostport = right.split("/", 1)[0]
            if ":" in hostport:
                server, port = hostport.split(":", 1)
            else:
                server, port = hostport, 8388
            return {
                "_type": "ss",
                "server": server,
                "port": int(port),
                "method": method,
                "password": password,
                "name": name or server
            }
        else:
            # content could be base64(method:password@host:port)
            dec = safe_b64decode(content)
            if not dec:
                return None
            s = dec.decode("utf-8", errors="ignore")
            if "@" not in s:
                return None
            creds, hostport = s.split("@", 1)
            method, password = creds.split(":", 1)
            hostport = hostport.split("/", 1)[0]
            if ":" in hostport:
                server, port = hostport.split(":", 1)
            else:
                server, port = hostport, 8388
            return {
                "_type": "ss",
                "server": server,
                "port": int(port),
                "method": method,
                "password": password,
                "name": name or server
            }
    except Exception:
        return None

def parse_ssr(line):
    """SSR: ssr://<base64>"""
    try:
        payload = line
        if line.startswith("ssr://"):
            payload = line[6:]
        b = safe_b64decode(payload)
        if not b:
            return None
        s = b.decode("utf-8", errors="ignore")
        main, _, params = s.partition("/?")
        parts = main.split(":")
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, pwd_b64 = parts[:6]
        pwd_bytes = safe_b64decode(pwd_b64) or b""
        try:
            passwd = pwd_bytes.decode("utf-8", errors="ignore")
        except Exception:
            passwd = ""
        p = {
            "_type": "ssr",
            "server": server,
            "port": int(port),
            "password": passwd,
            "protocol": protocol,
            "method": method,
            "obfs": obfs,
            "name": server
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

def parse_generic_scheme(line):
    """
    Generic parser for hysteria/anytls/hysteria2/anytls2/tuic/other URL-like schemes.
    We will capture server, port, user/password/token, params, fragment as name.
    """
    try:
        parsed = urlparse(line)
        if not parsed.scheme or not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        name = unquote(parsed.fragment) if parsed.fragment else parsed.netloc
        entry = {
            "_type": scheme,
            "server": parsed.hostname,
            "port": int(parsed.port or 0),
            "name": name or parsed.hostname
        }
        if parsed.username:
            entry["user"] = parsed.username
        if parsed.password:
            entry["password"] = parsed.password
        if parsed.query:
            entry["params"] = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        # For hysteria/anytls we may have token or auth info in params; keep them
        return entry
    except Exception:
        return None

def parse_vmess_or_json(line):
    """Try parse if line is raw JSON or vmess base64 without scheme"""
    try:
        s = line.strip()
        # If it looks like JSON
        if s.startswith("{") and "add" in s:
            try:
                data = json.loads(s)
                server = data.get("add") or data.get("server")
                port = int(data.get("port") or data.get("p") or 443)
                return {
                    "_type": "vmess",
                    "server": server,
                    "port": port,
                    "uuid": data.get("id") or data.get("uuid") or "",
                    "alterId": data.get("aid") or data.get("alterId"),
                    "cipher": data.get("scy") or data.get("cipher"),
                    "network": data.get("net"),
                    "raw": data,
                    "name": data.get("ps") or data.get("name") or server
                }
            except Exception:
                return None
        return None
    except Exception:
        return None

# ---------------- Load sources ----------------
def load_sources():
    if not os.path.exists(SOURCES_FILE):
        log(f"[FATAL] sources.txt not found at {SOURCES_FILE}")
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
        log(f"[FATAL] sources.txt is empty. Please check the secret or file content.")
        sys.exit(1)
    return sources

# ---------------- Parse subscription content at a URL ----------------
def load_proxies(url):
    """
    Given a URL (or local file path or raw text), attempt to fetch and parse:
    - clash YAML 'proxies:' (preferred)
    - plain text lines containing vmess://, vless://, ss://, ssr://, trojan://, hysteria://, anytls://, etc.
    - base64-encoded whole subscription (decode then parse)
    - fallback: try to parse single-line base64 vmess/json
    Returns (parsed_proxies_list, stats) where stats includes counts and skipped lines details.
    """
    parsed_proxies = []
    stats = {
        "total_lines": 0,
        "parsed": 0,
        "skipped_lines": 0,
        "skipped_details": []  # list of (line_preview, reason)
    }
    try:
        # Fetch
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text or ""
        text = text.strip()
    except Exception as e:
        stats["skipped_details"].append(("[fetch-error]", f"failed to fetch URL -> {e}"))
        log(f"[warn] failed to fetch {url} -> {e}")
        return parsed_proxies, stats

    # 1) Try YAML (Clash) first
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            log(f"[info] {url} detected as YAML (clash) with {len(data['proxies'])} proxies")
            # Normalize entries by ensuring _type exists (try to infer from entry keys)
            for ent in data["proxies"]:
                if not isinstance(ent, dict):
                    continue
                ent_copy = dict(ent)
                # try infer type
                if "uuid" in ent_copy or ent_copy.get("type") == "vmess":
                    ent_copy["_type"] = ent_copy.get("type") or "vmess"
                elif ent_copy.get("type") == "vless":
                    ent_copy["_type"] = "vless"
                elif ent_copy.get("type") == "trojan":
                    ent_copy["_type"] = "trojan"
                elif ent_copy.get("type") in ("ss", "shadowsocks"):
                    ent_copy["_type"] = "ss"
                elif ent_copy.get("type") == "ssr":
                    ent_copy["_type"] = "ssr"
                else:
                    ent_copy["_type"] = ent_copy.get("type") or "generic"
                # ensure server & port exist
                if ent_copy.get("server") and ent_copy.get("port"):
                    parsed_proxies.append(ent_copy)
                    stats["parsed"] += 1
                else:
                    stats["skipped_lines"] += 1
                    stats["skipped_details"].append((str(ent_copy)[:120], "missing server/port in YAML proxy"))
            stats["total_lines"] = len(data.get("proxies", []))
            return parsed_proxies, stats
    except Exception:
        # not YAML or invalid YAML; continue
        pass

    # 2) If whole text looks base64, try decode entire body (many providers encode full subscription)
    decoded_whole = safe_b64decode(text)
    if decoded_whole:
        try:
            decoded_text = decoded_whole.decode("utf-8", errors="ignore")
            # prefer decoded_text if it contains known schemes
            if any(scheme in decoded_text for scheme in ("vmess://", "ss://", "ssr://", "trojan://", "vless://", "hysteria://", "anytls://")):
                text = decoded_text
                log(f"[info] {url} base64-decoded as whole subscription (looks like mixed links)")
        except Exception:
            pass

    # 3) Split into lines and parse each
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    stats["total_lines"] = len(lines)
    for i, ln in enumerate(lines, start=1):
        # skip comments/invalid replacement characters
        if ln.startswith("#"):
            stats["skipped_lines"] += 1
            stats["skipped_details"].append((ln[:120], "comment"))
            continue
        if "\ufffd" in ln:
            stats["skipped_lines"] += 1
            stats["skipped_details"].append((ln[:120], "invalid unicode (replacement char)"))
            continue
        p = None
        reason = None
        l_lower = ln.lower()
        try:
            if l_lower.startswith("vmess://"):
                p = parse_vmess(ln)
                reason = "vmess"
            elif l_lower.startswith("vless://"):
                p = parse_vless(ln)
                reason = "vless"
            elif l_lower.startswith("trojan://"):
                p = parse_trojan(ln)
                reason = "trojan"
            elif l_lower.startswith("ssr://"):
                p = parse_ssr(ln)
                reason = "ssr"
            elif l_lower.startswith("ss://"):
                p = parse_ss(ln)
                reason = "ss"
            elif any(l_lower.startswith(s + "://") for s in ("hysteria", "hysteria2", "anytls", "anytls2", "tuic")):
                p = parse_generic_scheme(ln)
                reason = "generic-scheme"
            else:
                # try if full line is base64-encoded blob (vmess/ss/ssr inside)
                b = safe_b64decode(ln)
                if b:
                    try:
                        inner = b.decode("utf-8", errors="ignore")
                        # if inner contains multiple lines, parse them recursively
                        if "\n" in inner:
                            for sub in inner.splitlines():
                                sub = sub.strip()
                                if not sub:
                                    continue
                                sub_parsed, sub_stats = load_proxies_line(sub)
                                if sub_parsed:
                                    parsed_proxies.append(sub_parsed)
                                    stats["parsed"] += 1
                                else:
                                    stats["skipped_lines"] += 1
                                    stats["skipped_details"].append((sub[:120], "inner line decode but couldn't parse"))
                            continue
                        # otherwise try to interpret inner as vmess JSON or scheme line
                        # attempt vmess json
                        maybe = parse_vmess_or_json(inner) or parse_vless(inner) or parse_trojan(inner) or parse_ss(inner) or parse_ssr(inner) or parse_generic_scheme(inner)
                        if maybe:
                            p = maybe
                            reason = "inner-base64"
                    except Exception:
                        p = None
                else:
                    # fallback: try naive host:port like "1.2.3.4:443"
                    m = re.match(r"^([0-9a-zA-Z\.-]+):([0-9]{1,5})$", ln)
                    if m:
                        p = {"_type": "generic", "server": m.group(1), "port": int(m.group(2)), "name": ln}
                        reason = "host:port"
                    else:
                        # last attempt: treat as URI with scheme not explicit in our list
                        gen = parse_generic_scheme(ln)
                        if gen:
                            p = gen
                            reason = f"generic-scheme-{gen.get('_type')}"
        except Exception as e:
            p = None
            stats["skipped_lines"] += 1
            stats["skipped_details"].append((ln[:120], f"parse exception -> {e}"))
            log(f"[parse-exc] source={url} line#{i} reason=exception: {e}")
            continue

        if p:
            # verify server & port exist for usable entries (some generic schemes may lack port; keep but warn)
            if not p.get("server"):
                stats["skipped_lines"] += 1
                stats["skipped_details"].append((ln[:120], f"parsed but missing server (type={p.get('_type')})"))
                log(f"[skip] source={url} line#{i} reason=missing server")
                continue
            if not p.get("port") or int(p.get("port") or 0) == 0:
                # keep generic entries with port 0 (some schemes specify port in params) but warn and skip if impossible
                # attempt to extract port from params if present
                if isinstance(p.get("params"), dict):
                    port_candidates = []
                    for k in ("port", "p"):
                        v = p["params"].get(k)
                        if v:
                            try:
                                port_candidates.append(int(v))
                            except Exception:
                                pass
                    if port_candidates:
                        p["port"] = port_candidates[0]
                    else:
                        stats["skipped_lines"] += 1
                        stats["skipped_details"].append((ln[:120], f"parsed but missing port (type={p.get('_type')})"))
                        log(f"[skip] source={url} line#{i} reason=missing port (type={p.get('_type')})")
                        continue
                else:
                    stats["skipped_lines"] += 1
                    stats["skipped_details"].append((ln[:120], f"parsed but missing port (type={p.get('_type')})"))
                    log(f"[skip] source={url} line#{i} reason=missing port (type={p.get('_type')})")
                    continue

            parsed_proxies.append(p)
            stats["parsed"] += 1
            log(f"[parse] source={url} line#{i} parsed type={p.get('_type')} server={p.get('server')} port={p.get('port')}")
        else:
            stats["skipped_lines"] += 1
            stats["skipped_details"].append((ln[:120], "unrecognized/invalid format"))
            log(f"[skip] source={url} line#{i} skipped (unrecognized/invalid)")

    return parsed_proxies, stats

# helper used during recursive inner-line parsing
def load_proxies_line(line):
    """
    Try to parse a single line (vmess/json/vless/ss/trojan/ssr/etc.)
    Returns (parsed_dict_or_None, reason_str)
    """
    try:
        ln = line.strip()
        if not ln:
            return None, "empty"
        l_lower = ln.lower()
        if l_lower.startswith("vmess://"):
            p = parse_vmess(ln)
            return (p, "vmess") if p else (None, "vmess-failed")
        if l_lower.startswith("vless://"):
            p = parse_vless(ln)
            return (p, "vless") if p else (None, "vless-failed")
        if l_lower.startswith("trojan://"):
            p = parse_trojan(ln)
            return (p, "trojan") if p else (None, "trojan-failed")
        if l_lower.startswith("ssr://"):
            p = parse_ssr(ln)
            return (p, "ssr") if p else (None, "ssr-failed")
        if l_lower.startswith("ss://"):
            p = parse_ss(ln)
            return (p, "ss") if p else (None, "ss-failed")
        gen = parse_generic_scheme(ln)
        return (gen, f"generic-{gen.get('_type')}") if gen else (None, "unknown")
    except Exception as e:
        return None, f"exception-{e}"

# ---------------- Latency filtering (after parsing) ----------------
def filter_by_latency(proxies):
    if not USE_LATENCY:
        log("[latency] LATENCY_FILTER disabled; skipping latency checks")
        return proxies

    log(f"[latency] checking TCP connect latency on {len(proxies)} proxies with threshold {LATENCY_THRESHOLD} ms")
    alive = []

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
                else:
                    # we could log which node failed, but that may be verbose. still collect.
                    pass
            except Exception:
                pass

    log(f"[latency] {len(alive)}/{len(proxies)} proxies passed latency filter")
    return alive

# ---------------- Deduplication (after latency) ----------------
def dedupe_proxies(proxies):
    """
    Keep different UUIDs for vmess/vless etc.
    Key rules:
    - vmess: ('vmess', server, port, uuid)
    - vless: ('vless', server, port, uuid)
    - trojan: ('trojan', server, port, password)
    - ssr: ('ssr', server, port, password)
    - ss: ('ss', server, port, method, password)
    - generic/other: (type, server, port)
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
        log(f"[dedupe] reduced {len(proxies)} -> {len(out)} proxies (duplicates removed)")
    else:
        log(f"[dedupe] no duplicates found ({len(out)} proxies)")
    return out

# ---------------- Assign GeoIP and name ----------------
def assign_geo_and_name(proxies):
    """
    Deterministic ordering: process proxies in input order and assign index per country code.
    """
    country_counter = defaultdict(int)
    corrected = []
    for p in proxies:
        try:
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
            corrected.append(p)
        except Exception:
            # skip entries that fail here
            pass
    return corrected

        # Convert mapping to YAML flow mapping (single line)
        dumped = yaml.safe_dump(entry, default_flow_style=True, allow_unicode=True).strip()
        lines.append(f"- {dumped}")
    return "\n".join(lines)

# ---------------- Main ----------------
def main():
    sources = load_sources()
    log(f"[start] loaded {len(sources)} sources from {SOURCES_FILE}")

    all_parsed = []
    aggregate_stats = {"sources": []}

    # parse each source
    for url in sources:
        parsed_list, stats = load_proxies(url)
        log(f"[source] {url} -> lines={stats['total_lines']} parsed={stats['parsed']} skipped={stats['skipped_lines']}")
        # print skipped details if any (limited)
        if stats["skipped_details"]:
            for i, (preview, reason) in enumerate(stats["skipped_details"]):
                if i < 10:  # limit output to avoid huge logs in GH Actions
                    log(f"  [skip-detail] {preview[:120]} -> {reason}")
                elif i == 10:
                    log("  ... (more skipped lines omitted)")
                    break
        aggregate_stats["sources"].append({"url": url, "stats": stats})
        all_parsed.extend(parsed_list)

    log(f"[collect] total parsed entries before latency dedupe: {len(all_parsed)}")

    # latency filtering (after parsing)
    alive = filter_by_latency(all_parsed)

    # deduplicate
    unique = dedupe_proxies(alive)

    # assign geoip & names
    corrected = assign_geo_and_name(unique)

    log(f"[done] final {len(corrected)} nodes after latency/dedupe/geoip")

    # load template
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        log(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # convert proxies to one-line yaml block
    proxies_yaml_block = proxies_to_one_line_yaml(corrected)

    # build proxy names block for groups
    proxy_names_block = "\n".join([f"      - {p['name']}" for p in corrected])

    # replace placeholders
    output_text = template_text.replace("{{PROXIES}}", proxies_yaml_block)
    output_text = output_text.replace("{{PROXY_NAMES}}", proxy_names_block)

    # write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_text)

    log(f"[done] wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("[FATAL ERROR] " + str(e))
        traceback.print_exc()
        sys.exit(1)

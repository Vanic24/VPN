#!/usr/bin/env python3
# v1: Clash-YAML aggregator + latency tester + renamer (IP+latency)
# Future v2: add base64 URI subscription support

import os, re, time, socket, base64, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(ROOT, ".."))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")

# ---------- Helpers ----------

def load_sources():
    urls = []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                urls.append(u)
    return urls

def fetch(url, timeout=20):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[fetch] FAIL {url} -> {e}")
        return None

def is_probably_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 24:  # too short to be a whole subscription
        return False
    if len(s) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", s) is not None

def try_decode_base64_to_text(s: str):
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None

def extract_proxies_from_yaml_text(text: str):
    """
    Accepts Clash-style YAML (normal config or provider).
    Returns list of proxy dicts if found, else [].
    """
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []

    proxies = []
    if isinstance(data, dict):
        # provider format: {'proxies': [...]}
        if "proxies" in data and isinstance(data["proxies"], list):
            proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])

        # sometimes nested under 'Proxy'/'proxies' etc. (rare)
        for key in ("Proxy", "proxy", "ProxyList"):
            if key in data and isinstance(data[key], list):
                proxies.extend([p for p in data[key] if isinstance(p, dict)])

    return proxies

def normalize_type(t: str):
    return (t or "").strip().lower()

def proxy_fingerprint(p: dict) -> str:
    """
    Build a stable key to deduplicate proxies across sources.
    Use server/port/type + key credential.
    """
    t = normalize_type(p.get("type") or p.get("Type"))
    host = str(p.get("server") or p.get("Server") or "").strip()
    port = str(p.get("port") or p.get("Port") or "").strip()

    # Identify credential-ish field
    cred = ""
    if t in ("vmess", "vless"):
        cred = str(p.get("uuid") or p.get("id") or "")
    elif t == "trojan":
        cred = str(p.get("password") or "")
    elif t in ("ss", "shadowsocks"):
        cred = f"{p.get('cipher','')}:{p.get('password','')}"
    else:
        # fallback: include all keys to reduce accidental collisions
        cred = yaml.safe_dump(p, allow_unicode=True)

    raw = f"{t}|{host}|{port}|{cred}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def resolve_ip(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def tcp_latency_ms(host: str, port: int, timeout=2.0) -> float:
    """
    Measure connect() time to host:port. Returns ms (float), or 9999.0 on failure.
    """
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            pass
        return round((time.time() - start) * 1000.0, 2)
    except Exception:
        return 9999.0

def unique_name(base: str, used: set) -> str:
    name = base
    i = 2
    while name in used:
        name = f"{base} #{i}"
        i += 1
    used.add(name)
    return name

# ---------- Pipeline ----------

def collect_all_proxies(urls):
    """
    Fetch each URL, attempt to parse Clash YAML. If the content appears base64,
    try to base64-decode then parse again. (v1 only supports Clash YAML.)
    """
    proxies = []

    for url in urls:
        text = fetch(url)
        if not text:
            continue

        # Try direct YAML
        parsed = extract_proxies_from_yaml_text(text)
        if parsed:
            print(f"[parse] {url} -> {len(parsed)} proxies (yaml)")
            proxies.extend(parsed)
            continue

        # Try base64 -> YAML
        if is_probably_base64(text):
            decoded = try_decode_base64_to_text(text)
            if decoded:
                parsed2 = extract_proxies_from_yaml_text(decoded)
                if parsed2:
                    print(f"[parse] {url} -> {len(parsed2)} proxies (base64->yaml)")
                    proxies.extend(parsed2)
                    continue

        print(f"[parse] {url} -> unsupported format (v1), skipped")

    return proxies

def dedupe_proxies(proxies):
    seen = set()
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if "server" not in p or "port" not in p:
            continue
        fp = proxy_fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(p)
    return out

def measure_and_rename(proxies, keep_top=50):
    """
    1) Resolve IP, 2) latency test, 3) sort by latency, 4) rename.
    """
    # Resolve + latency (parallel)
def job(p):
    host = str(p.get("server"))
    raw_port = str(p.get("port", ""))
    if "/" in raw_port:  # strip plugin or extra params
        raw_port = raw_port.split("/")[0]
    try:
        port = int(raw_port)
    except ValueError:
        port = 443  # fallback to default
    ip = resolve_ip(host) or host
    lat = tcp_latency_ms(host, port)
    return (p, ip, lat)


    results = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = [ex.submit(job, p) for p in proxies]
        for f in as_completed(futs):
            results.append(f.result())

    # Sort, keep fastest N
    results.sort(key=lambda x: x[2])
    results = results[:keep_top]

    used_names = set()
    out = []
    for p, ip, lat in results:
        t = normalize_type(p.get("type") or p.get("Type") or "")
        base_name = f"{ip}:{p.get('port')} | {t or 'proxy'} | {lat}ms"
        p["name"] = unique_name(base_name, used_names)
        p["udp"] = True  # common default
        p.pop("latency", None)  # ensure clean
        out.append(p)

    return out

def build_output_yaml(proxies):
    """
    Create a minimal-but-usable Clash config with groups and rules.
    """
    names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names
            },
            {
                "name": "Manual",
                "type": "select",
                "proxies": ["Auto"] + names
            }
        ],
        "rules": [
            "MATCH,Auto"
        ]
    }
    return config

def main():
    urls = load_sources()
    print(f"[start] sources: {len(urls)}")
    proxies = collect_all_proxies(urls)
    print(f"[collect] total proxies: {len(proxies)}")

    proxies = dedupe_proxies(proxies)
    print(f"[dedupe] unique proxies: {len(proxies)}")

    if not proxies:
        print("[warn] No proxies collected. Keeping previous proxies.yaml if exists.")
        return

    fastest = measure_and_rename(proxies, keep_top=60)
    print(f"[select] fastest kept: {len(fastest)}")

    cfg = build_output_yaml(fastest)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)

    print(f"[done] wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

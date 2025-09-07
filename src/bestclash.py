import sys
import os
import yaml
import requests
import socket
import concurrent.futures
import time
import traceback

# ---------------- Paths ----------------
ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(ROOT, ".."))
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
OUTPUT_FILE = os.path.join(REPO_ROOT, "proxies.yaml")

# ---------------- DNS / Latency ----------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def tcp_latency_ms(host, port, timeout=3):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return 9999  # unreachable

# ---------------- Job ----------------
def job(p):
    host = str(p.get("server"))

    # Safe port parsing
    raw_port = str(p.get("port", ""))
    if "/" in raw_port:  # strip plugin/extra params
        raw_port = raw_port.split("/")[0]

    try:
        port = int(raw_port)
    except ValueError:
        port = 443  # fallback default

    ip = resolve_ip(host) or host
    lat = tcp_latency_ms(host, port)
    return (p, ip, lat)

# ---------------- Fetch & Parse ----------------
def load_sources():
    urls = []
    if not os.path.isfile(SOURCES_FILE):
        print(f"[warn] sources.txt not found at {SOURCES_FILE}")
        return urls
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                urls.append(u)
    return urls

def fetch_yaml(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[fetch] FAIL {url} -> {e}")
        return None

def parse_yaml(content, url=""):
    try:
        data = yaml.safe_load(content)
        if not data:
            print(f"[parse] {url} -> empty")
            return []
        if "proxies" in data:
            proxies = data["proxies"]
            print(f"[parse] {url} -> {len(proxies)} proxies (yaml)")
            return proxies
        else:
            print(f"[parse] {url} -> unsupported format, skipped")
            return []
    except Exception as e:
        print(f"[parse] {url} -> FAIL {e}")
        return []

# ---------------- Main ----------------
def main():
    urls = load_sources()
    print(f"[start] loaded {len(urls)} sources")

    all_proxies = []
    for url in urls:
        text = fetch_yaml(url)
        if text:
            all_proxies.extend(parse_yaml(text, url))

    print(f"[collect] total proxies: {len(all_proxies)}")

    # Deduplicate by server:port
    seen = set()
    unique = []
    for p in all_proxies:
        sid = f"{p.get('server')}:{p.get('port')}"
        if sid not in seen:
            seen.add(sid)
            unique.append(p)

    print(f"[dedupe] unique proxies: {len(unique)}")

    # Test latency in parallel
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(job, p) for p in unique]
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                print("[job error]", e)

    # Filter by latency <= 200ms
    filtered = [r for r in results if r[2] <= 200]
    filtered.sort(key=lambda x: x[2])  # sort by latency

    print(f"[filter] {len(filtered)} proxies ≤ 200ms latency")

    # Build YAML
    out = {"proxies": [r[0] for r in filtered]}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True)

    print(f"[done] wrote {len(filtered)} proxies to {OUTPUT_FILE}")

# ---------------- Entry ----------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

import sys
import yaml
import requests
import socket
import concurrent.futures
import time
import traceback

# --- DNS resolution ---
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# --- TCP latency test ---
def tcp_latency_ms(host, port, timeout=3):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return 9999  # unreachable

# --- Job for each proxy ---
def job(p):
    host = str(p.get("server"))

    # --- Safe port parsing ---
    raw_port = str(p.get("port", ""))
    if "/" in raw_port:  # strip plugin or extra params
        raw_port = raw_port.split("/")[0]

    try:
        port = int(raw_port)
    except ValueError:
        port = 443  # fallback default

    ip = resolve_ip(host) or host
    lat = tcp_latency_ms(host, port)
    return (p, ip, lat)

# --- Fetch a YAML URL ---
def fetch_yaml(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[fetch] FAIL {url} -> {e}")
        return None

# --- Parse proxies from YAML ---
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

# --- Main runner ---
def main():
    urls = [
        "https://cdn.jsdelivr.net/gh/vxiaov/free_proxies@main/clash/clash.provider.yaml",
        "https://freenode.openrunner.net/uploads/20240807-clash.yaml",
        "https://raw.githubusercontent.com/Misaka-blog/chromego_merge/main/sub/merged_proxies_new.yaml",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml",
        "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/Clash.yaml",
        "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml",
        "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
        "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
        "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/clash.yml",
        "https://raw.githubusercontent.com/lagzian/SS-Collector/main/mix_clash.yaml",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
        "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
        "https://raw.githubusercontent.com/ronghuaxueleng/get_v2/main/pub/combine.yaml",
        "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
        "https://raw.githubusercontent.com/yaney01/Yaney01/main/temporary",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/mix",
        "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
        "https://tt.vg/freeclash"
    ]

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

    # Sort by latency
    results.sort(key=lambda x: x[2])

    # Build YAML
    out = {"proxies": [r[0] for r in results]}
    with open("proxies.yaml", "w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True)

    print(f"[done] wrote {len(results)} proxies to output.yaml")

# --- Entry point with error logging ---
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL ERROR]", str(e))
        traceback.print_exc()
        sys.exit(1)

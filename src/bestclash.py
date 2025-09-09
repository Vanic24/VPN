import os
import sys
import yaml
import requests
import socket
import subprocess
import concurrent.futures
import traceback
from collections import defaultdict
import time

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

# ---------------- Mihomo Binary ----------------
MIHOMO_BIN = os.path.join(REPO_ROOT, "mihomo", "mihomo")  # updated path

# ---------------- Helpers ----------------
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

# ---------------- Load proxies from URLs ----------------
def load_proxies(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = yaml.safe_load(r.text)
        if "proxies" in data:
            return data["proxies"]
    except Exception as e:
        print(f"[warn] failed to fetch {url} -> {e}")
    return []

# ---------------- Get actual outbound IP using Mihomo SOCKS ----------------
def get_outbound_ip(proxy_config):
    server = proxy_config.get("server")
    port = str(proxy_config.get("port", 443))
    if "/" in port:
        port = port.split("/")[0]

    try:
        port = int(port)
    except ValueError:
        port = 443

    # temporary config file (minimal)
    temp_config_path = os.path.join(REPO_ROOT, "mihomo_temp.yaml")
    with open(temp_config_path, "w", encoding="utf-8") as f:
        yaml.dump({
            "server": server,
            "port": port,
            "type": proxy_config.get("type"),
            "password": proxy_config.get("password", "")
        }, f)

    # select a free local SOCKS port
    local_socks_port = 1080  # you can randomize if needed

    try:
        # start Mihomo with local SOCKS port
        process = subprocess.Popen(
            [MIHOMO_BIN, "run", "-c", temp_config_path, "-L", f"127.0.0.1:{local_socks_port}:socks"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(3)  # wait for proxy to be ready

        # request actual outbound IP through the local SOCKS proxy
        proxies = {
            "http": f"socks5://127.0.0.1:{local_socks_port}",
            "https": f"socks5://127.0.0.1:{local_socks_port}"
        }
        r = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=5)
        outlet_ip = r.json().get("ip")

        process.kill()
        return outlet_ip
    except Exception as e:
        print(f"[warn] Mihomo failed for {server}:{port} -> {e}")
        try:
            process.kill()
        except:
            pass
        return None
    finally:
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)

# ---------------- Correct node ----------------
def correct_node(p, country_counter):
    host = str(p.get("server"))
    raw_port = str(p.get("port", ""))
    if "/" in raw_port:
        raw_port = raw_port.split("/")[0]
    try:
        port = int(raw_port)
    except ValueError:
        port = 443

    # latency check
    latency = tcp_latency_ms(host, port)
    if USE_LATENCY and latency > LATENCY_THRESHOLD:
        return None

    # get actual outbound IP via Mihomo SOCKS
    outlet_ip = get_outbound_ip(p)
    if not outlet_ip:
        return None

    cc_lower, cc_upper = geo_ip(outlet_ip)
    flag = country_to_flag(cc_upper)

    country_counter[cc_upper] += 1
    index = country_counter[cc_upper]

    # rename node
    p["name"] = f"{flag}|{cc_upper}{index}|@SHFX"
    p["port"] = port
    p["outlet_ip"] = outlet_ip
    return p

# ---------------- Main ----------------
def main():
    sources = load_sources()
    print(f"[start] loaded {len(sources)} sources from sources.txt")

    all_proxies = []
    for url in sources:
        proxies = load_proxies(url)
        print(f"[source] {url} -> {len(proxies)} proxies")
        all_proxies.extend(proxies)

    print(f"[collect] total {len(all_proxies)} proxies")

    country_counter = defaultdict(int)
    corrected_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(correct_node, p, country_counter) for p in all_proxies]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if res:
                    corrected_nodes.append(res)
            except Exception as e:
                print("[job error]", e)

    print(f"[done] final {len(corrected_nodes)} nodes after correction/filtering")

    # ---------------- Load template as text ----------------
    try:
        r = requests.get(TEMPLATE_URL, timeout=15)
        r.raise_for_status()
        template_text = r.text
    except Exception as e:
        print(f"[FATAL] failed to fetch template -> {e}")
        sys.exit(1)

    # ---------------- Convert proxies to YAML block ----------------
    proxies_yaml_block = yaml.dump(corrected_nodes, allow_unicode=True, default_flow_style=False)

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

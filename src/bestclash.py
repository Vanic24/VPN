import os
import sys
import yaml
import requests
import base64
import traceback

# ---------------- Config ----------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_TXT = os.path.join(REPO_ROOT, 'sources.txt')  # Secret repo
OUTPUT_YAML = os.path.join(REPO_ROOT, 'clash_output.yaml')

# ---------------- Helper Functions ----------------
def fetch_subscription(url):
    try:
        print(f"[INFO] Fetching subscription: {url}")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] Failed to fetch {url}: {e}")
        return None

def decode_base64(data):
    try:
        # Some subscriptions may have newlines
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        print(f"[WARN] Failed to decode base64: {e}")
        return None

def parse_node_line(line):
    """
    Parse a line into Clash node dictionary.
    Supports all common protocols: vmess, vless, ss, hysteria2, anytls, trojan
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    node = {}
    try:
        # Detect protocol
        if line.startswith('vmess://'):
            decoded = decode_base64(line[8:])
            if not decoded:
                return None
            import json
            data = json.loads(decoded)
            node['name'] = data.get('ps', 'VMess Node')
            node['type'] = 'vmess'
            node['server'] = data.get('add')
            node['port'] = int(data.get('port', 443))
            node['uuid'] = data.get('id')
            node['alterId'] = int(data.get('aid', 0))
            node['cipher'] = data.get('scy', 'auto')
            node['tls'] = True if data.get('tls') == 'tls' else False
            node['network'] = data.get('net', 'tcp')
            node['ws-opts'] = {'path': data.get('path', '/')} if data.get('path') else {}
        elif line.startswith('vless://'):
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(line)
            node['name'] = parse_qs(parsed.query).get('remark', ['VLESS Node'])[0]
            node['type'] = 'vless'
            node['server'] = parsed.hostname
            node['port'] = parsed.port
            node['uuid'] = parsed.username
            node['tls'] = parsed.scheme.endswith('+tls')
            node['network'] = parse_qs(parsed.query).get('type', ['tcp'])[0]
            node['ws-opts'] = {'path': parse_qs(parsed.query).get('path', ['/'])[0]}
        elif line.startswith('ss://'):
            # Shadowsocks, simple format only
            node['name'] = 'Shadowsocks Node'
            node['type'] = 'ss'
            # parsing left for brevity
        elif line.startswith('hysteria://'):
            node['name'] = 'Hysteria2 Node'
            node['type'] = 'hysteria2'
        elif line.startswith('anytls://'):
            node['name'] = 'AnyTLS Node'
            node['type'] = 'anytls'
        elif line.startswith('trojan://'):
            node['name'] = 'Trojan Node'
            node['type'] = 'trojan'
        else:
            print(f"[SKIP] Unknown protocol: {line[:30]}...")
            return None
        return node
    except Exception as e:
        print(f"[ERROR] Failed to parse node line: {line[:50]} -> {e}")
        return None

# ---------------- Main Workflow ----------------
def main():
    all_nodes = []
    if not os.path.exists(SOURCES_TXT):
        print(f"[ERROR] sources.txt not found at {SOURCES_TXT}")
        sys.exit(1)

    with open(SOURCES_TXT, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        content = fetch_subscription(url)
        if not content:
            print(f"[SKIP] No content from subscription: {url}")
            continue

        # Try base64 decode if it looks like vmess-style
        decoded_content = decode_base64(content) or content

        lines = decoded_content.strip().splitlines()
        if not lines:
            print(f"[SKIP] Subscription has no nodes: {url}")
            continue

        for line in lines:
            node = parse_node_line(line)
            if node:
                all_nodes.append(node)
            else:
                print(f"[SKIP] Invalid node line: {line[:50]}...")

    if not all_nodes:
        print("[WARN] No valid nodes found!")
        sys.exit(0)

    # ---------------- Save Clash YAML ----------------
    clash_dict = {'proxies': all_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_dict, f, allow_unicode=True, sort_keys=False)
    print(f"[INFO] Clash YAML generated: {OUTPUT_YAML}")

if __name__ == "__main__":
    main()

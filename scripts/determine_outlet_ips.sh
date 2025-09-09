#!/bin/bash
ALIVE_FILE="scripts/alive_links.txt"
OUTLET_FILE="scripts/outlet_links.json"
> $OUTLET_FILE

while IFS= read -r link; do
  echo "Processing $link ..."
  
  case "$CORE_TYPE" in
    v2ray)
      $CORE_BIN -config scripts/v2ray_config.json &
      ;;
    clash)
      $CORE_BIN -d scripts/clash_config.yaml &
      ;;
    sing-box)
      $CORE_BIN run -c scripts/singbox_config.json &
      ;;
  esac

  PROXY_PID=$!
  sleep 5
  outlet_ip=$(curl -s -x socks5h://127.0.0.1:1080 --max-time 5 https://api.ipify.org)
  echo "{\"link\": \"$link\", \"outlet_ip\": \"$outlet_ip\"}" >> $OUTLET_FILE
  kill $PROXY_PID
done < scripts/alive_links.txt

echo "Outlet IPs:"
cat $OUTLET_FILE

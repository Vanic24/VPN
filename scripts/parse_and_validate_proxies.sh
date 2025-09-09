#!/bin/bash
valid_protocols=("vmess" "vless" "trojan" "hysteria2" "anytls" "ss" "socks")
VALID_LINKS_FILE="scripts/valid_links.txt"
> $VALID_LINKS_FILE

while IFS= read -r line; do
  for protocol in "${valid_protocols[@]}"; do
    if [[ "$line" == $protocol://* ]]; then
      echo "$line" >> $VALID_LINKS_FILE
      break
    fi
  done
done < scripts/sources.txt

echo "Valid links:"
cat $VALID_LINKS_FILE

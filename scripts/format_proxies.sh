#!/bin/bash
OUTLET_FILE="scripts/outlet_links.json"
FORMATTED_FILE="scripts/formatted_proxies.txt"
> $FORMATTED_FILE

while IFS= read -r line; do
  link=$(echo $line | jq -r '.link')
  ip=$(echo $line | jq -r '.outlet_ip')
  # Example: flag/country code parsing (simple, you can improve)
  country="TW"
  flag="🇹🇼"
  type=$(echo $link | grep -oE '^[^:]+' )
  password=$(uuidgen)
  formatted="{\"name\": \"$flag|$country|@SHFX\", \"server\": \"$ip\", \"port\": 443, \"sni\": \"$ip\", \"up\": null, \"down\": null, \"skip-cert-verify\": true, \"type\": \"$type\", \"password\": \"$password\"}"
  echo "$formatted" >> $FORMATTED_FILE
done < <(jq -c '.[]' $OUTLET_FILE 2>/dev/null || cat $OUTLET_FILE)

echo "Formatted proxies:"
cat $FORMATTED_FILE

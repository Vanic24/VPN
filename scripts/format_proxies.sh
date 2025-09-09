#!/bin/bash
set -e
set -x

OUTLET_IPS="scripts/outlet_ips.txt"
PROXIES_JSON="scripts/proxies.json"
> $PROXIES_JSON

INDEX=1
while IFS= read -r line; do
    node=$(echo "$line" | cut -d '|' -f1)
    ip=$(echo "$line" | cut -d '|' -f2)
    # Simple flag and country code placeholder
    FLAG="🇹🇼"
    COUNTRY="TW$INDEX"
    NAME="$FLAG|$COUNTRY|@SHFX"

    # Example JSON format
    echo "{ \"name\": \"$NAME\", \"server\": \"$ip\", \"port\": 30001, \"sni\": \"example.com\", \"up\": null, \"down\": null, \"skip-cert-verify\": true, \"type\": \"hysteria2\", \"password\": \"9e0f72bb-7ad6-4383-994a-497569a94d74\" }" >> $PROXIES_JSON
    INDEX=$((INDEX+1))
done < $OUTLET_IPS

echo "Formatted proxies:"
cat $PROXIES_JSON

#!/bin/bash
set -e
set -x

FILTERED_NODES="scripts/filtered_nodes.txt"
OUTLET_IPS="scripts/outlet_ips.txt"
> $OUTLET_IPS

for node in $(cat $FILTERED_NODES); do
    # Use appropriate core
    if [[ $CORE_TYPE == "v2ray" ]]; then
        IP=$($CORE_BIN -test -config <(echo "{\"outbounds\":[{\"protocol\":\"freedom\",\"settings\":{}}]}") 2>&1 | grep -Eo '(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
    elif [[ $CORE_TYPE == "mihomo" ]]; then
        IP=$($CORE_BIN test "$node" | grep -Eo '(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
    elif [[ $CORE_TYPE == "sing-box" ]]; then
        IP=$($CORE_BIN check "$node" | grep -Eo '(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
    fi
    echo "$node|$IP" >> $OUTLET_IPS
done

echo "Outlet IPs determined:"
cat $OUTLET_IPS

#!/bin/bash
set -e
set -x

# File with all subscription URLs from secret repo
SOURCES_FILE="scripts/sources.txt"
PARSED_NODES="scripts/parsed_nodes.txt"

# Empty previous parsed nodes
> $PARSED_NODES

# Only allow supported protocols
SUPPORTED="^(vmess|vless|trojan|hysteria2|anytls|ss|socks)://"

while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r') # remove carriage returns
    if [[ $line =~ $SUPPORTED ]]; then
        echo "$line" >> $PARSED_NODES
    fi
done < "$SOURCES_FILE"

echo "Valid links:"
cat $PARSED_NODES

# Optional: filter by ping latency and alive/dead check
FILTERED_NODES="scripts/filtered_nodes.txt"
> $FILTERED_NODES

while IFS= read -r node; do
    # Extract host from URL (simple parsing)
    host=$(echo "$node" | sed -E 's#.*://([^:/]+).*#\1#')
    # Ping check
    pingtime=$(ping -c 1 -W 1 "$host" 2>/dev/null | tail -1 | awk -F '/' '{print $5}')
    pingtime=${pingtime:-999}
    if (( $(echo "$pingtime <= 100" | bc -l) )); then
        echo "$node" >> $FILTERED_NODES
    fi
done < "$PARSED_NODES"

echo "Filtered nodes (<100ms):"
cat $FILTERED_NODES

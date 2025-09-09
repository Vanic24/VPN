#!/bin/bash
set -e
set -x

TEMPLATE="ClashTemplate.ini"
PROXIES_JSON="scripts/proxies.json"
OUTPUT="proxies.yaml"

# Separate {{PROXIES}} and {{PROXY_NAMES}} if needed
PROXIES=$(cat $PROXIES_JSON | jq -c '.[]')
PROXY_NAMES=$(cat $PROXIES_JSON | jq -r '.[].name' | paste -sd "," -)

# Replace placeholders
TEMPLATE_TEXT=$(cat $TEMPLATE)
OUTPUT_TEXT=${TEMPLATE_TEXT//"{{PROXIES}}"/"$PROXIES"}
OUTPUT_TEXT=${OUTPUT_TEXT//"{{PROXY_NAMES}}"/"$PROXY_NAMES"}

echo "$OUTPUT_TEXT" > $OUTPUT
echo "Generated $OUTPUT"

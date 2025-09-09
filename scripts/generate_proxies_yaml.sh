#!/bin/bash
TEMPLATE_FILE="ClashTemplate.ini"
PROXIES_FILE="scripts/formatted_proxies.txt"
OUTPUT_FILE="proxies.yaml"

proxies_yaml=$(paste -sd '\n' $PROXIES_FILE)
proxy_names=$(cat $PROXIES_FILE | jq -r '.name')

output_text=$(< $TEMPLATE_FILE)
output_text=${output_text//"{{PROXIES}}"/$proxies_yaml}
output_text=${output_text//"{{PROXY_NAMES}}"/$proxy_names}

echo "$output_text" > $OUTPUT_FILE

echo "Generated proxies.yaml"
cat $OUTPUT_FILE

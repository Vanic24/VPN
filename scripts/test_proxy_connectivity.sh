#!/bin/bash
INPUT_FILE="scripts/valid_links.txt"
ALIVE_FILE="scripts/alive_links.txt"
> $ALIVE_FILE

while IFS= read -r link; do
  server=$(echo "$link" | grep -oP '(?<=@)[^:/]+')
  ping_time=$(ping -c 1 -W 1 $server | grep 'time=' | awk -F 'time=' '{print $2}' | awk '{print $1}')
  if [ -z "$ping_time" ]; then
    echo "$link unreachable"
    continue
  fi
  if (( $(echo "$ping_time > 100" | bc -l) )); then
    echo "$link high latency ($ping_time ms)"
    continue
  fi
  echo "$link" >> $ALIVE_FILE
done < $INPUT_FILE

echo "Alive links:"
cat $ALIVE_FILE

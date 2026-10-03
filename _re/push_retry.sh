#!/bin/bash
# push_retry.sh <branch> - push with token from file (never persisted), retry loop
set -u
BR="${1:-evasion-research}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOKFILE="$ROOT/GITHUB_PERSONAL_ACCESS_TOKEN.txt"
TOK="$(cat "$TOKFILE" | tr -d '[:space:]')"
[ -z "$TOK" ] && { echo "no token"; exit 2; }
for i in $(seq 1 15); do
  if git push "https://x-access-token:${TOK}@github.com/bXZb/Beacon.git" "$BR" 2>&1 | grep -v "^remote:" ; then
    echo "PUSH_OK attempt $i"; exit 0
  fi
  echo "push attempt $i failed, retry in 6s"; sleep 6
done
echo "PUSH_FAILED"; exit 1

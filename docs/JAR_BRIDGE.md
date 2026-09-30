# Jar bridge (settings generation)

## Intent

Produce the same settings blob the official Beacon expects, including Malleable
program bytecode for `SETTING_C2_REQUEST` / `C2_POSTREQ` / `C2_RECOVER`.

## CS 4.5 class map (from `../4.5/decompiled_src`)

| Class | Role |
|-------|------|
| `beacon.Settings` | TLV writer; `toPatch(4096)` |
| `beacon.BeaconPayload` | `exportBeaconStage`, `setupHTTP`, `beacon_obfuscate` (XOR 46) |
| `beacon.BeaconConstants` | Setting IDs + fixed lengths |
| `c2profile.Program` | `transform_binary` / `recover_binary` opcodes |
| `c2profile.Profile` | `apply_binary` / `recover_binary` entry |
| `common.Packer` | BE packer |
| `common.CommonUtils` | `readObject` for `.cobaltstrike.beacon_keys` |

## Approach

### Path A — Python reimplementation (fallback)

`tools/pack_settings.py` mirrors Settings + setupHTTP **default** programs + obfuscate.
Enough for default-profile HTTP check-in only.

### Path B — Settings-only jar bridge (**product path**)

Implementation: `tools/bridge/LinuxBeaconBridge.java`

1. Classpath: `4.5/lib/cobaltstrike.jar` (+ bridge `out/`).
2. `c2profile.Loader.LoadProfile` / `LoadDefaultProfile`.
3. Build `beacon.Settings` like `BeaconPayload.exportBeaconStage` **HTTP branch**
   (`setupHTTP`, killdate, pivot frames, cookie/host flags) — **no** `SleevedResource`
   and **no** `exportBeaconStage*` (avoids encrypted `sleeve/` DLL).
4. `toPatch(4096)` → `BeaconPayload.beacon_obfuscate` → `settings.bin`.

```bash
bash tools/bridge/build.sh   # or tools/bridge/build.ps1
bash tools/gen_payload.sh --host H --port P --bridge jar --profile file.profile \
  --pubkey tools/fixtures/publickey.der --out beacon
```

See [UI_GENERATE.md](UI_GENERATE.md). Follow `4.5/AGENTS.md` if editing Java under `4.5/src/`.

### Path C — Extract from generated Windows beacon

1. Generate official Windows beacon against same listener/profile.
2. Find patch marker `AAAABBBBCCCCDDDDEEEEFFFF` in DLL (requires sleeved DLL decrypt for research).
3. Read 4096 bytes, already obfuscated — use as fixture for LinuxBeacon.

## Sleeve

Jar `sleeve/*` resources are encrypted (`SleeveSecurity`). Linux generation must not
depend on CrackSleeve. Use CrackSleeve only in lab to diff Windows exports.

## Dev fallback

`pack_settings.py` without jar: minimal default profile programs + fixed URIs.

## Version pin

- CS version: **4.5 (20211214)** (from `aggressor.Aggressor.VERSION`)
- Validated classes: Settings, BeaconPayload.setupHTTP / beacon_obfuscate, Program opcodes, Loader.LoadProfile
- 4.9.1: not wired; keep separate bridge if needed later

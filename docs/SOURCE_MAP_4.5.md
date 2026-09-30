# Reference map: 4.5 Java + Beacon C++ → LinuxBeacon

This tree is the **protocol truth** for implementing LinuxBeacon.

## Sources

| Tree | Role |
|------|------|
| `4.5/decompiled_src/` | Cobalt Strike **4.5 (20211214)** client/teamserver Java (decompiled) |
| `CobaltStrikeBeaconCppSource-main/` | Windows **Beacon implant** C++ (runtime) |
| `LinuxBeacon/` | Linux implant reimplementation |

## Settings blob pipeline (must match)

```
4.5  beacon/Settings.java          TLV writer (BE short/int)
4.5  beacon/BeaconConstants.java   field IDs + fixed lengths
4.5  beacon/BeaconPayload.java     exportBeaconStage / setupHTTP
4.5  BeaconPayload.beacon_obfuscate  XOR 0x2E (46)
4.5  common/Packer.java            big-endian; zero-pad strings

C++   settings.cpp                 XOR 0x2E unmask → parse TLV
Linux settings.c                   same
Linux tools/pack_settings.py       same as Settings + obfuscate
```

### Critical fixed sizes (BeaconPayload.setupHTTP / exportBeaconStage)

| ID | Name | Size |
|----|------|------|
| 7 | PUBKEY | **256** (DER + zero pad) |
| 8 | DOMAINS | **256** (`host,uri,host,uri,...`) |
| 9 | USERAGENT | 256 |
| 10 | SUBMITURI | 64 |
| 11 | C2_RECOVER | 256 |
| 12 | C2_REQUEST | 512 |
| 13 | C2_POSTREQ | 512 |
| 26/27 | VERB GET/POST | 16 |

### DOMAINS format

Built as alternating pairs:

```text
host1 + "," + uri1 + "," + host2 + "," + uri2 + ...
```

URI list comes from `.http-get.uri` (space-separated); each host gets one picked URI.

### Protocol flags (SETTING_PROTOCOL)

From `exportBeaconStage`:

- `|= 1` if DNS
- `|= 8` if HTTPS (`BEACON_PROTO_HTTPS`)

## Malleable program bytecode

| Java | C++ | Linux |
|------|-----|-------|
| `c2profile/Program.java` opcodes + `transform_binary` | `profile.cpp` apply/recover | `profile.c` (P2) |
| `Profile.apply_binary` / `recover_binary` | settings ptr 12/13/11 | pack_settings + future profile_compile |

Opcode IDs (Program.java = profile.cpp):

```
1 APPEND  2 PREPEND  3 BASE64  4 PRINT  5 PARAMETER  6 HEADER
7 BUILD   8 NETBIOS  9 !PARAMETER  10 !HEADER  11 NETBIOSU
12 URI_APPEND  13 BASE64URL  15 MASK  16 HOSTHEADER
```

BUILD argument: `0` = metadata/id, `1` = output.

## Crypto / metadata

| Topic | C++ | Java (teamserver) |
|-------|-----|-------------------|
| Session AES/HMAC | `security.cpp` | decrypt side in BeaconC2 / related |
| Metadata layout | `metadata.cpp` | parses agent metadata on check-in |
| RSA | teamserver pubkey in settings 7 | keypair in `.cobaltstrike.beacon_keys` |

## Commands / callbacks

| C++ | Java |
|-----|------|
| `proto.cpp` command IDs | `beacon/CommandBuilder.java`, `Tasks.java`, `BeaconCommands.java` |
| `commands.h` CALLBACK_* | BeaconC2 output handling |

## Test plan using this tree

1. Use `4.5` + real teamserver to generate a Windows HTTP beacon with default profile.
2. Extract patched settings region (`AAAABBBBCCCCDDDDEEEEFFFF` marker → 4096 bytes after de-obfuscate).
3. Diff against `tools/pack_settings.py` output for same listener/profile.
4. LinuxBeacon must parse that blob and check in to the same listener.

## LinuxBeacon phase mapping

| Phase | Lean on |
|-------|---------|
| P0/P1 | Settings + crypto + HTTP default (this doc + C++ security/metadata) |
| P2 | `c2profile/Program.java` full transform_binary + recover_binary |
| P3+ | CommandBuilder / TaskBeacon for richer task packing; SOCKS from BeaconSocks |

## Do not confuse

- **`4.5`** = Java controller (generates config, talks protocol server-side)
- **`CobaltStrikeBeaconCppSource-main`** = Windows implant runtime
- **`LinuxBeacon`** = Linux implant runtime (peer of C++, consumer of settings from Java-compatible packer)

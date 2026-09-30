# Protocol surface (HTTP/S)

Source of truth: `CobaltStrikeBeaconCppSource-main` + verified Linux POC frames.

## Settings blob

Source: CS **4.5** `beacon/Settings.java` + `BeaconPayload.beacon_obfuscate` + C++ `settings.cpp`.
See also [SOURCE_MAP_4.5.md](SOURCE_MAP_4.5.md).

- Size: 4096 bytes (`PATCH_SIZE`)
- Writer pads unused space with **random** bytes, then XOR
- On load: each byte `^= 0x2E` (46)
- TLV stream (big-endian shorts/ints via Packer):

```
index:u16  type:u16  length:u16  value[length]
type 1=SHORT 2=INT 3=PTR
index 0 ends
```

Fixed sizes used by real payload export:

| ID | Field | Fixed length |
|----|-------|--------------|
| 7 | PUBKEY | 256 |
| 8 | DOMAINS | 256 (`host,uri,host,uri,...`) |
| 9 | USERAGENT | 256 |
| 10 | SUBMITURI | 64 |
| 11 | C2_RECOVER | 256 |
| 12 | C2_REQUEST | 512 |
| 13 | C2_POSTREQ | 512 |

Critical IDs: PROTOCOL(1), PORT(2), SLEEPTIME(3), MAXGET(4), JITTER(5),
PUBKEY(7), DOMAINS(8), USERAGENT(9), SUBMITURI(10), C2_RECOVER(11),
C2_REQUEST(12), C2_POSTREQ(13), VERB_GET(26), VERB_POST(27), CRYPTO_SCHEME(31).

## Crypto

- Session key: 16 random bytes
- `SHA256(session_key)` → AES key \| HMAC key (16+16)
- IV: fixed ASCII `abcdefghijklmnop`
- Task/callback: AES-128-CBC, length padded to 16 (consumer uses embedded BE length)
- Trailer: HMAC-SHA256 truncated to 16 over ciphertext
- Metadata: RSA PKCS#1 v1.5 with teamserver public DER

## Metadata (RSA plaintext)

```
magic 0x0000BEEF BE | len BE | session_key[16]
ansi_cp LE | oem_cp LE | agent_id BE | pid BE | port BE | flags
os_maj | os_min | build BE | ptr_hi | gmh | gpa | local_ip | "host\tuser\tproc"≤58
```

Agent ID: `rand & 0x7FFFFFFF & ~1`.

## Tasks (after decrypt)

```
[counter BE][len BE][blob]
blob: repeat [cmd_id BE][cmd_len BE][data]
```

## Callbacks (before encrypt)

```
[counter BE][len BE][type BE][data]
```

HTTP POST queue (official): `[enc_len BE][cipher+hmac]...`

## Malleable C2 bytecode (P2)

Programs live in settings as PTR fields:

| ID | Field | Role |
|----|-------|------|
| 11 | C2_RECOVER | reverse transforms on GET response body |
| 12 | C2_REQUEST | GET: build headers/query/body from metadata (arg0) |
| 13 | C2_POSTREQ | POST: build from session id (arg0) + output (arg1) |

Opcode stream (big-endian `u32` ops, same as `profile.cpp` / `Program.java`):

| Op | Name | Apply | Recover |
|----|------|-------|---------|
| 1 | APPEND | append string | strip right N |
| 2 | PREPEND | prepend string | strip left N |
| 3 | BASE64 | encode | decode |
| 4 | PRINT | body ← temp | no-op |
| 5 | PARAMETER | `?name=temp` / `&name=temp` | no-op |
| 6 | HEADER | `Name: temp\r\n` | no-op |
| 7 | BUILD | temp ← arg0 (0) or arg1 (1) | — |
| 8 | NETBIOS | encode base `'a'` | decode |
| 9 | !PARAMETER | append raw query fragment | — |
| 10 | !HEADER | append raw header line | — |
| 11 | NETBIOSU | encode base `'A'` | decode |
| 12 | URI_APPEND | uri ← uri+temp | no-op |
| 13 | BASE64URL | encode | decode |
| 15 | MASK | 4-byte key XOR | unmask |
| 16 | !HOSTHEADER | host header (or SETTING_HOST_HEADER) | — |
| 0 | END | inject global Host if needed | return length |

HTTP channel (`channel_http.c`):

1. `profile_setup` → seed `uri` from DOMAINS/SUBMITURI  
2. `apply(C2_REQUEST|C2_POSTREQ, …)`  
3. request path = `uri + parameters`; headers from profile; body from `print`  
4. GET response → `recover(C2_RECOVER)` then AES decrypt  

Empty recover program = identity (default profile).


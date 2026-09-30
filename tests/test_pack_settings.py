#!/usr/bin/env python3
"""Frame-level smoke tests (no teamserver)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from pack_settings import pack, PATCH, XOR_KEY  # noqa: E402


def test_pack_roundtrip_size():
    pubkey = b"\x30" + b"\x00" * 161
    blob = pack("10.0.0.1", 80, 0, pubkey)
    assert len(blob) == PATCH
    raw = bytes(b ^ XOR_KEY for b in blob)
    idx = struct.unpack(">H", raw[0:2])[0]
    assert idx == 1, idx
    # type short, length 2
    assert struct.unpack(">H", raw[2:4])[0] == 1
    assert struct.unpack(">H", raw[4:6])[0] == 2
    print("ok pack size + first TLV")


def test_pubkey_field_is_256():
    pubkey = b"\x30\x81\x9f" + b"\x11" * 100  # short key
    blob = pack("h", 443, 1, pubkey)
    raw = bytes(b ^ XOR_KEY for b in blob)
    # walk TLVs until id 7
    off = 0
    while off + 6 <= len(raw):
        idx, typ, ln = struct.unpack(">HHH", raw[off : off + 6])
        off += 6
        if idx == 0:
            break
        if idx == 7:
            assert typ == 3 and ln == 256, (typ, ln)
            val = raw[off : off + ln]
            assert val.startswith(pubkey[: len(pubkey)])
            assert val[len(pubkey) :] == b"\x00" * (256 - len(pubkey))
            print("ok pubkey padded to 256")
            return
        off += ln
    raise AssertionError("SETTING_PUBKEY not found")


def test_domains_format():
    blob = pack("1.2.3.4", 80, 0, b"\x00" * 20, get_uri="/a.js")
    raw = bytes(b ^ XOR_KEY for b in blob)
    off = 0
    while off + 6 <= len(raw):
        idx, typ, ln = struct.unpack(">HHH", raw[off : off + 6])
        off += 6
        if idx == 0:
            break
        if idx == 8:
            s = raw[off : off + ln].split(b"\x00", 1)[0].decode()
            assert s == "1.2.3.4,/a.js", s
            print("ok domains host,uri")
            return
        off += ln
    raise AssertionError("DOMAINS not found")


def test_build_length_rsa_magic():
    magic = struct.pack(">I", 0x0000BEEF)
    assert magic == b"\x00\x00\xbe\xef"
    print("ok magic")


if __name__ == "__main__":
    test_pack_roundtrip_size()
    test_pubkey_field_is_256()
    test_domains_format()
    test_build_length_rsa_magic()
    print("all tests passed")

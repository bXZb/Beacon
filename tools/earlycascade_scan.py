#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""earlycascade_scan.py - symbol-less locator for the two ntdll globals the
Outflank Early Cascade injection technique overwrites:

    g_pfnSE_DllLoaded  (.mrdata) - Shim-Engine callback fired inside
                                   LdrpSendPostSnapNotifications during
                                   kernelbase.dll initialization
    g_ShimsEnabled     (.data)   - the boolean gate for that callback

Ground truth for this workstation's build (Win10 19044, symbols via cdb):
    LdrpSendPostSnapNotifications RVA 0x3dc0c
    g_ShimsEnabled                RVA 0x16d194   (.data)
    g_pfnSE_DllLoaded             RVA 0x181268   (.mrdata)

Reference patterns in LdrpSendPostSnapNotifications (disasm 2026-11-10):

  +0x56: 44 38 3D <disp32>          cmp byte ptr [g_ShimsEnabled], r15b
          0F 85 <rel32>             jne  (skip when shims disabled)
  ...
  +0x135: 8B 14 25 30 03 FE 7F      mov edx, [SharedUserData+0x330]  ; KCFG cookie
           B8 40 00 00 00           mov eax, 40h
           48 8B 3D <disp32>        mov rdi, [g_pfnSE_DllLoaded]     ; ENCODED
           ... ror rdi, cl / xor rdi, rax                            ; decode

KCFG NOTE (important for the write side): on this build the stored
g_pfnSE_DllLoaded value is KCFG-cookie encoded; the reader computes
decoded = ror64(stored, 64 - (cookie & 63)) ^ cookie  (cookie = the 32-bit
value at SharedUserData+0x330, zero-extended). A stub address S must be
written as  stored = rol64(S ^ cookie, 64 - (cookie & 63)).

Scan strategy (no symbols, no disassembler):
  1. anchor cluster A: SharedUserData+0x330 literal "8B 14 25 30 03 FE 7F"
     followed within 16 bytes by "B8 40 00 00 00" and a "48 8B 3D" whose
     rip-relative target is uniquely identified -> g_pfnSE_DllLoaded.
  2. from the same function, anchor "44 38 3D" (cmp byte [rip+X], r15b)
     whose target lies in a writable data section -> g_ShimsEnabled.
  3. cross-check section placement: g_pfnSE_DllLoaded must sit in .mrdata
     (or the build's equivalent writable-at-boot section), g_ShimsEnabled
     in .data.
"""
import struct
import sys

NTDLL = r"C:\Windows\System32\ntdll.dll"


def parse_sections(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, vaddr, vsize, roff, rsize))
    return secs


def rva_to_off(secs, rva):
    for name, vaddr, vsize, roff, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return name, roff + (rva - vaddr)
    return None, None


def main():
    data = open(NTDLL, "rb").read()
    secs = parse_sections(data)
    print("sections:", [(s[0], hex(s[1])) for s in secs])

    hits = {}
    # anchor A: SharedUserData cookie load + mov eax,40h + mov rdi,[rip+X]
    anchor = bytes.fromhex("8B14253003FE7F")
    i = 0
    while True:
        i = data.find(anchor, i)
        if i < 0:
            break
        window = data[i:i + 24]
        # expect B8 40 00 00 00 then 48 8B 3D disp32
        k = window.find(bytes.fromhex("B840000000"))
        if k >= 0:
            w2 = window[k + 5:]
            if w2[:3] == bytes.fromhex("488B3D"):
                disp = struct.unpack_from("<i", w2, 3)[0]
                site = rva_of(secs, i)  # file offset -> rva
                if site is None:
                    i += 1
                    continue
                # instruction end rva = site(k+5+3+4 within window) ... compute precisely
                insn_rva = site + k + 5 + 3 + 4
                hits["g_pfnSE_DllLoaded"] = insn_rva + disp
                hits["_cookie_site"] = site + k
        i += 1

    # anchor B: cmp byte ptr [rip+X], r15b -> g_ShimsEnabled candidates
    # keep (site_rva, target_rva) pairs for the strict pass below
    cands = []
    infunc = []
    pat = bytes.fromhex("44383D")
    i = 0
    while True:
        i = data.find(pat, i)
        if i < 0:
            break
        disp = struct.unpack_from("<i", data, i + 3)[0]
        site = rva_of(secs, i)
        if site is not None:
            target = site + 7 + disp
            name, _ = rva_to_off(secs, target)
            if name in (".data", ".mrdata"):
                cands.append((target, name))
                infunc.append((site, target))
        i += 1

    # STRICT discrimination: the ShimsEnabled gate is the in-function cmp
    # whose following jne lands on the cookie-load/decode block (the +0x135
    # shape). The sibling g_ShimsLoading cmp guards the callback call under
    # a different branch and its jne loops back to the walk, not to the
    # decode block.
    cookie_site_rva = hits.get("_cookie_site")
    strict = []
    for site_rva, target in infunc:
        o = off_of(site_rva)
        if o is None or data[o + 7:o + 9] != bytes.fromhex("0F85"):
            continue
        d = struct.unpack_from("<i", data, o + 9)[0]
        jtarget = site_rva + 13 + d
        if cookie_site_rva is not None and abs(jtarget - cookie_site_rva) <= 0x40:
            strict.append(target)
    hits["g_ShimsEnabled"] = strict[0] if len(strict) == 1 else None
    print("\ng_pfnSE_DllLoaded:", hex(hits["g_pfnSE_DllLoaded"]) if "g_pfnSE_DllLoaded" in hits else "NOT FOUND",
          "section:", rva_to_off(secs, hits.get("g_pfnSE_DllLoaded", 0))[0] if "g_pfnSE_DllLoaded" in hits else "-")
    print("ground truth     : 0x181268")
    print("g_ShimsEnabled (strict):", hex(hits["g_ShimsEnabled"]) if hits.get("g_ShimsEnabled") else
          "AMBIGUOUS candidates=%s" % [hex(t) for _, t in infunc])
    print("ground truth     : 0x16d194")

    # KCFG write-side helper: sample the live cookie and prove the
    # encode/decode round-trip the stub write must satisfy on this build
    try:
        cookie = struct.unpack("<I", __import__("ctypes").string_at(0x7FFE0000 + 0x330, 4))[0]

        def rol64(v, n):
            n %= 64
            return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF if n else v

        def encode(ptr):  # inverse of: ror64(stored, 64-(c&63)) ^ c
            return rol64(ptr ^ cookie, 64 - (cookie & 63))

        sample = 0x180001000
        stored = encode(sample)
        n = (64 - (cookie & 63)) % 64
        rot = ((stored >> n) | (stored << (64 - n))) & 0xFFFFFFFFFFFFFFFF if n else stored
        rt = "OK" if (rot ^ cookie) == sample else "FAIL"
        print("KCFG cookie=0x%08x  write(0x%x)=0x%x roundtrip=%s" % (cookie, sample, stored, rt))
    except Exception as e:
        print("KCFG helper skipped:", e)

    ok1 = hits.get("g_pfnSE_DllLoaded") == 0x181268
    ok2 = hits.get("g_ShimsEnabled") == 0x16D194
    print("\nVERDICT: g_pfnSE_DllLoaded %s | g_ShimsEnabled %s" % ("PASS" if ok1 else "FAIL", "PASS" if ok2 else "FAIL"))
    return 0 if (ok1 and ok2) else 1


def off_of(rva, data=None, _cache={}):
    if data is None:
        data = _cache.get("data")
        if data is None:
            data = open(NTDLL, "rb").read()
            _cache["data"] = data
    e = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    so = e + 24 + o
    for i in range(n):
        b2 = so + i * 40
        vs, va, rs, ro = struct.unpack_from("<IIII", data, b2 + 8)
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def rva_of(secs, file_off):
    for name, vaddr, vsize, roff, rsize in secs:
        if roff <= file_off < roff + rsize:
            return vaddr + (file_off - roff)
    return None


if __name__ == "__main__":
    sys.exit(main())

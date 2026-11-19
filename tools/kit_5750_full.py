# -*- coding: utf-8 -*-
"""kit_5750_full.py - full 0x5750 dump + kit API name strings + full
ntdll!RtlUserThreadStart body (to ret) on 19044."""
import struct
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)


def load_pe(path):
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    opt = e + 0x18
    sect = opt + struct.unpack_from("<H", d, e + 0x14)[0]
    secs = []
    for i in range(nsec):
        s = sect + i * 40
        name = d[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        vsz, va, rsz, ro = (struct.unpack_from("<I", d, s + 8)[0],
                            struct.unpack_from("<I", d, s + 12)[0],
                            struct.unpack_from("<I", d, s + 16)[0],
                            struct.unpack_from("<I", d, s + 20)[0])
        secs.append((name, va, vsz, ro, rsz))
    return d, secs


def rva2off(secs, rva):
    for name, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


def dump_until_ret(d, secs, rva, title, maxlen=0x400):
    off = rva2off(secs, rva)
    print("\n===== %s (rva 0x%x) =====" % (title, rva))
    end = off + maxlen
    for insn in md.disasm(d[off:end], rva):
        print("  %06x  %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic == "ret":
            break


# ---- kit DLL ----
d1, s1 = load_pe(r"C:\Users\Public\kit_async.x64.dll")
dump_until_ret(d1, s1, 0x5750, "kit sub_5750 (thread create wrapper)")

# API-name strings anywhere in the kit image
print("\n===== kit strings: thread/context APIs =====")
for pat in (rb"[\x20-\x7e]{0,40}(?:Thread|thread)[\x20-\x7e]{0,40}",):
    seen = set()
    for m in re.finditer(pat, d1):
        s = m.group(0).decode(errors="replace")
        if s in seen:
            continue
        seen.add(s)
        if len(s) < 6:
            continue
        print("  off=0x%x %r" % (m.start(), s[:64]))
        if len(seen) > 40:
            break

# ---- ntdll ----
d2, s2 = load_pe(r"C:\Windows\System32\ntdll.dll")
dump_until_ret(d2, s2, 0x4cc70, "ntdll!RtlUserThreadStart FULL", 0x120)
# what's at 0x4ccb3 (the +0x21 jmp target)?
dump_until_ret(d2, s2, 0x4ccb3, "ntdll 0x4ccb3 (+0x21 jmp target)", 0x80)

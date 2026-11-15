# -*- coding: utf-8 -*-
"""kit_helper_disasm.py - disassemble kit DLL helper functions (0x5750
thread-create wrapper etc.) AND Windows 19044 ntdll!RtlUserThreadStart
from the on-disk binary (export-table name -> capstone, no PDB needed)."""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)


def load_pe(path):
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    opt = e + 0x18
    magic = struct.unpack_from("<H", d, opt)[0]
    assert magic == 0x20B, "not PE32+"
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


def exports(d, secs):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e + 0x18
    exp_rva = struct.unpack_from("<I", d, opt + 0x70 + 0)[0]
    exp_sz = struct.unpack_from("<I", d, opt + 0x70 + 4)[0]
    off = rva2off(secs, exp_rva)
    (_, _, _, name_rva, ordbase, nfuncs, nnames, addr_rva, name_tbl,
     ord_rva) = struct.unpack_from("<10I", d, off)
    aoff = rva2off(secs, addr_rva)
    noff = rva2off(secs, name_tbl)
    ooff = rva2off(secs, ord_rva)
    out = {}
    for i in range(nnames):
        no = struct.unpack_from("<I", d, noff + i * 4)[0]
        fo = rva2off(secs, no)
        nm = d[fo:d.find(b"\x00", fo)].decode(errors="replace")
        oi = struct.unpack_from("<H", d, ooff + i * 2)[0]
        rva = struct.unpack_from("<I", d, aoff + oi * 4)[0]
        out[nm] = rva
    return out


def dis(d, secs, rva, n=0x80, title=""):
    off = rva2off(secs, rva)
    print("\n===== %s (rva 0x%x) =====" % (title, rva))
    for insn in md.disasm(d[off:off + n], rva):
        print("  %06x  %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))


# ---------- part 1: ntdll!RtlUserThreadStart on this OS ----------
NT = r"C:\Windows\System32\ntdll.dll"
d2, s2 = load_pe(NT)
exp = exports(d2, s2)
print("ntdll build: %s%s" % (
    struct.unpack_from("<H", d2, struct.unpack_from("<I", d2, 0x3C)[0] + 0x18 + 64)[0],
    struct.unpack_from("<H", d2, struct.unpack_from("<I", d2, 0x3C)[0] + 0x18 + 66)[0]))
for sym in ("RtlUserThreadStart", "RtlUserThreadStartTop", "thread_start_apc",
            "LdrInitializeThunk", "RtlInitializeUserStackAndTeb"):
    if sym in exp:
        print("export: %s rva=0x%x" % (sym, exp[sym]))
# walk RtlUserThreadStart until ret (with depth for calls shown, stop on ret)
rva = exp["RtlUserThreadStart"]
off = rva2off(s2, rva)
print("\n===== ntdll!RtlUserThreadStart (rva 0x%x) =====" % rva)
depth = 0
for insn in md.disasm(d2[off:off + 0x100], rva):
    print("  %06x  %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))
    if insn.mnemonic == "ret" and depth <= 0:
        break
    if insn.mnemonic == "call":
        depth += 1
    if insn.mnemonic.startswith("j") and "mp" not in insn.mnemonic:
        pass
    if insn.mnemonic == "jmp":
        break
# also the offset +0x21 exact instruction
off21 = rva2off(s2, rva + 0x21)
ins = next(md.disasm(d2[off21:off21 + 16], rva + 0x21))
print("\n>>> instruction at RtlUserThreadStart+0x21: %s %s" % (ins.mnemonic, ins.op_str))

# ---------- part 2: kit DLL helpers ----------
KIT = r"C:\Users\Public\kit_async.x64.dll"
d1, s1 = load_pe(KIT)
for fn, n in ((0x5750, 0xE0), (0x5510, 0x60), (0x5630, 0x60), (0x53f0, 0x40),
              (0x7220, 0x100), (0x48e0, 0x40)):
    dis(d1, s1, fn, n, "kit sub_%x" % fn)

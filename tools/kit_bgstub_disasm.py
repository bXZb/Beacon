# -*- coding: utf-8 -*-
"""kit_bgstub_disasm.py - full disasm of kit bg stub 0x3B70 and runner
0x3d40 with IAT + rip-target annotation; hunt the 0x4F error emission."""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)

d = open(r"C:\Users\Public\kit_async.x64.dll", "rb").read()
e = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, e + 6)[0]
sect = e + 0x18 + struct.unpack_from("<H", d, e + 0x14)[0]
secs = []
for i in range(nsec):
    s = sect + i * 40
    nm = d[s:s + 8].rstrip(b"\x00").decode(errors="replace")
    vsz, va, rsz, ro = struct.unpack_from("<IIII", d, s + 8)
    secs.append((nm, va, vsz, ro, rsz))


def r2o(rva):
    for n, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


# IAT map
impdir = struct.unpack_from("<I", d, e + 0x18 + 0x70 + 8)[0]
desc = r2o(impdir)
iatmap = {}
while True:
    oft, _, _, namerva, firstrva = struct.unpack_from("<IIIII", d, desc)
    if firstrva == 0:
        break
    noff = r2o(namerva)
    dllname = d[noff:d.find(b"\x00", noff)].decode()
    thunk = oft if oft else firstrva
    i = 0
    while True:
        val = struct.unpack_from("<Q", d, r2o(thunk) + i * 8)[0]
        if val == 0:
            break
        if val & 0x8000000000000000 == 0:
            fo = r2o(val & 0xFFFFFFFF)
            fname = d[fo + 2:d.find(b"\x00", fo + 2)].decode()
            iatmap[firstrva + i * 8] = dllname + "!" + fname
        i += 1
    desc += 20


def dump(lo, hi, title):
    off = r2o(lo)
    print("===== %s (0x%x-0x%x) =====" % (title, lo, hi))
    for insn in md.disasm(d[off:off + (hi - lo)], lo):
        cmt = ""
        if insn.mnemonic == "call" and "[rip" in insn.op_str:
            try:
                disp = int(insn.op_str.split("[rip +")[-1].split("]")[0]
                           .replace(" ", ""), 0)
                tgt = insn.address + insn.size + disp
                cmt = "   ; " + (iatmap.get(tgt) or ("sub_%x" % tgt))
            except Exception:
                pass
        elif insn.mnemonic in ("lea", "mov", "cmp", "test") and "[rip" in insn.op_str:
            try:
                disp = int(insn.op_str.split("[rip +")[-1].split("]")[0]
                           .replace(" ", ""), 0)
                cmt = "   ; ->0x%x" % (insn.address + insn.size + disp)
            except Exception:
                pass
        print("  %06x  %-9s %s%s" % (insn.address, insn.mnemonic,
                                     insn.op_str, cmt))
    print()


dump(0x3B70, 0x3d40, "bg stub 0x3B70")
dump(0x3d40, 0x3f00, "runner 0x3d40")

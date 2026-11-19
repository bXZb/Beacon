# -*- coding: utf-8 -*-
"""kit_main_disasm.py - PE-parse the prebuilt async-execute kit dll, locate
the _POSTEX_ARGUMENTS_ and pipe-name markers in .data/.rdata, and find every
rip-relative code reference to them; dump the surrounding functions to read
the kit main's real control flow."""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = r"C:\Users\Public\kit_async.x64.dll"
d = open(DLL, "rb").read()

e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
opt = e_lfanew + 0x18
entry_rva = struct.unpack_from("<I", d, opt + 16)[0]
sect = e_lfanew + 0x18 + 0xF0
secs = []
for i in range(nsec):
    s = sect + i * 40
    name = d[s:s + 8].rstrip(b"\x00").decode(errors="replace")
    vsz, va, rsz, ro = (struct.unpack_from("<I", d, s + 8)[0],
                        struct.unpack_from("<I", d, s + 12)[0],
                        struct.unpack_from("<I", d, s + 16)[0],
                        struct.unpack_from("<I", d, s + 20)[0])
    secs.append((name, va, vsz, ro, rsz))
    print("sec %-8s va=0x%x vsz=0x%x ro=0x%x rsz=0x%x" % (name, va, vsz, ro, rsz))
print("entry rva=0x%x" % entry_rva)


def rva2off(rva):
    for name, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


def off2rva(off):
    for name, va, vsz, ro, rsz in secs:
        if ro <= off < ro + rsz:
            return va + (off - ro)
    return None

m1 = d.find(b"_POSTEX_ARGUMENTS_")
m2 = d.find(b"POST_EX_PIPE_NAME")
print("markers: args@off=0x%x rva=0x%x | pipe@off=0x%x rva=0x%x" % (
    m1, off2rva(m1) or 0, m2, off2rva(m2) or 0))
targets = {off2rva(m1): "ARGS_MARK", off2rva(m2): "PIPE_MARK"}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

text = [(n, va, vsz, ro, rsz) for n, va, vsz, ro, rsz in secs if n == ".text"][0]
tname, tva, tvsz, tro, trsz = text
code = d[tro:tro + trsz]

xrefs = []
for insn in md.disasm(code, tva):
    if insn.mnemonic in ("lea", "mov") and "[rip" in insn.op_str:
        # compute the rip-relative target
        try:
            disp_str = insn.op_str.split("[rip +")[-1].split("[rip ")[-1]
            disp = int(disp_str.split("]")[0].strip().replace("h", ""), 0)
        except Exception:
            continue
        tgt = insn.address + insn.size + disp
        if tgt in targets:
            xrefs.append((insn.address, targets[tgt], insn.mnemonic, insn.op_str))

print("\nxrefs to markers:")
for a, t, m, o in xrefs:
    print("  0x%x %s -> %s (%s %s)" % (a, t, m, o, ""))

# dump a window around each xref site (function-ish context)
for a, t, m, o in xrefs:
    lo = max(tva, a - 0x140)
    hi = min(tva + trsz, a + 0x140)
    off = tro + (lo - tva)
    print("\n===== window @0x%x (%s) =====" % (a, t))
    for insn in md.disasm(d[off:off + (hi - lo)], lo):
        tag = " <<<" if insn.address == a else ""
        print("  %08x  %-8s %s%s" % (insn.address, insn.mnemonic, insn.op_str, tag))

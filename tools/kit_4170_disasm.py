# -*- coding: utf-8 -*-
"""kit_4170_disasm.py - full disasm of kit DLL 0x4170 (bg server thread
creation) + every call site of thread/context APIs via IAT mapping."""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = r"C:\Users\Public\kit_async.x64.dll"
d = open(DLL, "rb").read()

e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
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


def rva2off(rva):
    for name, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


# ---- import table: IAT rva -> "dll!func" ----
impdir = struct.unpack_from("<I", d, e_lfanew + 0x18 + 0x70 + 8)[0]  # data dir 1
iat_rva = struct.unpack_from("<I", d, e_lfanew + 0x18 + 0x70 + 24)[0]  # data dir 2
iatmap = {}
desc = rva2off(impdir)
while True:
    oft, tds, fwd, namerva, firstrva = struct.unpack_from("<IIIII", d, desc)
    if firstrva == 0:
        break
    noff = rva2off(namerva)
    dllname = d[noff:d.find(b"\x00", noff)].decode()
    thunk = oft if oft else firstrva
    i = 0
    while True:
        val = struct.unpack_from("<Q", d, rva2off(thunk) + i * 8)[0]
        if val == 0:
            break
        if val & 0x8000000000000000 == 0:
            fo = rva2off(val & 0xFFFFFFFF)
            fname = d[fo + 2:d.find(b"\x00", fo + 2)].decode()
            iatmap[firstrva + i * 8] = dllname + "!" + fname
        i += 1
    desc += 20

WATCH = ("GetThreadContext", "SetThreadContext", "CreateThread", "ResumeThread",
         "SuspendThread", "Wow64GetThreadContext", "NtGetContextThread",
         "NtSetContextThread", "NtCreateThreadEx", "RtlCreateUserThread",
         "OpenThread", "QueueUserAPC", "NtQueueApcThread", "CreateRemoteThread",
         "NtResumeThread", "CreateEventW", "CreateEventA", "WaitForSingleObject",
         "VirtualAlloc", "VirtualAllocEx")
watch_iat = {rva: n for rva, n in iatmap.items()
             if any(w.lower() in n.lower().split("!")[1] for w in WATCH)}

text = [s for s in secs if s[0] == ".text"][0]
tname, tva, tvsz, tro, trsz = text
code = d[tro:tro + trsz]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print("watch IAT slots:")
for rva, n in sorted(watch_iat.items()):
    print("  0x%x %s" % (rva, n))

sites = []
for insn in md.disasm(code, tva):
    if insn.mnemonic == "call" and "[rip" in insn.op_str:
        try:
            disp = int(insn.op_str.split("[rip +")[-1].split("]")[0]
                       .replace(" ", ""), 0)
        except Exception:
            continue
        tgt = insn.address + insn.size + disp
        if tgt in watch_iat:
            sites.append((insn.address, watch_iat[tgt]))

print("\nthread/context API call sites:")
for a, n in sites:
    print("  0x%x  %s" % (a, n))


def dump(lo, hi, title):
    off = tro + (lo - tva)
    print("\n===== %s (0x%x-0x%x) =====" % (title, lo, hi))
    for insn in md.disasm(d[off:off + (hi - lo)], lo):
        cmt = ""
        if insn.mnemonic == "call" and "[rip" in insn.op_str:
            try:
                disp = int(insn.op_str.split("[rip +")[-1].split("]")[0]
                           .replace(" ", ""), 0)
                tgt = insn.address + insn.size + disp
                if tgt in iatmap:
                    cmt = "   ; " + iatmap[tgt]
                else:
                    cmt = "   ; sub_%x" % tgt
            except Exception:
                pass
        if insn.mnemonic in ("lea", "mov") and "[rip" in insn.op_str:
            try:
                disp = int(insn.op_str.split("[rip +")[-1].split("]")[0]
                           .replace(" ", ""), 0)
                cmt = "   ; ->0x%x" % (insn.address + insn.size + disp)
            except Exception:
                pass
        print("  %06x  %-9s %s%s" % (insn.address, insn.mnemonic,
                                     insn.op_str, cmt))


# 0x4170 full function: runs to ~0x4300 (realmMain start)
dump(0x4170, 0x4300, "0x4170 bg thread creation")
# dump context around each thread API call site
for a, n in sites:
    if any(k in n for k in ("ThreadContext", "CreateThread", "ResumeThread",
                            "SuspendThread", "CreateEvent", "NtCreateThreadEx")):
        dump(max(tva, a - 0x70), min(tva + trsz, a + 0x50), "site 0x%x %s" % (a, n))

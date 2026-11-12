# -*- coding: utf-8 -*-
"""tpd_ntqwf_disasm.py - static disasm of NtQueryInformationWorkerFactory from
the on-disk ntdll to learn the BasicInformation layout (IoCompletionHandle
offset) and valid classes."""
import ctypes
import struct
from ctypes import wintypes

import capstone

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]

h = k32.LoadLibraryW(r"C:\Windows\System32\ntdll.dll")
base = h
ntqwf = k32.GetProcAddress(h, b"NtQueryInformationWorkerFactory")
rva = ntqwf - base
print("ntdll base=0x%x NtQueryInformationWorkerFactory=0x%x rva=0x%x" % (base, ntqwf, rva))

# map RVA -> file offset via PE headers
dos = base
e_lfanew = struct.unpack_from("<I", ctypes.string_at(base + 0x3C, 4), 0)[0]
nsec = struct.unpack_from("<H", ctypes.string_at(base + e_lfanew + 6, 2), 0)[0]
opt = struct.unpack_from("<H", ctypes.string_at(base + e_lfanew + 20, 2), 0)[0]
sec0 = base + e_lfanew + 24 + opt
file_off = None
for i in range(nsec):
    hdr = ctypes.string_at(sec0 + i * 40, 40)
    vsz, sva, rsz, sro = struct.unpack_from("<IIII", hdr, 8)
    if sva <= rva < sva + max(vsz, rsz):
        file_off = sro + (rva - sva)
        break
assert file_off is not None
print("file offset 0x%x" % file_off)

data = open(r"C:\Windows\System32\ntdll.dll", "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False
code = data[file_off:file_off + 0x300]
for insn in md.disasm(code, ntqwf):
    s = "%08x  %-8s %s" % (insn.address - base, insn.mnemonic, insn.op_str)
    print(s)
    if insn.mnemonic == "ret":
        break

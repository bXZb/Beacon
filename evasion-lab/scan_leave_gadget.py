# -*- coding: utf-8 -*-
"""scan_leave_gadget.py - does ntdll (Win10 19044 host) contain executable
C9 C3 (leave;ret) or 48 89 EC 5D C3 (mov rsp,rbp; pop rbp; ret)?"""
import ctypes
import struct

ntdll = ctypes.CDLL("ntdll.dll")
base = ctypes.cast(ntdll._handle, ctypes.POINTER(ctypes.c_ubyte))
hmod = ntdll._handle

# read PE headers via ReadProcessMemory-free approach: ctypes string_at
def at(off, n):
    return ctypes.string_at(hmod + off, n)

dos = at(0, 0x40)
assert dos[:2] == b"MZ"
e_lfanew = struct.unpack("<I", dos[0x3C:0x40])[0]
nth = at(e_lfanew, 0x100)
assert nth[:4] == b"PE\x00\x00"
machine, nsec, _tds, _ptr, _sz, szopt, _chars = struct.unpack("<HHIIIHH", nth[4:24])
print("sections:", nsec, "szopt:", hex(szopt))
sec_off = e_lfanew + 24 + szopt
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000

pats = {
    b"\xC9\xC3": "leave; ret",
    b"\x48\x89\xEC\x5D\xC3": "mov rsp,rbp; pop rbp; ret",
    b"\x48\x89\xEC": "mov rsp,rbp (any)",
}

for i in range(nsec):
    s = at(sec_off + i * 40, 40)
    name = s[:8].rstrip(b"\x00").decode()
    vsize, vaddr, rsize, _raddr = struct.unpack("<IIII", s[8:24])
    chars = struct.unpack("<I", s[36:40])[0]
    if not (chars & IMAGE_SCN_MEM_EXECUTE and chars & IMAGE_SCN_MEM_READ):
        continue
    span = min(vsize, rsize)
    data = at(vaddr, span)
    print("exec section %s vaddr=%#x span=%#x" % (name, vaddr, span))
    for pat, label in pats.items():
        hits = []
    for pat, label in pats.items():
        start = 0
        count = 0
        first = None
        while True:
            j = data.find(pat, start)
            if j < 0:
                break
            if first is None:
                first = j
            count += 1
            start = j + 1
            if count >= 5:
                break
        print("  %-28s count>=%d first_off=%s rva=%s" % (
            label, count,
            hex(first) if first is not None else "-",
            hex(vaddr + first) if first is not None else "-"))

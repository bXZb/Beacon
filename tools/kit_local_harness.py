# -*- coding: utf-8 -*-
"""kit_local_harness.py - observe the official kit async-execute DLL's
CONTROL-PIPE protocol byte-for-byte in isolation:
  patch kit dll (pipe marker in-place; ARGS marker -> [20B hdr][args])
  -> loader -> DllMain(4) -> we connect the control pipe as the beacon
  -> dump everything the kit writes (framing, sizes, timing)
  -> optionally write a follow-up task and watch."""
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes

CTRL = r"\\.\pipe\kit_ctrl"
KIT = r"C:\Users\Public\kit_async.x64.dll"
LOADER = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin"

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"

# args blob (kit-contract first run): [iiizzb] single=1 alloc=1 syscall=1 "" pipe bof
FULL = bytes.fromhex(open(r"C:\Users\Public\bt_hello_wire.hex").read().strip())


def L(b):
    return struct.pack(">i", len(b)) + b


WIRE_KIT = FULL[8:] + struct.pack(">i", 0)          # A/B: 8-stripped
ARGS = (struct.pack(">i", 1) + struct.pack(">i", 1) + struct.pack(">i", 1)
        + L(b"\x00") + L(b"\\\\.\\pipe\\kit_out" + b"\x00") + L(WIRE_KIT))


def patch_kit(data):
    d = bytearray(data)
    n0 = len(d)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0, "pipe marker"
    name = CTRL.encode() + b"\x00"
    name = name + b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    i = bytes(d).find(ARGSMARK)
    assert i > 0, "args marker"
    hdr = (struct.pack("<i", 1) + b"AAAA" + b"Y" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    blob = hdr + ARGS
    d[i:i + len(blob)] = blob
    assert len(d) == n0
    return bytes(d)


CHILD = r"C:\Users\Public\kit_child.py"
open(CHILD, "w").write(r'''
import ctypes, struct, sys, time, os
from ctypes import wintypes
sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools")
from kit_local_harness import patch_kit
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.CreateThread.restype = wintypes.HANDLE
dll = patch_kit(open(r"C:\Users\Public\kit_async.x64.dll", "rb").read())
loader = open(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin", "rb").read()
blob = loader + dll
base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)
ctypes.memmove(base, blob, len(blob))
print("pid", os.getpid(), "base", hex(base), "kit", len(dll), flush=True)
k32.CreateThread(None, 0, ctypes.cast(base, wintypes.LPVOID), None, 0, None)
time.sleep(60)
print("SURVIVED 60s", flush=True)
''')

PARENT = r"C:\Users\Public\kit_parent.py"
open(PARENT, "w").write(r'''
import time, struct, ctypes, sys
from ctypes import wintypes
GENERIC_RW = 0x80000000 | 0x40000000
OPEN_EXISTING = 3
CTRL = r"\\.\pipe\kit_ctrl"

def open_pipe(name, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = ctypes.windll.kernel32.CreateFileW(name, GENERIC_RW, 0, None, OPEN_EXISTING, 0, None)
        if h != -1 and h != 0:
            return h
        time.sleep(0.3)
    return None

h = open_pipe(CTRL)
print("ctrl connected:", h is not None, flush=True)
if not h:
    raise SystemExit
out = b""
t0 = time.time()
while time.time() - t0 < 25:
    buf = ctypes.create_string_buffer(65536)
    got = wintypes.DWORD(0)
    if ctypes.windll.kernel32.ReadFile(h, buf, 65536, ctypes.byref(got), None) and got.value:
        chunk = buf.raw[:got.value]
        out += chunk
        print("t+%.1fs RECV %d B: %s" % (time.time() - t0, got.value, chunk[:80].hex()))
        # try framing
        if got.value >= 4:
            le = struct.unpack("<i", chunk[:4])[0]
            be = struct.unpack(">i", chunk[:4])[0]
            print("      first4 LE=%d BE=%d" % (le, be))
    else:
        time.sleep(0.3)
print("total:", len(out))
''')


def main():
    p = subprocess.Popen([sys.executable, "-I", CHILD], cwd=r"C:\Users\Public",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)
    p2 = subprocess.Popen([sys.executable, "-I", PARENT], cwd=r"C:\Users\Public",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t0 = time.time()
    rc = None
    while time.time() - t0 < 50 and rc is None:
        rc = p.poll()
        time.sleep(1)
    if rc is None:
        p.kill()
    p2.wait(timeout=70)
    print("child rc:", rc, hex(rc & 0xFFFFFFFF) if rc else "")
    print(p.stdout.read().decode("gbk", "replace").strip()[:120])
    print("--- parent ---")
    print(p2.stdout.read().decode("gbk", "replace").strip()[:1600])


if __name__ == "__main__":
    main()

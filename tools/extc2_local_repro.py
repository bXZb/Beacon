# -*- coding: utf-8 -*-
"""extc2_local_repro.py - local reproduction of the line-B failure:
LoadLibrary the CI extc2 stub-build DLL, call DllMain(base, 4, None) on a
thread, then watch (a) named-pipe list diff for a self-boot bind,
(b) whether the host process calls ExitProcess (line-B symptom),
(c) nothing at all (smb_init fail-return).

Run in a sacrificial child python so an ExitProcess cannot kill the rig."""
import os
import struct
import subprocess
import sys
import time

PUB = r"C:\Users\Public"
CHILD = PUB + r"\extc2_repro_child.py"

child_src = r'''
import ctypes, os, struct, sys, time, threading
k32 = ctypes.windll.kernel32
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]

def pipes():
    try:
        return set(os.listdir(r"\\.\pipe"))
    except Exception:
        return set()

before = pipes()
h = k32.LoadLibraryW(sys.argv[1])
if not h:
    print("LOAD FAIL gle=%d" % k32.GetLastError(), flush=True)
    raise SystemExit(1)
base = h
print("loaded base=0x%X" % base, flush=True)
e = struct.unpack_from("<I", ctypes.string_at(base + 0x3C, 4))[0]
entry_rva = struct.unpack_from("<I", ctypes.string_at(base + e + 24 + 0x10, 4))[0]
print("entry rva=0x%X" % entry_rva, flush=True)
entry = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                           ctypes.c_void_p)(base + entry_rva)

def pump():
    r = entry(base, 4, None)
    print("DllMain(4) returned %r" % r, flush=True)

t = threading.Thread(target=pump, daemon=True)
t.start()
for i in range(30):
    time.sleep(0.5)
    new = pipes() - before
    if new:
        print("NEW PIPES: %s" % sorted(new), flush=True)
        break
    if not t.is_alive():
        print("beacon thread ENDED without pipe", flush=True)
        break
print("alive=%s new=%s" % (t.is_alive(), sorted(pipes() - before)), flush=True)
time.sleep(20)
print("SURVIVED 20s", flush=True)
'''

open(CHILD, "w").write(child_src)

if __name__ == "__main__":
    p = subprocess.Popen([sys.executable, "-I", CHILD,
                          PUB + r"\extc2_test\extc2.x64.dll"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        out, _ = p.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        p.kill()
        out = p.stdout.read()
    txt = out.decode(errors="replace")
    print(txt)
    print("child exit code:", p.returncode)

# -*- coding: utf-8 -*-
"""kit2_sentinel.py - synth a probe wire: 20B skip + 14 sentinel-marked
fields (int i -> 0x10000+i, blob i -> 8B filled 0xC0+i). The INT3@0x1759
struct dump reveals the true field->slot mapping in one shot."""
import os
import struct
import subprocess
import sys
import time

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_st_c_" + STAMP
OUT = r"\\.\pipe\kit_st_o_" + STAMP

WIRE = b"\x00" * 20
FIELDS = []
for i in range(14):
    WIRE += struct.pack(">i", 0x10000 + i)      # sentinel len
    WIRE += bytes([0xC0 + i]) * 8               # marker blob
WIRE += struct.pack(">i", 0x7E1E77E1)           # entry sentinel
WIRE += struct.pack(">i", 8) + b"\xEE" * 8      # args pair
open(r"C:\Users\Public\bt_hello_kitfull_wire.bin", "wb").write(WIRE)
print("sentinel wire:", len(WIRE))

# child + parent scripts expect the same env; reuse the two-pipes pieces
p2 = subprocess.Popen([sys.executable, "-I", r"C:\Users\Public\kit2_parent2.py", CTRL, OUT],
                      cwd=r"C:\Users\Public", stdout=subprocess.PIPE,
                      stderr=subprocess.STDOUT)

CDB = r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\cdbX64.exe"
CMDS = r"C:\Users\Public\kit2_st_cmds.txt"
open(CMDS, "w").write(
    '.echo STOP; dq @rcx L6; db poi(@rcx) L48; '
    'db poi(@rsp+0x48) L10; db poi(@rsp+0x58) L10; '
    'db poi(@rsp+0x68) L10; db poi(@rsp+0x78) L10; qd\n')
OUTLOG = r"C:\Users\Public\kit2_st_out.txt"
env = dict(os.environ, KIT_WIRE_MODE="kitfull")
r = subprocess.run([CDB, "-cf", CMDS, "-logo", OUTLOG, "-y", "C:\\symbols",
                    sys.executable, "-I", r"C:\Users\Public\kit2_child.py", CTRL, OUT],
                   cwd=r"C:\Users\Public", capture_output=True, timeout=120,
                   stdin=subprocess.DEVNULL, env=env)
try:
    p2.kill()
except Exception:
    pass
d = open(OUTLOG, encoding="utf-8", errors="replace").read()
i = d.find("STOP")
print(d[i:i + 1800] if i > 0 else "not reached")

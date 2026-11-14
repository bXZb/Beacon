# -*- coding: utf-8 -*-
"""kit2_crashprobe.py - child under cdb FROM START (sxe av): the remapped
BOF crashes; the faulting IP identifies which kit function the slot really
hit - validating/correcting the 16-slot table order."""
import os
import subprocess
import sys
import time

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_cp_c_" + STAMP
OUT = r"\\.\pipe\kit_cp_o_" + STAMP

p2 = subprocess.Popen([sys.executable, "-I", r"C:\Users\Public\kit2_parent2.py", CTRL, OUT],
                      cwd=r"C:\Users\Public", stdout=subprocess.PIPE,
                      stderr=subprocess.STDOUT)

CDB = r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\cdbX64.exe"
CMDS = r"C:\Users\Public\kit2_cp_cmds.txt"
open(CMDS, "w").write(
    'sxe -c "!analyze -v; r; kv 8; qd" av\n'
    "g\n")
OUTLOG = r"C:\Users\Public\kit2_cp_out.txt"
r = subprocess.run([CDB, "-cf", CMDS, "-logo", OUTLOG, "-y", "C:\\symbols",
                    sys.executable, "-I", r"C:\Users\Public\kit2_child.py", CTRL, OUT],
                   cwd=r"C:\Users\Public", capture_output=True, timeout=120,
                   stdin=subprocess.DEVNULL)
print("cdb rc", r.returncode)
try:
    p2.kill()
except Exception:
    pass
d = open(OUTLOG, encoding="utf-8", errors="replace").read()
i = d.find("ExceptionAddress")
print(d[max(0, i - 200):i + 400] if i > 0 else "no crash captured; tail:")
if i < 0:
    print(d[-600:])

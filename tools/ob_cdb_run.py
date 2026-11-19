# -*- coding: utf-8 -*-
"""ob_cdb_run.py - launch the OpenBeacon loader child under cdb, catch the
fastfail, print the faulting stack."""
import subprocess
import sys
import time

CDB = (r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps"
       r"\cdbX64.exe")
PY = r"C:\Program Files\Python314\python.exe"
CHILD = r"C:\Users\Public\ob_child.py"
DLL = r"C:\Users\Public\openbeacon_x64.dll"

cmd = ("& '{cdb}' -g -G -c '.sxe 0xC0000005;.sxe 0xC0000409;g' '{py}' -I '{child}' '{dll}'"
       .format(cdb=CDB, py=PY, child=CHILD, dll=DLL))

p = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(50)
p.kill()
out = p.stdout.read().decode(errors="replace")
# show the crash region
lines = out.splitlines()
idx = next((i for i, l in enumerate(lines)
            if "C0000409" in l or "C0000005" in l or "ARGCHK" in l), 0)
for ln in lines[max(0, idx - 6):idx + 40]:
    print(ln[:170])

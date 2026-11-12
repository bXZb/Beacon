# -*- coding: utf-8 -*-
"""tpd_disasm2.py - disasm ntdll!TpDirectCallback with proper attach timing."""
import subprocess
import sys
import time

CDB = r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\cdbX64.exe"
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)"])
time.sleep(2)
r = subprocess.run([CDB, "-p", str(p.pid), "-c",
                    "lm m ntdll; .reload /f ntdll; x ntdll!TpDirect*; uf ntdll!TpDirectCallback; q"],
                   capture_output=True, timeout=900, cwd=r"C:\Users\Public")
p.kill()
t = r.stdout.decode("gbk", "replace")
open(r"C:\Users\Public\cdb_tpd3.log", "wb").write(r.stdout)
i = t.find("TpDirectCallback:")
if i < 0:
    i = t.find("TpDirect")
print(t[max(0, i - 200):i + 4200] if i >= 0 else t[-1000:])

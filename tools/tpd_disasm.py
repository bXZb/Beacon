# -*- coding: utf-8 -*-
"""tpd_disasm.py - disassemble ntdll!TpDirectCallback from a live process
to extract the TP_DIRECT.Callback offset and the call shape."""
import subprocess
import sys
import time
import os

CDB = r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\cdbX64.exe"

# launch a long-lived debuggee
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
time.sleep(2)

r = subprocess.run([CDB, "-p", str(p.pid), "-c",
                    ".symfix+;.reload /f ntdll; uf ntdll!TpDirectCallback; q"],
                   capture_output=True, timeout=600, cwd=r"C:\Users\Public")
p.kill()
t = r.stdout.decode("gbk", "replace")
open(r"C:\Users\Public\cdb_tpd2.log", "wb").write(r.stdout)
i = t.find("TpDirectCallback:")
print(t[i:i + 4000] if i >= 0 else t[-1200:])

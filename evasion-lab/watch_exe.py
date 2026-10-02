# -*- coding: utf-8 -*-
"""Watch a beacon EXE: process liveness + on-disk file, every 10s."""
import subprocess
import sys
import time
import os

exe = sys.argv[1]
p = subprocess.Popen([exe], cwd=os.path.dirname(exe))
print("pid:", p.pid, "start:", time.strftime("%H:%M:%S"), flush=True)
t0 = time.time()
while time.time() - t0 < 300:
    time.sleep(10)
    r = subprocess.run(["tasklist", "/FI", "PID eq %d" % p.pid],
                       capture_output=True)
    alive = str(p.pid).encode() in r.stdout
    exst = os.path.exists(exe)
    print("+%3ds alive=%s file=%s" % (int(time.time()-t0), alive, exst), flush=True)
    if not alive:
        print("DIED at", time.strftime("%H:%M:%S"), flush=True)
        break

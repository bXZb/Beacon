# -*- coding: utf-8 -*-
"""Dump SETTING_PROCINJ_* (43/44/45/52/16/41) from a live spawn beacon.

Finds the beacon image (the 0x48000 private MZ region with a full PE),
walks its .data for the `settings` pointer: the table itself lives in a
separate heap block; we locate it by signature (short-type entries with
known invariant pairs: idx0 type INT value == payload size-ish is unstable,
so instead: idx 43..45 are TYPE_SHORT with sane protection values 4/32/64,
idx 41 TYPE_SHORT 0/1, idx 45 TYPE_INT > 0). Scan all readable private RW
regions for a 128*16-byte aligned pattern matching those invariants at
fixed offsets 43*16 and 44*16.
"""
import ctypes
import struct
import sys

k32 = ctypes.windll.kernel32

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def walk(h):
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFEFFFF:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            addr += 0x1000
            continue
        yield mbi.BaseAddress or addr, mbi.RegionSize or 0x1000, mbi
        addr = (mbi.BaseAddress or addr) + (mbi.RegionSize or 0x1000)


def entry(data, idx):
    off = idx * 16
    if off + 16 > len(data):
        return None
    typ, = struct.unpack_from("<H", data, off)
    val, = struct.unpack_from("<Q", data, off + 8)
    return typ, val


def main(pid):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print("open failed")
        return
    candidates = 0
    for base, size, m in walk(h):
        if m.State != 0x1000 or (m.Protect & 0x100) or m.Protect in (0, 1):
            continue
        if size < 128 * 16 or size > 0x100000:
            continue
        data = read_mem(h, base, 128 * 16)
        if not data:
            continue
        e43, e44, e45, e41, e52 = (entry(data, i) for i in (43, 44, 45, 41, 52))
        if not all([e43, e44, e45, e41, e52]):
            continue
        # invariants: 43/44 short with protection codes {4,32,64}; 45 int >= 0;
        # 41 short in {0,1}; 52 short in {0,1}
        if (e43[0] == 2 and e44[0] == 2 and e43[1] in (4, 32, 64) and e44[1] in (4, 32, 64)
                and e45[0] == 1 and e41[0] == 2 and e41[1] in (0, 1, 2)
                and e52[0] == 2 and e52[1] in (0, 1)):
            candidates += 1
            print("settings table @ 0x%x" % base)
            for name, idx in [("41 GARGLE_NOOK", 41), ("43 PERMS_I", 43), ("44 PERMS", 44),
                              ("45 MINALLOC", 45), ("52 ALLOCATOR", 52), ("16 BOF_ALLOC", 16)]:
                t, v = entry(data, idx)
                print("  %s: type=%d value=%d (0x%x)" % (name, t, v, v))
    if not candidates:
        print("table not found")
    k32.CloseHandle(h)


if __name__ == "__main__":
    main(int(sys.argv[1]))

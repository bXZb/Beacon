# -*- coding: utf-8 -*-
r"""scan_v3_live.py - scan a live beacon process for the v3 synthetic-frame
stub prologue (55 48 89 E5 48 81 EC = push rbp; mov rbp,rsp; sub rsp,imm32)
in its private RX gate pages. Finding it proves the deployed gate serves
synthetic frames, not the direct fallback (4C 8B D1 B8 ... 0F 05)."""
import ctypes
import ctypes.wintypes as wt
import struct
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04

V3 = b"\x55\x48\x89\xE5\x48\x81\xEC"
DIRECT = b"\x4C\x8B\xD1\xB8"

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def main(pid):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    assert h, "OpenProcess failed %d" % ctypes.get_last_error()
    addr = 0
    v3_hits, direct_hits, rx_pages = [], [], 0
    mbi = MBI()
    buf = ctypes.create_string_buffer(0x20000)
    got = ctypes.c_size_t()
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in (PAGE_EXECUTE_READ, 0x10) and mbi.Type == 0x20000:
            rx_pages += 1
            base = mbi.BaseAddress
            size = mbi.RegionSize
            off = 0
            while off < size:
                chunk = min(0x20000, size - off)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, chunk, ctypes.byref(got)) and got.value:
                    data = buf.raw[:got.value]
                    i = data.find(V3)
                    while i >= 0:
                        # prologue is 7 bytes + imm32(4) -> the imm64 load sits at +11:
                        # 48 B8 <leave_gadget>. The imm32's low byte occupies +7 (a
                        # synth-size byte, NOT the loader - first scanner cut false-
                        # negatived every real stub by checking 48 B8 at +7)
                        if i + 19 <= len(data) and data[i + 11] == 0x48 and data[i + 12] == 0xB8:
                            gad = struct.unpack("<Q", data[i + 13:i + 21])[0]
                            v3_hits.append((base + off + i, gad))
                        i = data.find(V3, i + 1)
                    j = data.find(DIRECT)
                    while j >= 0:
                        if j + 12 <= len(data) and data[j + 8:j + 12] != b"\xFF\x25\x00\x00":
                            direct_hits.append(base + off + j)
                        j = data.find(DIRECT, j + 1)
                off += chunk
        addr = (mbi.BaseAddress or 0) + mbi.RegionSize
        if mbi.RegionSize == 0:
            break
    print("scan pid=%d rx_private_pages=%d" % (pid, rx_pages))
    print("v3 stub prologues found: %d" % len(v3_hits))
    for a, g in v3_hits[:8]:
        print("  stub @ %#x -> leave_gadget %#x" % (a, g))
    # leave gadget must land inside ntdll's range (0x7FF8... typical ASLR high range)
    ntdll_ok = all(0x7FF000000000 <= g < 0x7FFF00000000 for _, g in v3_hits if g)
    print("all embedded gadgets in module range:", ntdll_ok)
    print("direct-stub 4C8BD1B8 hits (unbacked pages, may include benign):", len(direct_hits))
    print("V3_LIVE_DEPLOYED" if v3_hits and ntdll_ok else "V3_NOT_FOUND")


if __name__ == "__main__":
    main(int(sys.argv[1]))

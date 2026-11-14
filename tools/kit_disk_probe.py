# -*- coding: utf-8 -*-
"""kit_disk_probe2.py - CreateFileW-to-disk spawner probe (bypass the CTRL
pipe). jmp-hook at 0x3f00, sub rsp,0x30 (entry rsp==0 mod 16, preserved).
Writes {magic, rbx} to C:\\Users\\Public\\spawn_probe.bin via the kit IAT
(CreateFileW@0x32150, WriteFile@0x32158). Displaced mov re-emitted, jmp back
to 0x3f05. Path string embedded after the stub in the freed zone."""
import struct

CLEAN = r"C:\Users\Public\kit_async.x64.dll"
OUT = r"C:\Users\Public\kit_async_logged.x64.dll"
PATH = "C:\\s.bin"
S = 0x16a0
ZONE_END = 0x1733


def off(rva):
    return rva - 0x1000 + 0x400


def build():
    d = bytearray(open(CLEAN, "rb").read())
    # keep the executor skip patch (frees the zone)
    skip = bytes.fromhex("4883474814") + bytes.fromhex("836f5014")
    skip += b"\xe9" + struct.pack("<i", 0x1733 - (0x1692 + len(skip) + 5))
    d[off(0x1692): off(0x1692) + len(skip)] = skip

    parts = []
    parts.append(bytes.fromhex("4989db"))          # 3  mov r11, rbx
    parts.append(bytes.fromhex("4883ec30"))        # 4  sub rsp,0x30
    parts.append(b"\x48\xb8" + b"SPWNDISK")        # 10 mov rax, magic
    parts.append(bytes.fromhex("4889442418"))      # 5  [rsp+0x18]=magic
    parts.append(bytes.fromhex("4c895c2420"))      # 5  [rsp+0x20]=r11
    lea_pos = S + sum(len(p) for p in parts)
    parts.append(b"\x48\x8d\x0d" + struct.pack("<i", 0))   # 7 lea rcx,[rip+0] placeholder
    parts.append(bytes.fromhex("ba00000040"))      # 5  edx=GENERIC_WRITE
    parts.append(bytes.fromhex("4531c0"))          # 3  r8d=0
    parts.append(bytes.fromhex("4531c9"))          # 3  r9d=0
    parts.append(bytes.fromhex("48c7042402000000"))  # 8 [rsp]=2 CREATE_ALWAYS
    parts.append(bytes.fromhex("48c744240880000000"))  # 8 [rsp+8]=0x80
    parts.append(bytes.fromhex("48c744241000000000"))  # 8 [rsp+0x10]=0
    c1 = S + sum(len(p) for p in parts)
    parts.append(b"\xff\x15" + struct.pack("<i", 0x32150 - (c1 + 6)))  # CreateFileW
    parts.append(bytes.fromhex("4889c1"))          # 3  rcx=rax (handle)
    parts.append(bytes.fromhex("488d542418"))      # 5  rdx=[rsp+0x18] buf
    parts.append(bytes.fromhex("41b810000000"))    # 6  r8d=16
    parts.append(bytes.fromhex("4531c9"))          # 3  r9d=0
    parts.append(bytes.fromhex("48c7042400000000"))  # 8 [rsp]=0 lpOverlapped
    c2 = S + sum(len(p) for p in parts)
    parts.append(b"\xff\x15" + struct.pack("<i", 0x32158 - (c2 + 6)))  # WriteFile
    parts.append(bytes.fromhex("4883c430"))        # 4  add rsp,0x30
    t = S + sum(len(p) for p in parts)
    parts.append(bytes.fromhex("48895c2410"))      # 5  displaced: mov [rsp+0x10],rbx
    parts.append(b"\xe9" + struct.pack("<i", 0x3f05 - (t + 5 + 5)))  # 5 jmp 0x3f05
    stub = b"".join(parts)

    path_rva = S + len(stub) + 2
    wpath = PATH.encode("utf-16-le") + b"\x00\x00"
    assert path_rva + len(wpath) <= ZONE_END, (hex(path_rva), len(wpath))
    # patch the lea disp now that positions are known
    stub = bytearray(stub)
    struct.pack_into("<i", stub, lea_pos - S + 3, path_rva - (lea_pos + 7))
    stub = bytes(stub)

    d[off(S): off(S) + len(stub)] = stub
    d[off(path_rva): off(path_rva) + len(wpath)] = wpath
    d[off(0x3f00): off(0x3f00) + 5] = b"\xe9" + struct.pack("<i", S - 0x3f05)
    open(OUT, "wb").write(bytes(d))
    print("stub %dB at 0x%x, path at 0x%x (%dB)" % (len(stub), S, path_rva, len(wpath)))


if __name__ == "__main__":
    build()

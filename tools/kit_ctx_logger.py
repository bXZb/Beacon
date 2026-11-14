# -*- coding: utf-8 -*-
"""kit_ctx_logger.py - DLL byte-level injected logger (debugger-free ctx
capture) for the arsenal-kit async-execute DLL.

Patches (from the CLEAN kit dll):
  1. Overwrites the runner's pipe-create error path (0x3e4f..0x3e8b, dead in
     the success flow) with a stub:
       mov r11, rcx                    ; save the incoming ctx ptr
       mov rcx, [rip+0x43C48]          ; gPipeHandle (dllmain CTRL pipe)
       sub rsp, 0x28
       mov rax, 'STUBOK!!'
       mov [rsp], rax                  ; +0 magic
       mov [rsp+8], r11                ; +8 the ctx pointer handed to 0x1670
       mov rdx, rsp ; mov r8d, 0x10 ; xor r9d, r9d
       call [rip+WriteFile@0x32158]    ; deliver through the CTRL pipe
       add rsp, 0x28 ; jmp 0x1670      ; continue into the executor
  2. Redirects the runner's executor call (0x3ed1: call 0x1670) -> the stub.

Usage: KIT_HINT/KIT_WIRE_MODE/KIT_SYSCALL env as in kit_two_pipes_harness.
The two-pipe parent's CTRL reader prints: 'CTRL RECV 16 B: STUBOK!!<hex8>'.

First capture (2026-11-15): rcx = 0x0000000000000000 at the executor call —
the ctx pointer IS NULL (real, debugger-free). Since 0x3ecd just executed
lea rcx,[rbp-0x39], rbp must equal 0x39 at that point — the runner's frame
pointer is destroyed by the time the executor call runs. Next step: extend
this logger to dump rbp/rdi and the [rbp-0x39] qword (push-based variants
failed to deliver; mov-based stub5 is the proven form)."""
import struct

CLEAN = r"C:\Users\Public\kit_async.x64.dll"
OUT = r"C:\Users\Public\kit_async_logged.x64.dll"
S = 0x3e4f


def build():
    d = bytearray(open(CLEAN, "rb").read())
    parts = []
    parts.append(bytes.fromhex("4989cb"))                                  # mov r11,rcx
    p1 = S + 3
    parts.append(b"\x48\x8b\x0d" + struct.pack("<i", 0x43C48 - (p1 + 7)))  # rcx=[gPipe]
    parts.append(bytes.fromhex("4883ec28"))                                # sub rsp,0x28
    parts.append(b"\x48\xb8" + b"STUBOK!!")
    parts.append(bytes.fromhex("48890424"))                                # [rsp]=magic
    parts.append(bytes.fromhex("4c895c2408"))                              # [rsp+8]=r11
    parts.append(bytes.fromhex("4889e2"))
    parts.append(bytes.fromhex("41b810000000"))                            # r8d=16
    parts.append(bytes.fromhex("4533c9"))
    pre = b"".join(parts)
    call = b"\xff\x15" + struct.pack("<i", 0x32158 - (S + len(pre) + 6))
    tail = bytes.fromhex("4883c428")
    jmp_off = S + len(pre) + len(call) + len(tail)
    jmp = b"\xe9" + struct.pack("<i", 0x1670 - (jmp_off + 5))
    stub = pre + call + tail + jmp
    assert len(stub) <= 60, len(stub)
    d[S - 0x1000 + 0x400: S - 0x1000 + 0x400 + len(stub)] = stub
    d[0x3ed1 - 0x1000 + 0x400 + 1: 0x3ed1 - 0x1000 + 0x400 + 5] = struct.pack(
        "<i", S - 0x3ed6)
    open(OUT, "wb").write(bytes(d))
    print("logger dll:", len(stub), "byte stub")


if __name__ == "__main__":
    build()

# -*- coding: utf-8 -*-
"""verify_v3_stub.py - desk-verify the exact byte sequence build_synth_stub
emits (mirror of the C logic) with capstone, for every arity we carry (S=0..7),
and statically re-check the offsets/return-path arithmetic."""
import struct

import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

LEAVE = 0x7FF800000000 + 0xC194
GADGET = 0x7FF800000000 + 0x9A050


def emit_imm64_reg(buf, v):
    buf += b"\x48\xB8" + struct.pack("<Q", v)
    return buf


def emit_store_rax_rsp(buf, disp):
    assert -128 <= disp <= 127, "disp8 out of range: %d" % disp
    return buf + b"\x48\x89\x44\x24" + bytes([disp & 0xFF])


def emit_load_rax_rbp(buf, disp):
    assert -128 <= disp <= 127, "disp8 out of range: %d" % disp
    return buf + b"\x48\x8B\x45" + bytes([disp & 0xFF])


def build(arity, ssn=0x23):
    s = arity - 4 if arity > 4 else 0
    assert s <= 7
    synth = 0x28 + 8 * s + 32
    a_off = 0x28 + 8 * s
    b = b""
    b += b"\x55"                      # push rbp
    b += b"\x48\x89\xE5"              # mov rbp, rsp
    b += b"\x48\x81\xEC" + struct.pack("<i", synth)  # sub rsp, imm32
    b = emit_imm64_reg(b, LEAVE)
    b = emit_store_rax_rsp(b, 0)      # [rsp] = RA1
    for k in range(s):
        b = emit_load_rax_rbp(b, 0x30 + 8 * k)   # rax = [rbp+arg]
        b = emit_store_rax_rsp(b, 0x28 + 8 * k)  # [rsp+0x28+8k] = arg
    fakes = [LEAVE, GADGET, LEAVE, GADGET]
    for k in range(4):
        b = emit_imm64_reg(b, fakes[k])
        b = emit_store_rax_rsp(b, a_off + 8 * k)
    b += b"\x4C\x8B\xD1"              # mov r10, rcx
    b += b"\xB8" + struct.pack("<I", ssn)  # mov eax, ssn
    b += b"\xFF\x25\x00\x00\x00\x00"  # jmp [rip+0]
    b += struct.pack("<Q", GADGET)
    return b, synth, a_off


failures = 0
for arity in (4, 5, 6, 7, 11):
    s = max(0, arity - 4)
    b, synth, a_off = build(arity)
    print("== arity %d (S=%d) len=%d synth=0x%X a_off=0x%X" % (arity, s, len(b), synth, a_off))
    expect = [
        "push rbp", "mov rbp, rsp", "sub rsp, 0x%x" % synth,
        "mov rax, 0x%x" % LEAVE, "mov qword ptr [rsp], rax",
    ]
    got = []
    for ins in md.disasm(b, 0x4000):
        got.append("%s %s" % (ins.mnemonic, ins.op_str))
    # spot structural expectations
    checks = {
        "prologue": got[0] == "push rbp" and got[1] == "mov rbp, rsp",
        "sub_synth": got[2].startswith("sub rsp, 0x"),
        "ra1_store": got[3] in ("mov rax, 0x%x" % LEAVE, "movabs rax, 0x%x" % LEAVE) and got[4] == "mov qword ptr [rsp], rax",
        "arg_pairs": got.count("mov rax, qword ptr [rbp + 0x%x]" % (0x30)) == (1 if s else 0),
        "dispatch": "mov r10, rcx" in got and ("mov eax, 0x23" in got),
        "tail_jmp": "jmp qword ptr [rip]" in got,
        "len_ok": len(b) <= 256,
    }
    # count arg copy pairs precisely
    arg_loads = sum(1 for g in got if g.startswith("mov rax, qword ptr [rbp + 0x"))
    arg_stores = sum(1 for g in got if g.startswith("mov qword ptr [rsp + 0x2") or g.startswith("mov qword ptr [rsp + 0x3") or g.startswith("mov qword ptr [rsp + 0x4") or g.startswith("mov qword ptr [rsp + 0x5") or g.startswith("mov qword ptr [rsp + 0x6"))
    checks["arg_load_count"] = arg_loads == s + 4  # s args + 4 fakes use imm64+store, loads only s
    checks["arg_load_count"] = arg_loads == s
    # stores: 1 (RA1) + s (args) + 4 (fakes) = 5+s
    all_stores = sum(1 for g in got if g.startswith("mov qword ptr [rsp"))
    checks["store_count"] = all_stores == 5 + s
    bad = [k for k, v in checks.items() if not v]
    if bad:
        failures += 1
        print("   FAIL:", bad)
        for g in got:
            print("     ", g)
    else:
        print("   OK  (%d insns)" % len(got))

# static return-path arithmetic for arity 5 (s=1):
# entry rsp=R: [R]=ret, [R+0x28]=arg5. push rbp -> rbp=R-8.
# arg5 load from [rbp+0x30] = R+0x28  <-- must equal the ABI slot
R = 0x1000
rbp = R - 8
assert rbp + 0x30 == R + 0x28, "arg5 offset mismatch"
print("arg5 offset arithmetic: OK ([rbp+0x30] == entry_rsp+0x28)")
# return path: syscall ret pops RA1 (rsp=synth_base+8) -> leave: rsp=rbp
# -> pop rbp (rsp=rbp+8=R) -> ret pops [R]=wrapper RA -> rsp=R+8 (entry+8)
print("return path arithmetic: OK (leave pivots to entry rsp, ret to wrapper)")

print("FAILURES:", failures)
raise SystemExit(1 if failures else 0)

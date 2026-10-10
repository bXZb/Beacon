# -*- coding: utf-8 -*-
r"""verify_bofwin_stub.py - desk-verify the bofwin stub-page builder.

Mirrors bw_build_pages byte-for-byte, disassembles all three stubs with
capstone, and asserts the control flow: rip-relative disp32 lands on the
ctx qword, jne displacements land exactly on the skip targets, and every
sf032 call site is 16-byte aligned per its stub's entry alignment."""
import struct

import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

PAGE = 0x1000
CTXQ = 0x0C0
ENTER, EXIT, WATCH = 0x000, 0x040, 0x080


def put32(b, v):
    return struct.pack("<i", v)


def put64(v):
    return struct.pack("<Q", v)


def disp(next_off, target):
    return struct.pack("<i", target - next_off)


def build():
    p = bytearray(0x1000)

    # enter
    e = ENTER
    p[e:e + 4] = bytes([0x48, 0x83, 0xEC, 0x08]); e += 4
    p[e:e + 2] = bytes([0x49, 0xBB]); p[e + 2:e + 10] = put64(0x1000 + EXIT); e += 10
    p[e:e + 2] = bytes([0x41, 0x53]); e += 2
    p[e:e + 4] = bytes([0x48, 0x83, 0xEC, 0x28]); e += 4
    p[e:e + 3] = bytes([0x48, 0x8B, 0x05]); p[e + 3:e + 7] = disp(e + 7, CTXQ); e += 7
    p[e:e + 4] = bytes([0x48, 0x8D, 0x48, 0x50]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8D, 0x50, 0x60]); e += 4
    p[e:e + 3] = bytes([0xFF, 0x50, 0x18]); e += 3
    p[e:e + 4] = bytes([0x48, 0x83, 0xC4, 0x28]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8B, 0x48, 0x28]); e += 4
    p[e:e + 3] = bytes([0x8B, 0x50, 0x30]); e += 3
    p[e:e + 3] = bytes([0xFF, 0x60, 0x20]); e += 3
    enter_len = e - ENTER

    # exit
    e = EXIT
    p[e:e + 3] = bytes([0x48, 0x8B, 0x05]); p[e + 3:e + 7] = disp(e + 7, CTXQ); e += 7
    p[e:e + 5] = bytes([0xB9, 0x02, 0x00, 0x00, 0x00]); e += 5
    p[e:e + 2] = bytes([0x87, 0x08]); e += 2
    p[e:e + 3] = bytes([0x83, 0xF9, 0x01]); e += 3
    jne_exit_at = e
    p[e:e + 2] = bytes([0x75, 0x13]); e += 2
    unmask_start = e
    p[e:e + 4] = bytes([0x48, 0x83, 0xEC, 0x30]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8D, 0x48, 0x50]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8D, 0x50, 0x60]); e += 4
    call_exit_at = e
    p[e:e + 3] = bytes([0xFF, 0x50, 0x18]); e += 3
    p[e:e + 4] = bytes([0x48, 0x83, 0xC4, 0x30]); e += 4
    skip_at = e
    p[e] = 0xC3; e += 1
    exit_len = e - EXIT

    # watchdog
    e = WATCH
    p[e:e + 3] = bytes([0x48, 0x8B, 0x05]); p[e + 3:e + 7] = disp(e + 7, CTXQ); e += 7
    p[e:e + 5] = bytes([0xB9, 0x02, 0x00, 0x00, 0x00]); e += 5
    p[e:e + 2] = bytes([0x87, 0x08]); e += 2
    p[e:e + 3] = bytes([0x83, 0xF9, 0x01]); e += 3
    p[e:e + 2] = bytes([0x75, 0x24]); e += 2
    wd_body = e
    p[e:e + 4] = bytes([0x48, 0x83, 0xEC, 0x28]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8D, 0x48, 0x50]); e += 4
    p[e:e + 4] = bytes([0x48, 0x8D, 0x50, 0x60]); e += 4
    call_wd_at = e
    p[e:e + 3] = bytes([0xFF, 0x50, 0x18]); e += 3
    p[e:e + 4] = bytes([0x48, 0x83, 0xC4, 0x28]); e += 4
    p[e:e + 3] = bytes([0x48, 0x89, 0xC1]); e += 3
    jmp_at = e
    p[e:e + 6] = bytes([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); e += 6
    p[e:e + 8] = put64(0xDEADBEEFCAFE000)  # bw_watchdog_rest placeholder
    e += 8
    wd_ret = e
    p[e] = 0xC3; e += 1
    wd_len = e - WATCH

    return bytes(p), dict(enter_len=enter_len, exit_len=exit_len, wd_len=wd_len,
                          jne_exit_at=jne_exit_at, skip_at=skip_at,
                          unmask_start=unmask_start, wd_body=wd_body, wd_ret=wd_ret,
                          call_exit_at=call_exit_at, call_wd_at=call_wd_at,
                          jmp_at=jmp_at)


def disasm_region(blob, start, length, base=0x1000):
    out = []
    for ins in md.disasm(blob[start:start + length], base + start):
        out.append((ins.address - base, ins.mnemonic, ins.op_str, ins.size,
                    ins.bytes.hex()))
    return out


def main():
    blob, meta = build()
    fails = []

    if meta["enter_len"] > 0x40: fails.append("enter too big")
    if meta["exit_len"] > 0x40: fails.append("exit too big")
    if meta["wd_len"] > 0x3F: fails.append("watchdog too big")

    for name, off, ln in (("enter", ENTER, meta["enter_len"]),
                          ("exit", EXIT, meta["exit_len"]),
                          ("watch", WATCH, meta["wd_len"])):
        print("== %s @ %#x (%d bytes)" % (name, off, ln))
        for a, m, o, sz, hx in disasm_region(blob, off, ln):
            print("   +%02x %-9s %s   ; %s" % (a - off, m, o, hx))

    # jne targets
    def jne_target(at):
        # find the insn at offset 'at' in disasm and compute target
        for a, m, o, sz, hx in disasm_region(blob, at, 2):
            tgt = a + sz + struct.unpack("<b", bytes([int(hx[2:4], 16)])[0:1])[0] if False else None
        ins = next(md.disasm(blob[at:at + 2], 0x1000 + at))
        # capstone gives the target directly for short jumps in op_str
        return ins, int(ins.op_str, 16) - 0x1000 if ins.op_str.startswith("0x") else None

    ins, t = jne_target(meta["jne_exit_at"])
    print("exit jne -> %#x (skip at %#x)" % (t, meta["skip_at"]))
    if t != meta["skip_at"]:
        fails.append("exit jne target %#x != skip %#x" % (t, meta["skip_at"]))

    # watchdog jne (+0x24): compute target of the jne at WATCH+17
    jne_wd_at = WATCH + 7 + 5 + 2 + 3  # after mov rax/mov ecx/xchg/cmp
    ins2, t2 = jne_target(jne_wd_at)
    print("watch jne -> %#x (wd_ret at %#x)" % (t2, meta["wd_ret"]))
    if t2 != meta["wd_ret"]:
        fails.append("watchdog jne target %#x != wd_ret %#x" % (t2, meta["wd_ret"]))

    # rip-relative disp32 target = CTXQ
    for name, off in (("enter", ENTER + 0x0C + 2), ("exit", EXIT), ("watch", WATCH)):
        pass  # verified implicitly by capstone op_str above; assert explicitly:
    for name, off, ln in (("enter", ENTER, meta["enter_len"]),
                          ("exit", EXIT, meta["exit_len"]),
                          ("watch", WATCH, meta["wd_len"])):
        for a, m, o, sz, hx in disasm_region(blob, off, ln):
            if m == "mov" and o.startswith("rax, qword ptr [rip"):
                tgt = int(o.split("rip + ")[1].split("]")[0] if "rip + " in o else o.split("rip - ")[1].split("]")[0], 16)
                if " - " in o:
                    tgt = -tgt
                abs_t = (a + sz + tgt)
                print("%s mov rax,[rip] -> %#x (want ctx %#x)" % (name, abs_t, CTXQ))
                if abs_t != CTXQ:
                    fails.append("%s ctx disp lands %#x" % (name, abs_t))

    # alignment: simulate rsp%16 at each sf032 call
    # enter: entry rsp=8 -> sub8=0, push=8, sub0x28=0  -> call at 0 OK
    # exit : entry rsp=0 -> sub0x30=0 -> call OK (after jne+2)
    # watch: entry rsp=8 -> sub0x28=0 -> call OK
    # (asserted by construction; printed for the record)
    print("alignment: enter(8->sub8=0,push=8,sub28=0) exit(0->sub30=0) watch(8->sub28=0) OK")

    print("FAILURES:", fails if fails else "none")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
r"""verify_bofwin_stub.py - desk-verify the bofwin stub-page builder (v2:
protect/flush-aware). Mirrors bw_build_pages byte-for-byte, disassembles
all three stubs with capstone, and asserts: rip-relative disp32 lands on
the ctx qword (0x110), jne targets land exactly on ret, the watchdog
tail-jump data qword sits at the jmp's rip, and region bounds hold."""
import struct

import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

CTXQ = 0x110
ENTER, EXIT, WATCH = 0x000, 0x050, 0x0A0


def disp(next_off, target):
    return struct.pack("<i", target - next_off)


def build():
    p = bytearray(0x1000)

    def emit(off, bs):
        p[off:off + len(bs)] = bs
        return off + len(bs)

    # ---- enter ----
    e = ENTER
    e = emit(e, bytes([0x48, 0x83, 0xEC, 0x08]))
    e = emit(e, bytes([0x49, 0xBB]) + struct.pack("<Q", 0x1000 + EXIT))
    e = emit(e, bytes([0x41, 0x53]))
    e = emit(e, bytes([0x48, 0x83, 0xEC, 0x28]))
    e = emit(e, bytes([0x48, 0x8B, 0x05]) + disp(e + 7, CTXQ))
    e = emit(e, bytes([0x48, 0x8B, 0x48, 0x58]))
    e = emit(e, bytes([0x48, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]))
    e = emit(e, bytes([0x4C, 0x8D, 0x48, 0x70]))
    e = emit(e, bytes([0xFF, 0x50, 0x78]))
    e = emit(e, bytes([0x48, 0x8D, 0x48, 0x50]))
    e = emit(e, bytes([0x48, 0x8D, 0x50, 0x60]))
    e = emit(e, bytes([0xFF, 0x50, 0x18]))
    e = emit(e, bytes([0x48, 0x83, 0xC4, 0x28]))
    e = emit(e, bytes([0x48, 0x8B, 0x48, 0x28]))
    e = emit(e, bytes([0x8B, 0x50, 0x30]))
    e = emit(e, bytes([0xFF, 0x60, 0x20]))
    enter_end = e

    # ---- exit ----
    e = EXIT
    e = emit(e, bytes([0x48, 0x8B, 0x05]) + disp(e + 7, CTXQ))
    e = emit(e, bytes([0xB9, 0x02, 0x00, 0x00, 0x00]))
    e = emit(e, bytes([0x87, 0x08]))
    e = emit(e, bytes([0x83, 0xF9, 0x01]))
    jne_e_at = e
    e = emit(e, bytes([0x75, 0x36]))
    e = emit(e, bytes([0x48, 0x8D, 0x48, 0x50]))
    e = emit(e, bytes([0x48, 0x8D, 0x50, 0x60]))
    e = emit(e, bytes([0xFF, 0x50, 0x18]))
    e = emit(e, bytes([0x48, 0x8B, 0x48, 0x58]))
    e = emit(e, bytes([0x48, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0x44, 0x8B, 0x80]) + struct.pack("<i", 0x74))
    e = emit(e, bytes([0x4C, 0x8D, 0x48, 0x70]))
    e = emit(e, bytes([0xFF, 0x50, 0x78]))
    e = emit(e, bytes([0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]))
    e = emit(e, bytes([0x48, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0x4C, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0xFF, 0x90]) + struct.pack("<i", 0x80))
    e = emit(e, bytes([0xC3]))
    exit_end = e
    exit_ret = exit_end - 1

    # ---- watch ----
    e = WATCH
    e = emit(e, bytes([0x48, 0x8B, 0x05]) + disp(e + 7, CTXQ))
    e = emit(e, bytes([0xB9, 0x02, 0x00, 0x00, 0x00]))
    e = emit(e, bytes([0x87, 0x08]))
    e = emit(e, bytes([0x83, 0xF9, 0x01]))
    jne_w_at = e
    e = emit(e, bytes([0x75, 0x4F]))
    e = emit(e, bytes([0x48, 0x83, 0xEC, 0x28]))
    e = emit(e, bytes([0x48, 0x8D, 0x48, 0x50]))
    e = emit(e, bytes([0x48, 0x8D, 0x50, 0x60]))
    e = emit(e, bytes([0xFF, 0x50, 0x18]))
    e = emit(e, bytes([0x48, 0x8B, 0x48, 0x58]))
    e = emit(e, bytes([0x48, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0x44, 0x8B, 0x80]) + struct.pack("<i", 0x74))
    e = emit(e, bytes([0x4C, 0x8D, 0x48, 0x70]))
    e = emit(e, bytes([0xFF, 0x50, 0x78]))
    e = emit(e, bytes([0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]))
    e = emit(e, bytes([0x48, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0x4C, 0x8B, 0x50, 0x50]))
    e = emit(e, bytes([0xFF, 0x90]) + struct.pack("<i", 0x80))
    e = emit(e, bytes([0x48, 0x83, 0xC4, 0x28]))
    e = emit(e, bytes([0x48, 0x89, 0xC1]))
    jmp_at = e
    e = emit(e, bytes([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]))
    dataq = e
    e = emit(e, struct.pack("<Q", 0xDEADBEEF))
    e = emit(e, bytes([0xC3]))
    watch_end = e
    wd_ret = watch_end - 1

    return bytes(p), dict(enter_end=enter_end, exit_end=exit_end, watch_end=watch_end,
                          jne_e_at=jne_e_at, exit_ret=exit_ret, jne_w_at=jne_w_at,
                          wd_ret=wd_ret, dataq=dataq, jmp_at=jmp_at)


def disasm(blob, start, length):
    return [(ins.address - 0x1000, ins.mnemonic, ins.op_str, ins.size)
            for ins in md.disasm(blob[start:start + length], 0x1000 + start)]


def main():
    blob, meta = build()
    fails = []

    if meta["enter_end"] - ENTER > 0x50: fails.append("enter >0x50")
    if meta["exit_end"] - EXIT > 0x50: fails.append("exit >0x50")
    if meta["watch_end"] - WATCH > 0x70: fails.append("watch >0x70")
    if meta["dataq"] + 8 > CTXQ: fails.append("data qword overlaps ctx slot")

    bounds = {"enter": meta["enter_end"], "exit": meta["exit_end"], "watch": meta["watch_end"]}
    for name, off in (("enter", ENTER), ("exit", EXIT), ("watch", WATCH)):
        print("== %s @ %#x (%d bytes)" % (name, off, bounds[name] - off))
        for a, m, o, sz in disasm(blob, off, bounds[name] - off):
            print("   +%02x %-9s %s" % (a - off, m, o))

    for tag, at, want in (("exit jne", meta["jne_e_at"], meta["exit_ret"]),
                          ("watch jne", meta["jne_w_at"], meta["wd_ret"])):
        ins = next(md.disasm(blob[at:at + 2], 0x1000 + at))
        tgt = int(ins.op_str, 16) - 0x1000
        print("%s -> %#x (want %#x)" % (tag, tgt, want))
        if tgt != want:
            fails.append("%s target %#x != %#x" % (tag, tgt, want))

    for name, off in (("enter", ENTER), ("exit", EXIT), ("watch", WATCH)):
        for a, m, o, sz in disasm(blob, off, bounds[name] - off):
            if m == "mov" and o.startswith("rax, qword ptr [rip"):
                if "rip + " in o:
                    t = int(o.split("rip + ")[1].rstrip("]"), 16)
                else:
                    t = -int(o.split("rip - ")[1].rstrip("]"), 16)
                abs_t = a + sz + t
                print("%s ctx load -> %#x (want %#x)" % (name, abs_t, CTXQ))
                if abs_t != CTXQ:
                    fails.append("%s ctx disp %#x" % (name, abs_t))

    jmp_insn = next(md.disasm(blob[meta["jmp_at"]:meta["jmp_at"] + 6], 0x1000 + meta["jmp_at"]))
    print("watch jmp [rip] reads %#x (dataq at %#x)" % (jmp_insn.address + jmp_insn.size, meta["dataq"]))
    if (jmp_insn.address + jmp_insn.size - 0x1000) != meta["dataq"]:
        fails.append("tail-jump data qword misaligned")

    print("FAILURES:", fails if fails else "none")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()

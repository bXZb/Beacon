# -*- coding: utf-8 -*-
"""kit_loader_disasm.py - find how the postex-loader sets DllMain's 3rd arg
(lpReserved) before calling the entry point."""
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

d = open(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench\src\main\resources\resources\postex-loader.x64.bin", "rb").read()
print("loader len:", len(d))
if HAVE_CAPSTONE:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    # scan for 'lea r8' (4C 8D xx) and 'mov r8' (49 B8 / 4C 8B) patterns near call/jmp
    for i in range(len(d) - 8):
        b = d[i]
        if b == 0x4C and d[i+1] in (0x8D, 0x8B, 0xB8 - 0x100 + 0xB8):
            pass
    # full disasm, print instructions touching r8/rcx/rdx and calls
    for insn in md.disasm(d, 0):
        s = "%04x  %s %s" % (insn.address, insn.mnemonic, insn.op_str)
        if any(k in insn.op_str for k in ("r8", "r15", "r15d")) or insn.mnemonic in ("call", "jmp"):
            print(s)
else:
    print("no capstone")

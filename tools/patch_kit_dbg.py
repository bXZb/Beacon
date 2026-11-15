# -*- coding: utf-8 -*-
"""patch_kit_dbg.py - switch kit_dbg_run.py to int3+r/g script mode."""
import io

P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\kit_dbg_run.py"
s = io.open(P, encoding="utf-8").read()

old = 'with open(r"C:\\Users\\Public\\kit_dbg_base.txt", "w") as f:\n    f.write("0x%x" % (kb or 0))\nprint("kitbase 0x%x" % (kb or 0), flush=True)\nif kb:\n    while not os.path.exists(r"C:\\Users\\Public\\kit_dbg_go.txt"):\n        time.sleep(0.2)'
new = ('with open(r"C:\\Users\\Public\\kit_dbg_base.txt", "w") as f:\n'
       '    f.write("0x%x" % (kb or 0))\n'
       'print("kitbase 0x%x" % (kb or 0), flush=True)\n'
       'if kb:\n'
       '    # int3 traps at all post-gate sites (kit image is RWX under our loader)\n'
       '    SITES = [0x4175, 0xe72e, 0x4223, 0x4247, 0x427b, 0x428c, 0x4291, 0x3B70]\n'
       '    got = ctypes.c_size_t(0)\n'
       '    for rva in SITES:\n'
       '        cc = b"\\xCC"\n'
       '        k32.WriteProcessMemory(h, ctypes.c_void_p(kb + rva), cc, 1,\n'
       '                               ctypes.byref(got))\n'
       '    print("int3 traps armed", flush=True)\n'
       '    while not os.path.exists(r"C:\\Users\\Public\\kit_dbg_go.txt"):\n'
       '        time.sleep(0.2)')
assert old in s, "child base-write block not found"
s = s.replace(old, new)

old2_start = s.index('    cmds = [')
old2_end = s.index('    open(PUB + r"\\kit_dbg_cmds.txt", "w")')
new2 = ('    # pure r/g script: cdb -cf lines execute as if typed; each g blocks\n'
        '    # until the next break event. 9 breaks expected: attach + 8 int3 sites.\n'
        '    cmds = (["r", "g"] + ["r", "g"] * 8 + ["g", "g", "g", "g"])\n\n')
s = s[:old2_start] + new2 + s[old2_end:]

old3 = '''    keep = [ln for ln in log.splitlines()
            if any(k in ln for k in ("RTS", "MAIN", "POST_GATE", "R_57",
                                     "R_55", "R_56", "RESUME", "DOOR",
                                     "TAIL", "WIN", "flag", "kitbase",
                                     "Breakpoint", "error", "rcx=", "rax="))]
    print("\\n".join(keep[-80:]))'''
new3 = '''    lines = log.splitlines()
    try:
        idx = next(i for i, ln in enumerate(lines)
                   if "Break instruction exception" in ln)
    except StopIteration:
        idx = 0
    print("\\n".join(lines[idx:idx + 220]))'''
assert old3 in s, "filter block not found"
s = s.replace(old3, new3)

io.open(P, "w", encoding="utf-8", newline="").write(s)
print("rig updated to int3+script mode")

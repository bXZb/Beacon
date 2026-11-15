# -*- coding: utf-8 -*-
"""patch_probe_v3.py - reconnect OUT after follow-up dispatch."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\tools\kit_bg_probe.py")
s = io.open(P, encoding="utf-8").read()

old = ('    # send the [z][b] follow-up frame over CTRL (official bg frame)\n'
       '    if hc:\n'
       '        FOLLOW = L(OUT.encode() + b"\\x00") + L(WIRE)\n'
       '        wr = wintypes.DWORD(0)\n'
       '        ok = k32.WriteFile(hc, FOLLOW, len(FOLLOW), ctypes.byref(wr), None)\n'
       '        print("follow-up [z][b] sent to CTRL:", bool(ok), wr.value,\n'
       '              flush=True)\n'
       '    for t in (5, 15):\n'
       '        time.sleep(t)\n'
       '        observe(kitbase, ho, hc, "T+%d" % (t + (0 if t == 5 else 15)))\n'
       '    print("DONE", flush=True)')
new = ('    # send the [z][b] follow-up frame over CTRL (official bg frame);\n'
       '    # the follow-up job\'s runner creates a NEW OUT pipe instance and\n'
       '    # blocks in ConnectNamedPipe until a client connects again\n'
       '    if hc:\n'
       '        FOLLOW = L(OUT.encode() + b"\\x00") + L(WIRE)\n'
       '        wr = wintypes.DWORD(0)\n'
       '        ok = k32.WriteFile(hc, FOLLOW, len(FOLLOW), ctypes.byref(wr), None)\n'
       '        print("follow-up [z][b] sent to CTRL:", bool(ok), wr.value,\n'
       '              flush=True)\n'
       '        time.sleep(2)\n'
       '        ho2 = connect_pipe(OUT, 30)\n'
       '        print("out reconnected (2nd client):", bool(ho2), flush=True)\n'
       '        if ho2:\n'
       '            drain_pipe(ho2, "OUT2")\n'
       '            time.sleep(2)\n'
       '            drain_pipe(ho2, "OUT2b")\n'
       '    observe(kitbase, ho, hc, "T+final")\n'
       '    print("DONE", flush=True)')
assert old in s, "main block not found"
s = s.replace(old, new)
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("probe v3 ok")

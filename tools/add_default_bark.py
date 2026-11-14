# -*- coding: utf-8 -*-
"""add_default_bark.py - inject dispatch: unknown technique opcodes bark
loudly (post_error 0x5f) instead of silently skipping (C-26). File is CRLF."""
P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\src\inject.cpp"
s = open(P, "rb").read()
old = (b"\t\t\t\tbreak;\r\n\t\t}\r\n\t}\r\n\r\n\treturn FALSE;\r\n}")
n = s.count(old)
print("count:", n)
assert n == 1, "expected 1 occurrence, got %d" % n
new = (b"\t\t\t\tbreak;\r\n"
       b"\r\n"
       b"\t\t\tdefault:\r\n"
       b"\t\t\t\t/* C-26 build identity: an opcode this build does not know means\r\n"
       b"\t\t\t\t * the TS profile is newer than the running beacon (the stale-slot\r\n"
       b"\t\t\t\t * class - the old build silently skipped unknown techniques and a\r\n"
       b"\t\t\t\t * test cycle burned on a misdiagnosis). Bark loudly. */\r\n"
       b"\t\t\t\tpost_error_d(0x5f, opcode);\r\n"
       b"\t\t\t\tbreak;\r\n"
       b"\t\t}\r\n"
       b"\t}\r\n"
       b"\r\n"
       b"\treturn FALSE;\r\n")
s = s.replace(old, new)
open(P, "wb").write(s)
print("default bark installed")

# -*- coding: utf-8 -*-
"""debug_bark.py - find why the dispatch-tail pattern doesn't match."""
P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\src\inject.cpp"
s = open(P, "rb").read()
print("file len:", len(s))
for probe, name in [
    (b"break;\n\t\t}\n\t}\n\n\treturn FALSE;", "break..returnFALSE"),
    (b"break;\n\t\t}\n\t}\n", "break..closeclose"),
    (b"\t\t}\n\t}\n\n\treturn FALSE;\n}", "closeclose..return"),
    (b"\t\t\t\tbreak;", "deepbreak"),
    (b"NTQUEUEAPCTHREAD_S:", "case name"),
]:
    print(name, "->", s.count(probe))
i = s.find(b"NTQUEUEAPCTHREAD_S")
print("ctx around case:")
print(repr(s[i:i + 420]))

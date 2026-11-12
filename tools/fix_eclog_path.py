# -*- coding: utf-8 -*-
"""fix_eclog_path.py - escape the backslashes in the two eclog/CreateFileA
path literals (\\U \\P \\a were eaten as escapes: \\U->U, \\P->P, \\a->BEL)."""
P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp"
s = open(P, "rb").read()
old = b'"C:\\Users\\Public\\asyncdll_trace.txt"'
new = b'"C:\\\\Users\\\\Public\\\\asyncdll_trace.txt"'
n = s.count(old)
assert n == 2, "expected 2 occurrences, got %d" % n
s = s.replace(old, new)
open(P, "wb").write(s)
print("patched", n, "occurrences")

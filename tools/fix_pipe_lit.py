# -*- coding: utf-8 -*-
"""fix_pipe_lit.py - restore the proper C pipe-name literal in hotbeef.cpp.
The bash-heredoc patch stripped one backslash layer from the memcmp
argument; the correct C source literal for \\.\pipe\ is "\\\\.\\pipe\\"."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\src\hotbeef.cpp")
s = io.open(P, encoding="utf-8").read()

BS = chr(92)
# C source literal for \\.\pipe\ : quote + BS BS BS BS . BS pipe BS + quote
bad = '"' + BS * 1 + '.' + BS + 'pipe' + BS + '"'
good = '"' + BS * 4 + '.' + BS * 2 + 'pipe' + BS * 2 + '"'
n = s.count(bad)
print("bad occurrences:", n)
assert n == 2, "expected exactly 2 broken literals"
s = s.replace(bad, good)
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("fixed to:", good)

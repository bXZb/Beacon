# -*- coding: utf-8 -*-
"""fix_braces.py - close the C-36 nested blocks in hotbeef.cpp (both A2
paths got one brace short when the parameter-scan block was inserted)."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\feat-post-4.9.1\src\hotbeef.cpp")
s = io.open(P, encoding="utf-8").read()

# inject2 path: connect_pipe close is followed by the fpos-close; insert
# the missing C-36 block close between them.
old1 = ('					if (connect_pipe(pname, &ctrl_h)) {\n'
        '						pipe_track(ctrl_h, (DWORD)pid, CALLBACK_OUTPUT, desc, JOB_MODE_BYTE);\n'
        '						spawn_log("jsu: ctrl tracked inject2", 0x7fffffff);\n'
        '					}\n'
        '			}\n'
        '		}\n')
new1 = ('					if (connect_pipe(pname, &ctrl_h)) {\n'
        '						pipe_track(ctrl_h, (DWORD)pid, CALLBACK_OUTPUT, desc, JOB_MODE_BYTE);\n'
        '						spawn_log("jsu: ctrl tracked inject2", 0x7fffffff);\n'
        '					}\n'
        '				}\n'
        '			}\n'
        '		}\n')
assert old1 in s, "inject2 tail not found"
s = s.replace(old1, new1)

old2 = ('				Sleep(2000);\n'
        '				if (connect_pipe(pname, &ctrl_h)) {\n'
        '					pipe_track(ctrl_h, pi.dwProcessId, CALLBACK_OUTPUT, desc, JOB_MODE_BYTE);\n'
        '					spawn_log("jsu: ctrl tracked", 0x7fffffff);\n'
        '				}\n'
        '			else {\n'
        '				spawn_log("jsu: ctrl connect failed gle=", (long)GetLastError());\n'
        '			}\n'
        '		}\n'
        '	}\n')
new2 = ('				Sleep(2000);\n'
        '				if (connect_pipe(pname, &ctrl_h)) {\n'
        '					pipe_track(ctrl_h, pi.dwProcessId, CALLBACK_OUTPUT, desc, JOB_MODE_BYTE);\n'
        '					spawn_log("jsu: ctrl tracked", 0x7fffffff);\n'
        '				}\n'
        '				else {\n'
        '					spawn_log("jsu: ctrl connect failed gle=", (long)GetLastError());\n'
        '				}\n'
        '			}\n'
        '		}\n'
        '	}\n')
assert old2 in s, "fork&run tail not found"
s = s.replace(old2, new2)

io.open(P, "w", encoding="utf-8", newline="").write(s)

# verify brace balance over the whole file
depth = 0
line = 1
mind = 0
bad = []
in_str = False
in_chr = False
in_com = None
prev = ""
for ch in s:
    if ch == "\n":
        line += 1
    if in_com == "line":
        if ch == "\n":
            in_com = None
        prev = ch
        continue
    if in_com == "block":
        if prev == "*" and ch == "/":
            in_com = None
        prev = ch
        continue
    if in_str:
        if ch == "\\":
            prev = ch
            continue
        if ch == '"':
            in_str = False
        prev = ch
        continue
    if in_chr:
        if ch == "\\":
            prev = ch
            continue
        if ch == "'":
            in_chr = False
        prev = ch
        continue
    if prev == "/" and ch == "/":
        in_com = "line"
    if prev == "/" and ch == "*":
        in_com = "block"
    if ch == '"':
        in_str = True
    if ch == "'":
        in_chr = True
    if ch == "{":
        depth += 1
    if ch == "}":
        depth -= 1
        if depth < 0:
            bad.append(line)
            depth = 0
    prev = ch
print("final depth:", depth, "negative at:", bad[:5])
assert depth == 0, "brace imbalance remains"
print("braces balanced")

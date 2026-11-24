#!/usr/bin/env python3
"""No side effects inside probe arguments.

KD(), spawn_log(), dlog(), boftrace(), g3_log() and BW_TRACE() are traces -
KD is a no-op in a release build - so a call that does something must never
be written as their argument: it only happens where the probe does.
channel.cpp sent its GET as `KD("ch: send ok=", (long)HttpSendRequestA(...))`:
every kdebug battery was green, and no release beacon ever checked in.

Every call found in a probe's argument list has to be in PURE below.
Exit status 1 on anything else."""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PROBE = re.compile(r'\b(KD|KDHEX|spawn_log|dlog|boftrace|g3_log|BW_TRACE)\s*\(')
PURE = {'GetLastError', 'WSAGetLastError', 'http_sum', 'bofwin_test_tramp', 'strlen', 'lstrlenA'}
CASTS = {'long', 'int', 'char', 'void', 'DWORD', 'BOOL', 'SIZE_T', 'unsigned', 'LPVOID', 'HANDLE', 'sizeof',
         'defined', 'if', 'while', 'for', 'return', 'ULONG_PTR', 'ULONG', 'WORD', 'BYTE', 'SHORT', 'uint',
         'LONGLONG', 'ULONGLONG', 'PVOID', 'LPARAM', 'WPARAM', 'USHORT', 'LARGE_INTEGER', 'time_t', 'LONG_PTR'}


def split_args(s):
    args, depth, cur = [], 0, ''
    for c in s:
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        if c == ',' and depth == 0:
            args.append(cur)
            cur = ''
        else:
            cur += c
    args.append(cur)
    return args


def main():
    bad = 0
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for f in sorted(files):
            if not f.endswith(('.c', '.cpp', '.h')):
                continue
            path = os.path.join(base, f)
            text = open(path, encoding='utf-8', errors='replace').read()
            for m in PROBE.finditer(text):
                i, depth = m.end(), 1
                while i < len(text) and depth > 0:
                    if text[i] == '(':
                        depth += 1
                    elif text[i] == ')':
                        depth -= 1
                    i += 1
                inner = text[m.end():i - 1]
                if inner.count('\n') > 2:
                    continue  # a block body, not a one-line probe
                line = text.count('\n', 0, m.start()) + 1
                for arg in split_args(inner)[1:]:
                    for call in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*[$!]*)\s*\(', arg):
                        name = call.group(1)
                        if name in CASTS or name in PURE:
                            continue
                        bad += 1
                        print('%s:%d %s -> %s()  | %s' % (os.path.relpath(path, ROOT).replace('\\', '/'), line,
                                                        m.group(1), name, ' '.join(arg.split())[:90]))
    if bad:
        print('%d probe argument(s) perform a call: make the call first, probe its result' % bad)
        return 1
    print('probe arguments: only pure getters')
    return 0


if __name__ == '__main__':
    sys.exit(main())

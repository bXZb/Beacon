#!/usr/bin/env python3
"""tools/llvm/compare_exports.py — Phase 1 gate helper.

Compares the DLL export tables of two PE files via `llvm-readobj --coff-exports`
and exits non-zero when the exported name sets differ (order-independent;
RVAs are reported but not compared — code layout legitimately differs between
compilers).

Usage: compare_exports.py <llvm-readobj> <dll-a> <dll-b>
"""
import re
import subprocess
import sys


def exports(readobj, dll):
    out = subprocess.run([readobj, "--coff-exports", dll],
                         capture_output=True, text=True, errors="replace")
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        raise SystemExit(f"llvm-readobj failed on {dll}")
    names = re.findall(r"Name:\s+(\S+)", out.stdout)
    return names


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    readobj, a, b = sys.argv[1:]
    ea, eb = exports(readobj, a), exports(readobj, b)
    sa, sb = set(ea), set(eb)
    print(f"{a}: {len(ea)} exports: {sorted(sa)}")
    print(f"{b}: {len(eb)} exports: {sorted(sb)}")
    if sa != sb:
        print(f"MISSING in {b}: {sorted(sa - sb)}", file=sys.stderr)
        print(f"EXTRA in {b}: {sorted(sb - sa)}", file=sys.stderr)
        raise SystemExit("export tables differ")
    print("== export tables identical ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())

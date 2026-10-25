#!/usr/bin/env python3
"""tools/llvm/sizes_table.py — markdown size table from llvm-out/_sizes.json."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "llvm-out/_sizes.json"
rows = json.load(open(path, encoding="utf-8"))
print("| variant | dll | bytes |")
print("|---|---|---|")
for e in rows:
    print(f"| {e['variant']} | {e['dll']} | {e['bytes']} |")

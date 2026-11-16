# -*- coding: utf-8 -*-
"""fix_obtrace.py - repair the OBTRACE macro (heredoc ate the backslashes:
"\\Users" became "\Users" and "\\n" became a real newline)."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\openbeacon\Beacon\beacon.c")
s = io.open(P, encoding="utf-8").read()

BS = chr(92)
bad1 = 'fopen("C:' + BS + 'Users' + BS + 'Public' + BS + 'ob_trace.txt", "a")'
good1 = ('fopen("C:' + BS * 4 + 'Users' + BS * 4 + 'Public' + BS * 4 +
         'ob_trace.txt", "a")')
assert bad1 in s, "fopen literal not found"
s = s.replace(bad1, good1)

bad2 = '"[%lu] %s\n"'
good2 = '"[%lu] %s' + BS * 2 + 'n"'
assert bad2 in s, "fprintf newline not found"
s = s.replace(bad2, good2)

io.open(P, "w", encoding="utf-8", newline="\n").write(s)
print("OBTRACE literals repaired")

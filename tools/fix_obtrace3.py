# -*- coding: utf-8 -*-
r"""fix_obtrace3.py - rewrite the whole OBTRACE function block cleanly."""
import io

P = (r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon"
     r"\openbeacon\Beacon\beacon.c")
s = io.open(P, encoding="utf-8").read()

BS = chr(92)
start = s.index("static void OBTRACE(const char* what) {")
end = s.index("}", s.index("fclose(f)")) + 1
old = s[start:end]
print("old block: %r" % old[:120])

new = ("static void OBTRACE(const char* what) {" + BS + "n"
       + BS + "tFILE* f = fopen(\"C:" + BS * 4 + "Users" + BS * 4 + "Public"
       + BS * 4 + "ob_trace.txt\", \"a\");" + BS + "n"
       + BS + "tif (f) { fprintf(f, \"[%lu] %s" + BS * 2 + "n\", "
       + "(unsigned long)GetTickCount(), what); fclose(f); }" + BS + "n"
       + "}")
s = s[:start] + new + s[end:]
io.open(P, "w", encoding="utf-8", newline=BS + "r" + BS + "n").write(s)
print("OBTRACE block rewritten")

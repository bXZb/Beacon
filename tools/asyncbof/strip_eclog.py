# -*- coding: utf-8 -*-
"""strip_eclog.py - remove the dead eclog file logger (token-denied inside
patsies) and its call sites, and add the ASYNCDLL_DIAG compile-time gate
around the pipe-based [asyncdiag] diagnostics."""
import re

P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp"
s = open(P, "rb").read()

# 1) drop the eclog function (comment line + body)
i = s.find(b'/* stage trace (C-19 debugging): append-only file log, best effort */')
assert i > 0
j = s.find(b'\n}\n', i)
assert j > 0
j += 3
s = s[:i] + s[j:]

# 2) drop every eclog("..."); call line (keep the surrounding logic)
n = 0
out = []
for line in s.split(b"\n"):
    st = line.strip()
    if st.startswith(b'eclog("'):
        n += 1
        continue
    out.append(line)
s = b"\n".join(out)
print("eclog calls removed:", n)

# 3) the DllMain reason-logger block (CreateFileA + WriteFile) - remove whole block
old = b'\t{\n\t\tHANDLE f = CreateFileA("'
i = s.find(old)
assert i > 0
j = s.find(b"\t}\n", i)
assert j > 0
j += 3
s = s[:i] + s[j:]
assert b"CreateFileA" not in s, "CreateFileA remnants"

# 4) diag gate: wrap shim-based diag writes behind ASYNCDLL_DIAG
anchor = b"/* ---------------- mini LE parser ---------------- */"
assert s.count(anchor) == 1
gate = (b"/* diagnostics gate (C-24): the [asyncdiag] lines (parse summary,\n"
        b" * zero-text refusal, bg-wait ticks, followup recv) ride the normal\n"
        b" * output channels - flip to 0 for a quiet production build. */\n"
        b"#define ASYNCDLL_DIAG 1\n\n") + anchor
s = s.replace(anchor, gate)

# gate the diag sites: they all build 'diag[...]' via _snprintf then shim_output
# -> wrap each 'char diag[..] ... _snprintf ... shim_output(...);' trio is
# invasive; simpler: make shim_output diag-specific? No - gate at the diag
# construction: replace 'char diag[' with 'char diag[' (unchanged) and gate
# the emit by prefixing each diagnostic shim_output with the flag.
cnt = 0
def gate_emit(m):
    global cnt
    cnt += 1
    return b"if (ASYNCDLL_DIAG) " + m.group(0)

# diagnostic emits are exactly the shim_output calls whose argument is (0, diag, dn)
s, cnt = re.subn(rb"shim_output\(0, diag, dn\);", rb"shim_output(0, diag, dn);", s)
# do it as a guarded statement form: 'if (dn > 0) { diag[dn] = 0; shim_output...' -> add flag
s = re.sub(rb"if \(dn > 0\) \{ diag\[dn\] = 0; shim_output\(0, diag, dn\); \}",
           b"if (dn > 0 && ASYNCDLL_DIAG) { diag[dn] = 0; shim_output(0, diag, dn); }", s)
s = re.sub(rb"if \(dn > 0\) \{ diag\[dn\] = 0; shim_output\(0, diag, dn\); \}",
           b"if (dn > 0 && ASYNCDLL_DIAG) { diag[dn] = 0; shim_output(0, diag, dn); }", s)
open(P, "wb").write(s)
print("done; CreateFileA gone, gate define in")

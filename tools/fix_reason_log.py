import re
from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()
t = t.replace(b'eclog-ready b2[64];', b'b2[64];')
# the inserted block: fix the mangled \n in the _snprintf literal
t = t.replace(b'_snprintf(b2, 63, "st: DllMain reason=%lu\n", dwReason);',
              b'_snprintf(b2, 63, "st: DllMain reason=%lu\\n", dwReason);')
p.write_bytes(t)
d = t
bad = 0
for m in re.finditer(rb'"[^"]*\n[^"]*"', d):
    s = m.group(0)
    if b'st:' in s:
        bad += 1
print("remaining bad string literals with raw LF:", bad)

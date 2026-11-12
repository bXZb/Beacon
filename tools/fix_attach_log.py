import re
from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()
t = t.replace(b'eclog("st: PROCESS_ATTACH enter\n");',
              b'eclog("st: PROCESS_ATTACH enter\\n");')
t = t.replace(b'eclog("st: PROCESS_ATTACH ok\n");',
              b'eclog("st: PROCESS_ATTACH ok\\n");')
p.write_bytes(t)
d = t
bad = 0
for m in re.finditer(rb'eclog\("([^"]*)"\)', d):
    if b"\n" in m.group(1) or b"\r" in m.group(1):
        bad += 1
print("remaining bad:", bad)

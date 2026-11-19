import re
from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()

# fix every eclog("...\n...") where \n became a real newline inside the literal.
# Pattern: eclog("  <LF>  ");  -> eclog("...\n");
fixed = t.replace(b'eclog("st: run_async parsed args\n");',
                  b'eclog("st: run_async parsed args\\n");')
fixed = fixed.replace(b'eclog("st: ARG PARSE FAILED\n");',
                      b'eclog("st: ARG PARSE FAILED\\n");')
fixed = fixed.replace(b'eclog("st: run_bof enter\n");',
                      b'eclog("st: run_bof enter\\n");')
fixed = fixed.replace(b'eclog("st: run_bof returned\n");',
                      b'eclog("st: run_bof returned\\n");')
fixed = fixed.replace(b'eclog("st: flush_output enter\n");',
                      b'eclog("st: flush_output enter\\n");')
fixed = fixed.replace(b'eclog("st: flush_output returned\n");',
                      b'eclog("st: flush_output returned\\n");')
fixed = fixed.replace(b'eclog("st: control client connected\n");',
                      b'eclog("st: control client connected\\n");')
fixed = fixed.replace(b'eclog("st: run_async enter\n");',
                      b'eclog("st: run_async enter\\n");')
fixed = fixed.replace(b'eclog("st: run_async returned\n");',
                      b'eclog("st: run_async returned\\n");')
fixed = fixed.replace(b'eclog("st: postex-attach enter\n");',
                      b'eclog("st: postex-attach enter\\n");')
fixed = fixed.replace(b'eclog("st: CreateNamedPipeA(control) FAILED\n");',
                      b'eclog("st: CreateNamedPipeA(control) FAILED\\n");')
fixed = fixed.replace(b'eclog("st: control pipe server up\n");',
                      b'eclog("st: control pipe server up\\n");')
n = sum(1 for a, b in ((t, fixed),)) if fixed != t else 0
p.write_bytes(fixed)
print("fixed bytes delta:", len(t) - len(fixed))
# verify
d = fixed
bad = 0
for m in re.finditer(rb'eclog\("([^"]*)"\)', d):
    if b"\n" in m.group(1) or b"\r" in m.group(1):
        bad += 1
print("remaining bad:", bad)

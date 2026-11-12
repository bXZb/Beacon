# -*- coding: utf-8 -*-
"""dec_dns_handler.py - decompile the TeamServerImage's DNS handler
(who implements DNSServer$Handler.respond) with cfr, and print the
unknown-id decision logic."""
import subprocess
from pathlib import Path

IMG = r"C:/Users/Administrator/Desktop/cobaltstrike/4.9.1/cobaltstrike.jar"
# TeamServerImage inside that jar is the real TS binary; extract it
import zipfile
z = zipfile.ZipFile(IMG)
out = Path(r"C:/Users/Administrator/Desktop/cobaltstrike/ci-artifacts/ts_tsi")
out.mkdir(parents=True, exist_ok=True)
# cfr can read a jar directly and decompile everything - too slow. Target:
# cfr supports --jarfilter. Use it.
CFR = r"C:/Users/Administrator/Desktop/cobaltstrike/ci-artifacts/cfr.jar"
r = subprocess.run([
    "C:/Users/Administrator/Desktop/jdk-21.0.12.1/bin/java.exe",
    "-jar", CFR, IMG,
    "--jarfilter", "server.Beacons",
    "--outputdir", str(out / "dec")],
    capture_output=True, text=True, timeout=600)
print("rc", r.returncode)
print(r.stdout[-500:])
print(r.stderr[-500:])
for p in (out / "dec").rglob("*.java"):
    print("JAVA:", p)

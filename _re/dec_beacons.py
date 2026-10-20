# -*- coding: utf-8 -*-
"""dec_beacons.py - extract server/Beacons*.class from the 4.9.1 TS jar and
decompile with the local cfr to answer: how does the DNS handler treat an
unknown beacon id (does it create a session / reply 0xF1)?"""
import subprocess
import zipfile
from pathlib import Path

JAR = r"C:/Users/Administrator/Desktop/cobaltstrike/4.9.1/cobaltstrike.jar"
OUT = Path(r"C:/Users/Administrator/Desktop/cobaltstrike/ci-artifacts/ts_dec")
OUT.mkdir(parents=True, exist_ok=True)

z = zipfile.ZipFile(JAR)
wanted = [n for n in z.namelist() if n.startswith("server/Beacons") or n.startswith("dns/")]
print("classes found:")
for n in wanted:
    print("  ", n)
    z.extract(n, OUT)

CFR = r"C:/Users/Administrator/Desktop/cobaltstrike/ci-artifacts/cfr.jar"
for n in wanted:
    if not n.endswith(".class") or "$" in n:
        continue
    cls = n.replace("/", ".").rstrip(".class") if False else n[:-len(".class")].replace("/", ".")
    r = subprocess.run([
        "C:/Users/Administrator/Desktop/jdk-21.0.12.1/bin/java.exe",
        "-jar", CFR, str(OUT / n), "--outputdir", str(OUT / "dec")],
        capture_output=True, text=True)
    print("decompiled", cls, "rc=", r.returncode)

for p in (OUT / "dec").rglob("*.java"):
    print("JAVA:", p)

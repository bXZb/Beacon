# -*- coding: utf-8 -*-
"""surgical_jar.py - C-49: take the known-good C-44 jar (bak_our) and replace
ONLY the BeaconPayload*.class entries with the fixed build's, then swap in the
official encoded sleeves. Everything else stays byte-identical to the jar that
ran all session."""
import shutil
import zipfile
from zipfile import ZipFile, ZIP_DEFLATED

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
BAK = JAR + ".bak_our"
ENC = r"C:\Users\Public\official_ctrl2"
WORK = JAR.replace(".jar", ".c49.jar")

fixed = JAR  # current rebuild (has the guard)
base = BAK   # known-good runtime jar

zin = ZipFile(fixed, "r")
patched = {}
for item in zin.infolist():
    if item.filename.startswith("beacon/BeaconPayload"):
        patched[item.filename] = zin.read(item.filename)
        print("captured fixed class:", item.filename, len(patched[item.filename]))
zin.close()
assert "beacon/BeaconPayload.class" in patched, "no BeaconPayload.class found"

zin = ZipFile(base, "r")
zout = ZipFile(WORK, "w", ZIP_DEFLATED)
n = 0
for item in zin.infolist():
    data = zin.read(item.filename)
    if item.filename.startswith("beacon/BeaconPayload"):
        data = patched[item.filename]
        n += 1
    if item.filename == "sleeve/beacon.x64.dll":
        data = open(ENC + r"\beacon.x64.dll.enc", "rb").read()
        print("swapped beacon.x64.dll -> official enc")
    elif item.filename == "sleeve/beacon.x64.rl0k.dll":
        data = open(ENC + r"\beacon.x64.rl0k.dll.enc", "rb").read()
        print("swapped beacon.x64.rl0k.dll -> official enc")
    zout.writestr(item, data)
zin.close()
zout.close()
print("patched classes:", n)
shutil.copy2(WORK, JAR)
print("working jar in place:", JAR)

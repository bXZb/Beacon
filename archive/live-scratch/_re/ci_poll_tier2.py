# -*- coding: utf-8 -*-
"""ci_poll_tier2.py [branch] [sha-prefix] - poll newest run on a branch until
completed; print status/conclusion and exit 0 only if success."""
import json
import sys
import time
import urllib.request

TOK = open(r"C:/Users/Administrator/Desktop/cobaltstrike/GITHUB_PERSONAL_ACCESS_TOKEN.txt").read().strip()
HDR = {"Authorization": "Bearer " + TOK, "User-Agent": "beacon-ops"}
proxy = urllib.request.ProxyHandler({"https": "http://127.0.0.1:10808", "http": "http://127.0.0.1:10808"})
opener = urllib.request.build_opener(proxy)

branch = sys.argv[1] if len(sys.argv) > 1 else "feat/post-4.9.1"
want = sys.argv[2] if len(sys.argv) > 2 else None


def api(url):
    req = urllib.request.Request(url, headers=HDR)
    return json.loads(opener.open(req, timeout=60).read().decode())


latest = None
for attempt in range(80):
    runs = api("https://api.github.com/repos/bXZb/Beacon/actions/runs?branch=%s&per_page=3" % branch)["workflow_runs"]
    if not runs:
        print("no runs yet", flush=True)
        time.sleep(30)
        continue
    latest = runs[0]
    print("poll:", latest["id"], latest["head_sha"][:9], latest["status"], latest["conclusion"], flush=True)
    if latest["status"] == "completed" and (want is None or latest["head_sha"].startswith(want)):
        break
    time.sleep(45)

if latest is None:
    sys.exit(2)
print("CONCLUSION:", latest["conclusion"])
sys.exit(0 if latest["conclusion"] == "success" else 1)

#!/usr/bin/env python3
"""Fetch the newest udc2_tcp.x64.o from the latest successful CI run."""
import io, os, sys, time, zipfile
import requests

PROXY = {"http": "http://127.0.0.1:10808", "https": "http://127.0.0.1:10808"}
TOKEN = open("C:/Users/Administrator/Desktop/GITHUB_PERSONAL_ACCESS_TOKEN.txt").read().strip()
H = {"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json"}
REPO = "https://api.github.com/repositories/1349826230"

run_id = sys.argv[1] if len(sys.argv) > 1 else None
if run_id is None:
    for wf in ["build.yml"]:
        r = requests.get(f"{REPO}/actions/workflows/{wf}/runs?branch=feat/post-4.9.1&status=success&per_page=1",
                         headers=H, proxies=PROXY, timeout=60).json()
        run_id = r["workflow_runs"][0]["id"]
        break
print("run:", run_id)

for attempt in range(6):
    arts = requests.get(f"{REPO}/actions/runs/{run_id}/artifacts", headers=H, proxies=PROXY, timeout=60).json()
    for a in arts.get("artifacts", []):
        if a["name"] == "beacon-x64-rl0k":
            url = a["archive_download_url"]
            for d in range(5):
                rr = requests.get(url, headers=H, proxies=PROXY, timeout=180)
                if rr.status_code == 200:
                    z = zipfile.ZipFile(io.BytesIO(rr.content))
                    names = [n for n in z.namelist() if n.endswith("udc2_tcp.x64.o")]
                    assert names, z.namelist()
                    data = z.read(names[0])
                    open("C:/Users/Public/udc2_tcp.x64.o", "wb").write(data)
                    print("staged udc2_tcp.x64.o bytes=", len(data))
                    sys.exit(0)
                print("dl retry", rr.status_code)
                time.sleep(5)
    print("artifact not listed yet, retry", attempt)
    time.sleep(10)
sys.exit(1)

# -*- coding: utf-8 -*-
"""gh_cs_detail.py - fetch contents + readme for candidate repos."""
import base64
import json
import urllib.request
import urllib.parse

TOKEN = open(r"C:\Users\Administrator\Desktop\cobaltstrike"
             r"\GITHUB_PERSONAL_ACCESS_TOKEN.txt").read().strip().splitlines()[0].strip()
proxy = urllib.request.ProxyHandler({"http": "http://127.0.0.1:10808",
                                     "https": "http://127.0.0.1:10808"})
urllib.request.install_opener(urllib.request.build_opener(proxy))


def gh(url):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + TOKEN,
        "Accept": "application/vnd.github+json"})
    return json.load(urllib.request.urlopen(req))


CANDS = [
    "outflanknl/C2-Tool-Collection",
    "ElJaviLuki/CobaltStrike_OpenBeacon",
    "ryanq47/CS-EXTC2-HUB",
    "REDMED-X/OperatorsKit",
    "anthemtotheego/InlineExecute-Assembly",
    "dazzyddos/lsawhisper-bof",
    "0xedh/dumpguard_bof",
    "RedSiege/C2concealer",
    "NVISOsecurity/CobaltWhispers",
    "wumb0/rust_bof",
    "connormcgarr/cThreadHijack",
    "chryzsh/redteam-bofs",
]

for full in CANDS:
    print("=" * 70)
    print("REPO:", full)
    try:
        tree = gh("https://api.github.com/repos/%s/git/trees/HEAD?recursive=1"
                  % full)
        paths = [t["path"] for t in tree.get("tree", [])]
        # summarize: top-level dirs + src files
        top = {}
        for p in paths:
            seg = p.split("/")[0]
            top[seg] = top.get(seg, 0) + 1
        print("tree %d files, top: %s" % (len(paths), list(top.items())[:12]))
        srcs = [p for p in paths if p.count("/") <= 2 and p.lower().endswith(
            (".c", ".h", ".cpp", ".cs", ".rs", ".go", ".py", ".cna"))]
        for s in srcs[:14]:
            print("   ", s)
    except Exception as e:
        print("tree fail:", e)
    try:
        rd = gh("https://api.github.com/repos/%s/readme" % full)
        txt = base64.b64decode(rd["content"]).decode(errors="replace")
        # first meaningful lines
        lines = [l for l in txt.splitlines() if l.strip()][:18]
        for l in lines:
            print("  R|", l[:110])
    except Exception as e:
        print("readme fail:", e)

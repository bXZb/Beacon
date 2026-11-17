# -*- coding: utf-8 -*-
"""gh_cs_detail2.py - fetch tree+readme for round-2 candidates."""
import base64
import json
import urllib.request

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
    "kyleavery/AceLdr",
    "Cracked5pider/KaynStrike",
    "memN0ps/doublepulsar-rs",
    "The-Z-Labs/bof-launcher",
    "VoldeSec/PatchlessInlineExecute-Assembly",
    "praetorian-inc/goffloader",
    "0xTriboulet/InlineExecuteEx",
    "CodeXTF2/Cobaltstrike_BOFLoader",
    "Ap3x/COFF-Loader",
    "ajpc500/BOFs",
    "rookuu/BOFs",
    "pwn1sher/CS-BOFs",
    "S4ntiagoP/freeBokuLoader",
    "jakobfriedl/async-bof-loader",
    "emdnaia/OdinLdr",
    "DeLuks2006/SweetDream",
]

for full in CANDS:
    print("=" * 70)
    print("REPO:", full)
    try:
        tree = gh("https://api.github.com/repos/%s/git/trees/HEAD?recursive=1" % full)
        paths = [t["path"] for t in tree.get("tree", [])]
        print("tree %d files" % len(paths))
        srcs = [p for p in paths if p.count("/") <= 2 and p.lower().endswith(
            (".c", ".h", ".cpp", ".cs", ".rs", ".py", ".cna", ".toml"))]
        for s in srcs[:10]:
            print("   ", s)
    except Exception as e:
        print("tree fail:", e)
    try:
        rd = gh("https://api.github.com/repos/%s/readme" % full)
        txt = base64.b64decode(rd["content"]).decode(errors="replace")
        lines = [l for l in txt.splitlines() if l.strip()][:14]
        for l in lines:
            print("  R|", l[:110])
    except Exception as e:
        print("readme fail:", e)

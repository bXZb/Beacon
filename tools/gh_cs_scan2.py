# -*- coding: utf-8 -*-
"""gh_cs_scan2.py - round-2 scan for CS ecosystem projects NOT yet covered.
Round-1 covered: OpenBeacon/C2-Tool-Collection/InlineExecute-Assembly/
C2concealer/rust_bof + 8 evasion repos + 4 C2-ext repos + official org.
This round targets different categories: UDRL loaders, sleepmask kits,
token/credential BOFs, lateral movement, MalleablePE, BOF-PE, hooking."""
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


QUERIES = [
    ("udrl2", "cobaltstrike+UDRL+loader"),
    ("sleepmask2", "cobaltstrike+sleepmask+kit"),
    ("bofpe", "cobaltstrike+BOF+PE+inline"),
    ("malleable", "malleable+c2+profile+generator"),
    ("lateral", "cobaltstrike+lateral+movement+bof"),
    ("token", "cobaltstrike+token+bof"),
    ("thread", "cobaltstrike+injection+technique"),
    ("sharpbof", "csharp+beacon+object+file"),
    ("interpreter", "beacon+interpreter+script"),
    ("elevation", "cobaltstrike+elevation+uac+bof"),
]

seen = set()
KNOWN = {
    "arsenal-kit", "sleepmask-vs", "callstackmasker", "bof-vs", "bof_template",
    "unhook-bof", "beacon-interpreter", "obfuscator-llvm", "udc2-vs",
    "external-c2", "icmp-udc2", "s3-udc2", "eden", "crystal-quotes",
    "bof-collection", "react2shell", "elevatekit", "malleable-c2-profiles",
    "no-consolation", "nanodump", "crystalpalace", "beaconeye",
    "cobaltstrike-strikekit", "cs-aggressor-kit", "c2-tool-collection",
    "cobaltstrike_openbeacon", "inlineexecute-assembly", "c2concealer",
    "rust_bof", "operatorskit", "bofallthethings", "redteam-bofs",
    "inlinewhispers", "inlinewhispers2", "inlinewhispers3", "cobaltwhispers",
    "cs-uploads-tracker", "offsecops-arsenal", "aggressorsploit", "cs-tools",
    "cobaltparrot", "abortcommand", "cs-extc2-hub", "redreaper",
    "windfarmdynamite-cna", "cthreadhijack", "dumpguard_bof", "lsawhisper-bof",
    "adsyncdump-bof", "timestomp_bof", "findobjects-bof", "wdtoggle",
    "credbandit", "spray-ad", "inlineexec", "beaconator", "csbruter",
    "malleable-c2-profiles", "ycsm", "sharpbuster", "opsec-aggressor",
}

rows = []
for tag, q in QUERIES:
    try:
        res = gh("https://api.github.com/search/repositories?q=%s&sort=stars"
                 "&order=desc&per_page=25" % urllib.parse.quote(q))
    except Exception as e:
        print("query %s failed: %s" % (tag, e))
        continue
    for it in res.get("items", []):
        full = it["full_name"]
        repo = full.split("/")[-1].lower()
        if repo in KNOWN or full.lower() in seen:
            continue
        seen.add(full.lower())
        if it["stargazers_count"] < 30 and it["pushed_at"] < "2025-06-01":
            continue
        desc = (it.get("description") or "")[:100]
        rows.append((it["stargazers_count"], it["pushed_at"][:10], full, desc))

rows.sort(key=lambda x: -x[0])
for st, pushed, full, desc in rows[:40]:
    print("%5d  %s  %-52s %s" % (st, pushed, full, desc))

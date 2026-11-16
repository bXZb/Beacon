# -*- coding: utf-8 -*-
"""gh_cs_scan.py - scan GitHub for CobaltStrike-ecosystem projects NOT yet
covered by our tested set (8 evasion repos + 4 C2-ext repos + official org),
for compatibility/regression testing against our beacon+TS."""
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
    ("bof", "beacon+object+file+bof"),
    ("udrl", "user+defined+reflective+loader+cobaltstrike"),
    ("exec-dll", "cobaltstrike+execute-dll"),
    ("aggressor", "cobaltstrike+aggressor+script"),
    ("sleepmask", "cobaltstrike+sleep+mask"),
    ("rest", "cobaltstrike+rest+api"),
    ("udc2", "cobaltstrike+udc2"),
    ("evasion", "cobaltstrike+beacon+evasion"),
    ("generic", "cobalt+strike+tool"),
    ("postex", "cobaltstrike+postex"),
]

seen = set()
# already covered by our test campaigns
KNOWN = {
    "arsenal-kit", "sleepmask-vs", "callstackmasker", "bof-vs", "bof_template",
    "unhook-bof", "beacon-interpreter", "obfuscator-llvm", "udc2-vs",
    "external-c2", "icmp-udc2", "s3-udc2", "eden", "crystal-quotes",
    "bof-collection", "react2shell", "elevatekit", "malleable-c2-profiles",
    "no-consolation", "nanodump", "crystalpalace", "beaconeye",
    "cobaltstrike-strikekit", "cs-aggressor-kit",
}

rows = []
for tag, q in QUERIES:
    try:
        res = gh("https://api.github.com/search/repositories?q=%s&sort=stars"
                 "&order=desc&per_page=20" % urllib.parse.quote(q))
    except Exception as e:
        print("query %s failed: %s" % (tag, e))
        continue
    for it in res.get("items", []):
        full = it["full_name"]
        repo = full.split("/")[-1].lower()
        if repo in KNOWN or full.lower() in seen:
            continue
        seen.add(full.lower())
        if it["stargazers_count"] < 15 and it["pushed_at"] < "2025-01-01":
            continue
        rows.append((it["stargazers_count"], it["pushed_at"][:10], full,
                     (it.get("description") or "")[:90]))

rows.sort(key=lambda x: -x[0])
for st, pushed, full, desc in rows[:45]:
    print("%5d  %s  %-45s %s" % (st, pushed, full, desc))

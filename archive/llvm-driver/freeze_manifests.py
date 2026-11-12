#!/usr/bin/env python3
"""freeze_manifests.py — Phase 5 (vcxproj retirement): freeze the resolved
per-variant manifests into COMMITTED JSON. Run once on a CI runner (or any
host with the xwin splat); review the diff; commit. After that the CMake
driver reads these files directly and build.py's parser retires.

The variant list mirrors llvm-build.yml's product matrix exactly.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as bp

# (project, platform, http, extra-args..., flags-tag)
VARIANTS = [
    ("beacon",  "x64", "wininet", [],              "layout"),
    ("beacon",  "x64", "winhttp", [],              "layout"),
    ("dnsb",    "x64", "wininet", [],              "layout"),
    ("extc2",   "x64", "wininet", [],              "layout"),
    ("pivot",   "x64", "wininet", [],              "layout"),
    ("beacon",  "x64", "wininet", ["--plain-sleep"], "plainsleep+layout"),
    ("beacon",  "x64", "wininet", ["--no-excreg"],   "noexcreg"),
    ("beacon",  "x64", "wininet", ["--diag-retaddr"],"diagretaddr"),
    ("beacon",  "x64", "wininet", ["--bofwin"],     "bofwin"),
]


def main():
    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    xwin = os.environ.get("XWIN_DIR") or os.path.expanduser("~/.llvm-cross/xwin-splat")
    xwin = os.path.abspath(xwin).replace(os.sep, "/")
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests")
    os.makedirs(outdir, exist_ok=True)

    for proj, plat, http, extra, tag in VARIANTS:
        argv = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "dump_manifest.py"),
                "--project", proj, "--platform", plat,
                "--http", http] + extra + ["--xwin-dir", xwin, "--repo", repo]
        r = subprocess.run([sys.executable] + argv, cwd=repo,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
            sys.exit(f"freeze failed for {proj}-{plat}-{http}-{tag}")
        src = os.path.join(repo, "gen", "manifest_last.json")
        m = bp.json.load(open(src))
        # normalize: tokenize ALL host paths (xwin splat + repo root) so the
        # JSON is host-independent and CI-checkout-path independent
        m["clang_cl"] = "clang-cl"
        def tok(t):
            t = t.replace(xwin, "$(XWIN)")
            t = t.replace(repo + "/", "$(REPO)/")
            return t
        m["base_flags"] = [tok(t) for t in m["base_flags"]]
        m["link"] = [tok(t) for t in m["link"]]
        for f in m["files"]:
            f["flags"] = [tok(t) for t in f["flags"]]
        out = os.path.join(outdir, f"{proj}-{plat}-{http}-{tag}.json")
        bp.json.dump(m, open(out, "w"), indent=1)
        print(f"frozen {tag}: {m['target_name']} ({len(m['files'])} TUs) -> {os.path.basename(out)}")


if __name__ == "__main__":
    sys.exit(main())

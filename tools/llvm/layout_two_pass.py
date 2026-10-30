#!/usr/bin/env python3
"""layout_two_pass.py — Phase 4 build driver (build.py's CLI retires).

Compiles a variant from its manifest (dump_manifest.py output), links,
runs the two-pass layout self-description loop, and verifies. The vcxproj
parsing stays in build.py (imported); everything build.py's main() used to
drive lives here, invoked by the CMake variant driver.

Usage:
  layout_two_pass.py --manifest gen/manifest_last.json --repo R \
      --xwin-dir D --out-dir O [--obf SO] [--jobs N]
"""
import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as bp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--xwin-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--obf", default=None)
    ap.add_argument("--lld-link", required=True)
    ap.add_argument("--link-exe", default=None,
                    help="override the linker (link.exe for the MSVC track)")
    ap.add_argument("--clang-cl", default=None,
                    help="override the manifest's clang_cl entry (CI passes "
                         "the pinned binary)")
    ap.add_argument("--cc", default=None,
                    help="override the compiler executable entirely (cl.exe "
                         "for the MSVC track); manifest flags are "
                         "clang-cl-style which cl.exe accepts verbatim")
    ap.add_argument("--jobs", type=int, default=3)
    args = ap.parse_args()

    m = json.load(open(args.manifest))
    if args.clang_cl:
        m["clang_cl"] = args.clang_cl
    if args.cc:
        m["clang_cl"] = args.cc
    if args.link_exe:
        m["link"] = [args.link_exe] + [t for t in m["link"]
                                       if not t.startswith("/libpath:$(XWIN)")]
    target = m["target_name"]
    repo = args.repo.replace(os.sep, "/")
    xwin = os.path.abspath(args.xwin_dir).replace(os.sep, "/")
    out_dir = os.path.abspath(args.out_dir).replace(os.sep, "/")
    obj_dir = f"{out_dir}/obj/{target}"
    os.makedirs(obj_dir, exist_ok=True)
    os.makedirs(f"{out_dir}/out", exist_ok=True)

    def xw(tok):
        # frozen manifests tokenize the xwin splat as $(XWIN) and the repo
        # root as $(REPO); live dump_manifest output embeds real paths
        # (both no-ops there)
        return tok.replace("$(XWIN)", xwin).replace("$(REPO)", repo)

    dll = f"{out_dir}/out/{target}.llvm.dll"
    mmap = f"{out_dir}/out/{target}.llvm.map"

    tasks = []
    link_objs = []
    for i, f in enumerate(m["files"]):
        src = repo + "/" + f["src"]
        if not os.path.exists(src):
            die(f"source missing: {src}")
        obj = f"{obj_dir}/{i}.obj"
        link_objs.append(obj)
        cmd = [m["clang_cl"]] + [xw(t) for t in m["base_flags"]] \
              + [xw(t) for t in f["flags"]] \
              + ["/Fo:" + obj, "/c", src]
        if args.obf:
            cmd += ["/clang:-fpass-plugin=" + args.obf]
        tasks.append((obj, cmd))

    # link command: lld-link first, then the manifest tokens with the real
    # obj list and out paths substituted (placeholders are in file order)
    link = [args.lld_link]
    oi = 0
    for tok in m["link"]:
        tok = xw(tok)
        if tok.startswith("<OBJ>/"):
            link.append(link_objs[oi])
            oi += 1
        else:
            link.append(tok.replace("<OUT>/", f"{out_dir}/out/"))
    assert oi == len(link_objs), "obj placeholder count mismatch"

    layout_h = repo + "/gen/layout.h"
    if not os.path.exists(layout_h):
        bp.write_layout_h(layout_h, [], 0x400000)

    print(f"==> {m['variant']}: {len(tasks)} TUs -> {dll}", flush=True)
    failures = []

    def run_one(t):
        obj, cmd = t
        r = subprocess.run(cmd, capture_output=True, text=True,
                           cwd=repo, errors="replace")
        if r.returncode != 0:
            failures.append((cmd, r.stderr[-4000:]))
        elif r.stderr.strip():
            tail = "\n".join(r.stderr.strip().splitlines()[-4:])
            print(f"[warn] {os.path.basename(cmd[-1])}:\n{tail}", flush=True)
        return r.returncode

    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for _ in ex.map(run_one, tasks):
            if failures:
                break
    if failures:
        for cmd, err in failures[:3]:
            print("FAILED:", " ".join(cmd[:8]), "...", err, file=sys.stderr)
        die(f"{len(failures)} compile failure(s)")

    def link_it():
        r = subprocess.run(link, capture_output=True, text=True, cwd=repo,
                           errors="replace")
        if r.returncode != 0:
            print(r.stdout[-3000:], file=sys.stderr)
            print(r.stderr[-3000:], file=sys.stderr)
            die(f"link failed for {m['variant']}")

    link_it()

    # two-pass layout loop (same contract as build.py had)
    regions, soi = bp.compute_regions(open(dll, "rb").read())
    if bp.write_layout_h(layout_h, regions, soi):
        print(f"==> {m['variant']}: layout changed, pass 2", flush=True)
        for i, f in enumerate(m["files"]):
            if "gargle" in f["src"]:
                subprocess.run(tasks[i][1], capture_output=True, text=True,
                               cwd=repo, errors="replace")
        link_it()
    if not bp.verify_layout(dll, layout_h):
        regions, soi = bp.compute_regions(open(dll, "rb").read())
        bp.write_layout_h(layout_h, regions, soi)
        for i, f in enumerate(m["files"]):
            if "gargle" in f["src"]:
                subprocess.run(tasks[i][1], capture_output=True, text=True,
                               cwd=repo, errors="replace")
        link_it()
        if not bp.verify_layout(dll, layout_h):
            die(f"layout did not converge for {m['variant']}")
    print(f"==> {m['variant']}: layout verified ({len(regions)} regions)")
    print(f"==> {m['variant']}: {dll} ({os.path.getsize(dll)} bytes)")
    return 0


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""dump_manifest.py — Phase 4 build.py retirement bridge.

Dumps the resolved per-variant build manifest (sources, per-file flags,
compile flags, link flags, target name) as JSON for the CMake driver. The
vcxproj/props evaluation logic is imported from build.py so there is exactly
one parser; once the CMake driver is proven, build.py's build-driving main()
retires (this import path stays).

Usage: dump_manifest.py <project> <platform> <http> <extra...> --xwin-dir D
       (extra switches mirror build.py: --bofwin --pause --no-excreg
        --diag-retaddr --plain-sleep --layout)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as bp


def main():
    ap = bp.argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--platform", default="x64", choices=["x64", "x86"])
    ap.add_argument("--http", default="wininet", choices=["wininet", "winhttp"])
    ap.add_argument("--bofwin", action="store_true")
    ap.add_argument("--pause", action="store_true")
    ap.add_argument("--no-excreg", action="store_true")
    ap.add_argument("--diag-retaddr", action="store_true")
    ap.add_argument("--plain-sleep", action="store_true")
    ap.add_argument("--layout", action="store_true")
    ap.add_argument("--clang-cl", default="clang-cl")
    ap.add_argument("--xwin-dir", required=True)
    ap.add_argument("--repo", default=os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    args = ap.parse_args()

    repo = os.path.abspath(args.repo).replace(os.sep, "/")
    xwin = os.path.abspath(args.xwin_dir).replace(os.sep, "/")
    proj = bp.load_project(repo, args.project, args.platform, args.http,
                           args.bofwin, args.pause, args.no_excreg,
                           args.diag_retaddr, args.plain_sleep, args.layout)
    base = bp.compile_flags(proj, args.platform, xwin)

    files = []
    for src_rel, meta in proj.files:
        is_c = src_rel.lower().endswith(".c")
        per = bp.per_file_flags(meta, proj, is_c)
        files.append({"src": src_rel, "flags": per})

    # link command with placeholder obj names (CMake supplies real paths)
    objs = [f"<OBJ>/{src_rel}.obj" for src_rel, _ in proj.files]
    link = bp.link_command(proj, args.platform, xwin, objs,
                           "<OUT>/%s.llvm.dll" % proj.target_name,
                           "<OUT>/%s.llvm.map" % proj.target_name)

    m = {
        "variant": f"{args.project}-{args.platform}-{args.http}",
        "target_name": proj.target_name,
        "clang_cl": args.clang_cl,
        "base_flags": base,
        "files": files,
        "link": link,
    }
    out = os.path.join(repo, "gen", "manifest_last.json")
    json.dump(m, open(out, "w"), indent=1)
    print("manifest written to", out, "target", proj.target_name)


if __name__ == "__main__":
    sys.exit(main())

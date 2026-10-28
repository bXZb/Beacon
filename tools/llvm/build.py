#!/usr/bin/env python3
"""tools/llvm/build.py — LLVM (clang-cl + lld-link) sidecar build for the beacon
variants.

Parses each project's .vcxproj (plus the shared common.props) with a small
MSBuild-subset evaluator and mirrors the Release|x64 / Release|Win32 pipeline:
project + per-file preprocessor defines, per-file CompileAs overrides,
ExcludedFromBuild conditions (Platform / BeaconHttpLibrary / BeaconBofWin /
BeaconInjectPause), and the winhttp / rl0k TargetName rules. Every TU is
compiled with clang-cl and linked with lld-link.

Cross-compiles from Linux: headers/libs come from an xwin "splat" tree
(crt/include, sdk/include/{ucrt,um,shared}, crt/lib/<arch>, sdk/lib/{um,ucrt}/<arch>)
passed as explicit /I and /libpath: flags — no INCLUDE/LIB env, no Windows host
required. Output naming: <TargetName>.llvm.dll (+ .llvm.map).

MSVC-parity notes (deviations from the MSBuild build are intentional and
listed here):
  - /Brepro is added (determinism gate for the dual-host byte-diff);
  - MSVC /O1 implies /Ob1 /GF /Gy /Os — we pass them explicitly for clarity;
  - the MSBuild default AdditionalDependencies set is passed explicitly
    (kernel32.lib ... odbccp32.lib); unused import libs cost nothing;
  - DebugInformationFormat/GenerateDebugInformation are dropped (no PDB).

Usage:
  python3 tools/llvm/build.py --project beacon --platform x64 \
      --clang-cl <path>/clang-cl --lld-link <path>/lld-link --xwin-dir <splat>
Options: --http wininet|winhttp (default wininet), --bofwin, --pause,
  --out-dir (default llvm-out), --jobs N, --dry-run (print commands only).
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from xml.etree import ElementTree as ET

NS = "{http://schemas.microsoft.com/developer/msbuild/2003}"

# MSBuild defaults when a project sets no AdditionalDependencies.
DEFAULT_LIBS = [
    "kernel32.lib", "user32.lib", "gdi32.lib", "winspool.lib",
    "comdlg32.lib", "advapi32.lib", "shell32.lib", "ole32.lib",
    "oleaut32.lib", "uuid.lib", "odbc32.lib", "odbccp32.lib",
]

TRIPLE = {"x64": "x86_64-pc-windows-msvc", "x86": "i686-pc-windows-msvc"}
# xwin splat arch dir spellings; probe because layouts differ across versions
ARCHDIR_CANDIDATES = {"x64": ["x86_64", "x64"], "x86": ["x86", "i386"]}


def arch_dirs(xwin_dir, platform):
    # tolerate a missing splat (dry-run) by yielding the first candidate
    if not os.path.isdir(xwin_dir):
        for sub in ("crt/lib/", "sdk/lib/um/", "sdk/lib/ucrt/"):
            yield f"{xwin_dir}/{sub}{ARCHDIR_CANDIDATES[platform][0]}"
        return
    for sub in ("crt/lib/", "sdk/lib/um/", "sdk/lib/ucrt/"):
        for cand in ARCHDIR_CANDIDATES[platform]:
            if os.path.isdir(f"{xwin_dir}/{sub}{cand}"):
                yield f"{xwin_dir}/{sub}{cand}"
                break
        else:
            die(f"xwin splat missing {sub}<arch> under {xwin_dir} "
                f"(looked for {ARCHDIR_CANDIDATES[platform]})")


def die(msg):
    print(f"build.py: error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- conditions

def eval_condition(cond, props):
    """Evaluate the MSBuild condition subset used by these projects:
    quoted '==', '!=', And/Or chains, exists('...') (always False for the
    user-props imports we deliberately skip)."""
    if cond is None:
        return True
    cond = cond.strip()
    if not cond:
        return True
    parts = re.split(r"(?i)\s+and\s+|\s+or\s+", cond)
    if len(parts) == 1:
        return eval_atom(parts[0], props)
    results = [eval_atom(p, props) for p in parts]
    ops = [m.group(1).lower() for m in
           re.finditer(r"(?i)\s+(and|or)\s+", cond)]
    acc = results[0]
    for op, r in zip(ops, results[1:]):
        acc = (acc and r) if op == "and" else (acc or r)
    return acc


def eval_atom(atom, props):
    atom = atom.strip()
    m = re.fullmatch(r"'([^']*)'\s*(==|!=)\s*'([^']*)'", atom)
    if m:
        lhs, op, rhs = m.groups()
        lhs = expand_macros(lhs, props)
        return (lhs == rhs) if op == "==" else (lhs != rhs)
    if re.match(r"(?i)exists\s*\(", atom):
        return False  # the only exists() here guards user-props imports
    raise ValueError(f"unsupported condition atom: {atom!r}")


MACRO_RE = re.compile(r"\$\(([^)]+)\)")


def expand_macros(text, props):
    def sub(m):
        return props.get(m.group(1), "")
    out = MACRO_RE.sub(sub, text or "")
    return out


# ------------------------------------------------------------- vcxproj model

class Project:
    def __init__(self, repo, name, props):
        self.repo = repo
        self.name = name
        self.props = props
        self.clcompile = {}   # merged ItemDefinitionGroup/ClCompile metadata
        self.link = {}
        self.files = []       # (src_rel_posix, metadata dict)
        self.target_name = name


def eval_property_groups(root, props):
    for pg in root.findall(f"{NS}PropertyGroup"):
        if not eval_condition(pg.get("Condition"), props):
            continue
        for el in pg:
            if el.tag.startswith(NS) and el.text is not None:
                if eval_condition(el.get("Condition"), props):
                    props[el.tag[len(NS):]] = expand_macros(el.text.strip(), props)


def merge_idg(root, props, proj):
    for idg in root.findall(f"{NS}ItemDefinitionGroup"):
        if not eval_condition(idg.get("Condition"), props):
            continue
        cl = idg.find(f"{NS}ClCompile")
        if cl is not None:
            for el in cl:
                if el.tag.startswith(NS):
                    proj.clcompile[el.tag[len(NS):]] = (el.text or "").strip()
        lk = idg.find(f"{NS}Link")
        if lk is not None:
            for el in lk:
                if el.tag.startswith(NS):
                    proj.link[el.tag[len(NS):]] = (el.text or "").strip()


def collect_files(root, props):
    files = []
    for ig in root.findall(f"{NS}ItemGroup"):
        for cc in ig.findall(f"{NS}ClCompile"):
            meta = {}
            excluded = False
            for el in cc:
                if not el.tag.startswith(NS):
                    continue
                key = el.tag[len(NS):]
                if key == "ExcludedFromBuild":
                    if eval_condition(el.get("Condition"), props) and \
                            (el.text or "").strip().lower() == "true":
                        excluded = True
                else:
                    meta[key] = (el.text or "").strip()
            if excluded:
                continue
            inc = cc.get("Include").replace("\\", "/")
            files.append((inc, meta))
    return files


def load_project(repo, name, platform, http, bofwin, pause, no_exc=False,
                 diag_ret=False, plain_sleep=False, layout=False):
    # vcxproj platform name for 32-bit is Win32; x86 is our CLI spelling
    msbuild_platform = "Win32" if platform == "x86" else platform
    props = {
        "Configuration": "Release",
        "Platform": msbuild_platform,
        "ProjectName": name,
        "ProjectDir": repo.replace(os.sep, "/").rstrip("/") + "/",
        "SolutionDir": repo.replace(os.sep, "/").rstrip("/") + "/",
        "BeaconHttpLibrary": http,
        "BeaconBofWin": "true" if bofwin else "",
        "BeaconInjectPause": "true" if pause else "",
        "BeaconNoExcReg": "true" if no_exc else "",
        "BeaconDiagRetaddr": "1" if diag_ret else "",
        "BeaconLlvmLayout": "true" if layout else "",
        "BeaconLoaderPrivate": "true",
        "BeaconPlainSleep": "true" if plain_sleep else "",
        "CSOptimized": "MinSpace",
        # unset in the projects themselves; defines expand to "RefLoadSize="
        "RefLoadSize": "",
        "UDRLExtension": "",
    }
    # common.props: PropertyGroups first (toolset defaults), then its Release IDG
    common = ET.parse(os.path.join(repo, "common.props")).getroot()
    eval_property_groups(common, props)
    proj = Project(repo, name, props)
    merge_idg(common, props, proj)

    tree = ET.parse(os.path.join(repo, f"{name}.vcxproj"))
    root = tree.getroot()
    eval_property_groups(root, props)
    merge_idg(root, props, proj)
    proj.files = collect_files(root, props)
    if "TargetName" not in props:
        die(f"TargetName not derived for {name} {platform}")
    proj.target_name = props["TargetName"]
    return proj


# ----------------------------------------------------------------- compilers

def compile_flags(proj, platform, xwin_dir):
    cc = proj.clcompile
    flags = ["--target=" + TRIPLE[platform], "/nologo", "/c"]
    opt = expand_macros(cc.get("Optimization", ""), proj.props)
    if opt == "MinSpace":
        flags += ["/O1", "/Ob1", "/GF", "/Gy", "/Os"]
    elif opt == "MaxSpeed":
        flags += ["/O2", "/Ob1", "/GF", "/Gy", "/Ot"]
    elif opt == "Disabled":
        flags += ["/Od"]
    if cc.get("IntrinsicFunctions", "").lower() == "true":
        flags += ["/Oi"]
    if cc.get("FunctionLevelLinking", "").lower() == "true":
        flags += ["/Gy"]
    rt = cc.get("RuntimeLibrary", "")
    if rt == "MultiThreaded":
        flags += ["/MT"]
    elif rt == "MultiThreadedDebugDLL":
        flags += ["/MTd"]
    if cc.get("BufferSecurityCheck", "true").lower() == "false":
        flags += ["/GS-"]
    wl = cc.get("WarningLevel", "")
    flags += { "Level3": ["/W3"], "Level4": ["/W4"], "EnableAllWarnings": ["/Wall"] }.get(wl, ["/W3"])
    std = cc.get("LanguageStandard", "")
    if std:
        flags += ["/std:" + {"stdcpp17": "c++17", "stdcpp14": "c++14",
                             "stdcpp20": "c++20"}.get(std, std[len("std"):])]
    defines = expand_macros(cc.get("PreprocessorDefinitions", ""), proj.props)
    for d in defines.split(";"):
        d = d.strip()
        if d and d != "%(PreprocessorDefinitions)":
            flags.append("/D" + d)
    incs = expand_macros(cc.get("AdditionalIncludeDirectories", ""), proj.props)
    for i in incs.split(";"):
        i = i.strip()
        if i and i != "%(AdditionalIncludeDirectories)":
            flags.append("/I" + i)
    # deterministic include set beyond the project: source dir (quoted-include
    # resolution is unchanged; this only adds a fallback search dir) + xwin
    flags.append("/I" + proj.repo + "/src")
    flags.append("/I" + proj.repo + "/gen")
    for sub in ("crt/include", "sdk/include/ucrt", "sdk/include/um",
                "sdk/include/shared"):
        flags.append("/I" + xwin_dir + "/" + sub)
    return flags


def per_file_flags(meta, proj, is_c_file):
    fl = []
    compile_as = meta.get("CompileAs") or proj.clcompile.get("CompileAs", "")
    if is_c_file:
        # project-level CompileAsCpp forces .c files through the C++ FE unless
        # the file overrides with CompileAsC
        fl.append("/TC" if compile_as == "CompileAsC" else "/TP")
    extra = meta.get("PreprocessorDefinitions", "")
    for d in expand_macros(extra, proj.props).split(";"):
        d = d.strip()
        if d and d != "%(PreprocessorDefinitions)":
            fl.append("/D" + d)
    return fl


def link_command(proj, platform, xwin_dir, objs, out_dll, out_map):
    lk = proj.link
    flags = ["/NOLOGO", "/DLL", "/Brepro",
             "/ENTRY:_DllMainCRTStartup",  # 显式入口：lld 默认解析曾指向函数中段（RIP 落在指令内部）
             "/MACHINE:" + ("X64" if platform == "x64" else "X86")]
    if lk.get("SubSystem"):
        flags.append("/SUBSYSTEM:" + lk["SubSystem"].upper())
    if lk.get("GenerateManifest", "true").lower() == "false":
        flags.append("/MANIFEST:NO")
    if lk.get("OptimizeReferences", "").lower() == "true":
        flags.append("/OPT:REF")
    if lk.get("EnableCOMDATFolding", "").lower() == "true":
        flags.append("/OPT:ICF")
    flags.append("/OUT:" + out_dll)
    flags.append("/MAP:" + out_map)
    for libdir in arch_dirs(xwin_dir, platform):
        flags.append("/libpath:" + libdir)
    # repo root so the #pragma comment(lib, "lib/tomcrypt.x64.lib") relative
    # paths resolve (we always run with cwd = repo root)
    flags.append("/libpath:" + proj.repo)
    flags += DEFAULT_LIBS
    flags += objs
    return flags


# ------------------------------------------------------------ layout (two-pass)

LAYOUT_EXCLUDE = {".pdata", ".fptable", ".reloc", ".gfids", ".retplne",
                  "_RDATA", ".idata", ".edata", ".debug"}


def compute_regions(dll_bytes):
    """Mask regions per policy: headers + code/data sections, metadata-only
    sections excluded. Returns [(rva_begin, rva_end), ...]."""
    lf = struct.unpack_from("<I", dll_bytes, 0x3C)[0]
    nsec = struct.unpack_from("<H", dll_bytes, lf + 6)[0]
    optsz = struct.unpack_from("<H", dll_bytes, lf + 20)[0]
    soi = struct.unpack_from("<I", dll_bytes, lf + 24 + 56)[0]
    regions = [(0, 0x1000)]  # header page
    for i in range(nsec):
        off = lf + 24 + optsz + i * 40
        name = dll_bytes[off:off + 8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", dll_bytes, off + 8)
        chars = struct.unpack_from("<I", dll_bytes, off + 36)[0]
        if name in LAYOUT_EXCLUDE or (chars & 0x02000000):
            continue
        if va < 0x1000 or vsz == 0:
            continue
        ve = min(va + vsz, soi)
        regions.append((va, ve))
    return regions, soi


def write_layout_h(path, regions, soi):
    n = 16
    lines = ["#pragma once",
             "/* AUTO-GENERATED by tools/llvm/build.py from the linked image.",
             " * Fixed-size arrays: the pass-2 rebuild must not change layout. */",
             f"#define BW_LAYOUT_SOI        0x{soi:06X}ULL",
             "#define BW_LAYOUT_REG_MAX    %d" % n,
             "static const unsigned long long bw_layout_reg[BW_LAYOUT_REG_MAX][2] = {"]
    for i in range(n):
        if i < len(regions):
            a, b = regions[i]
            lines.append(f"    {{0x{a:X}ULL, 0x{b:X}ULL}},")
        else:
            lines.append("    {0ULL, 0ULL},")
    lines.append("};")
    lines.append(f"static const unsigned long long bw_layout_reg_n = {len(regions)}ULL;")
    body = "\n".join(lines) + "\n"
    import os as _os
    _os.makedirs(_os.path.dirname(path), exist_ok=True)
    changed = True
    if _os.path.exists(path):
        changed = open(path, encoding="utf-8").read() != body
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return changed


def verify_layout(dll_path, layout_h_path):
    """Final DLL's real section layout must match the compiled-in table."""
    regions, soi = compute_regions(open(dll_path, "rb").read())
    cur = open(layout_h_path, encoding="utf-8").read()
    ok = all(f"{{0x{a:X}ULL, 0x{b:X}ULL}}," in cur for a, b in regions)
    ok = ok and f"bw_layout_reg_n = {len(regions)}ULL" in cur
    ok = ok and f"BW_LAYOUT_SOI        0x{soi:06X}ULL" in cur
    return ok


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True,
                    choices=["beacon", "dnsb", "extc2", "pivot"])
    ap.add_argument("--platform", default="x64", choices=["x64", "x86"])
    ap.add_argument("--http", default="wininet", choices=["wininet", "winhttp"])
    ap.add_argument("--bofwin", action="store_true")
    ap.add_argument("--layout", action="store_true",
                    help="two-pass build: derive gen/layout.h from the linked "
                         "image and rebuild consumers (build-time self-description)")
    ap.add_argument("--plain-sleep", action="store_true",
                    help="force GargleSleep Sleep() passthrough (nook=0) - "
                         "LLVM section layout breaks the gen3 mask table")
    ap.add_argument("--diag-retaddr", action="store_true",
                    help="define BW_DIAG_RETADDR: log RNG caller return addresses")
    ap.add_argument("--no-excreg", action="store_true",
                    help="set BeaconNoExcReg=true (BW_NO_EXC_REG: skip "
                         "RtlAddFunctionTable registration)")
    ap.add_argument("--pause", action="store_true")
    ap.add_argument("--obf", default=None, metavar="PASS_SO",
                    help="enable Phase 3 mutation: load the pass plugin at "
                         "compile time (-fpass-plugin). Shape is driven by the "
                         "OBF_SEED env var (same seed = byte-identical, "
                         "different seed = different shape).")
    ap.add_argument("--clang-cl", default="clang-cl")
    ap.add_argument("--lld-link", default="lld-link")
    ap.add_argument("--xwin-dir", required=True)
    ap.add_argument("--repo", default=os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 2))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo).replace(os.sep, "/")
    xwin = os.path.abspath(args.xwin_dir).replace(os.sep, "/")
    proj = load_project(repo, args.project, args.platform, args.http,
                        args.bofwin, args.pause, args.no_excreg, args.diag_retaddr,
                        args.plain_sleep, args.layout)

    variant = f"{args.project}-{args.platform}-{args.http}"
    if args.bofwin:
        variant += "-rl0k"
    if args.pause:
        variant += "-pause"
    out_dir = args.out_dir or (repo + "/llvm-out")
    obj_dir = f"{out_dir}/obj/{variant}"
    os.makedirs(obj_dir, exist_ok=True)

    base_flags = compile_flags(proj, args.platform, xwin)
    tasks = []  # (obj_path, src, full_cmd)
    for src_rel, meta in proj.files:
        src = repo + "/" + src_rel
        if not os.path.exists(src):
            die(f"source missing: {src}")
        obj = f"{obj_dir}/{src_rel}.obj"
        os.makedirs(os.path.dirname(obj), exist_ok=True)
        is_c = src_rel.lower().endswith(".c")
        cmd = [args.clang_cl] + base_flags + per_file_flags(meta, proj, is_c) \
              + ["/Fo:" + obj, "/c", src]
        if args.obf:
            cmd += ["-fpass-plugin=" + args.obf]
        tasks.append((obj, src, cmd))

    dll = f"{out_dir}/{proj.target_name}.llvm.dll"
    mmap = f"{out_dir}/{proj.target_name}.llvm.map"
    link_cmd = [args.lld_link] + link_command(
        proj, args.platform, xwin, [t[0] for t in tasks], dll, mmap)

    layout_h = repo + "/gen/layout.h"
    if args.layout and not os.path.exists(layout_h):
        # 占位首遍：固定尺寸数组（零值），保证两遍的 .text/.rdata 尺寸不变
        os.makedirs(repo + "/gen", exist_ok=True)
        write_layout_h(layout_h, [], 0x400000)

    if args.dry_run:
        print(json.dumps({"variant": variant, "target_name": proj.target_name,
                          "sources": len(tasks), "dll": dll,
                          "defines": [f for f in base_flags if f.startswith("/D")]},
                         indent=1))
        for _, src, cmd in tasks[:3]:
            print("COMPILE", " ".join(cmd[:6]), "...", src)
        print("LINK", " ".join(link_cmd[:8]), f"... ({len(tasks)} objs)")
        return 0

    print(f"==> {variant}: {len(tasks)} TUs -> {dll}")
    failures = []

    def run_one(task):
        obj, src, cmd = task
        r = subprocess.run(cmd, capture_output=True, text=True,
                           cwd=repo, errors="replace")
        if r.returncode != 0:
            failures.append((src, cmd, r.stderr[-4000:]))
        elif r.stderr.strip():
            # surface warnings compactly but do not fail
            tail = "\n".join(r.stderr.strip().splitlines()[-6:])
            print(f"[warn] {os.path.basename(src)}:\n{tail}", flush=True)
        return r.returncode

    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for _ in ex.map(run_one, tasks):
            if failures:
                break
    if failures:
        for src, cmd, err in failures[:5]:
            print(f"FAILED: {src}\n  {' '.join(cmd[:10])} ...\n{err}",
                  file=sys.stderr)
        die(f"{len(failures)} compile failure(s) in {variant}")

    r = subprocess.run(link_cmd, capture_output=True, text=True, cwd=repo,
                       errors="replace")
    if r.returncode != 0:
        print(r.stdout[-4000:], file=sys.stderr)
        print(r.stderr[-4000:], file=sys.stderr)
        die(f"link failed for {variant}")

    if args.layout:
        regions, soi = compute_regions(open(dll, "rb").read())
        changed = write_layout_h(layout_h, regions, soi)
        if changed:
            print(f"==> {variant}: layout changed, pass 2 (rebuild consumers)")
            for task in tasks:
                srcf = task[1]
                if "/gargle." in srcf or srcf.endswith("gargle.cpp"):
                    subprocess.run(task[2], capture_output=True, text=True,
                                   cwd=repo, errors="replace")
            r2 = subprocess.run(link_cmd, capture_output=True, text=True,
                                cwd=repo, errors="replace")
            if r2.returncode != 0:
                print(r2.stdout[-4000:], file=sys.stderr)
                print(r2.stderr[-4000:], file=sys.stderr)
                die(f"pass-2 link failed for {variant}")
        if not verify_layout(dll, layout_h):
            # 布局又漂了（极少）：再生一次并终验
            regions, soi = compute_regions(open(dll, "rb").read())
            write_layout_h(layout_h, regions, soi)
            for task in tasks:
                if task[1].endswith("gargle.cpp"):
                    subprocess.run(task[2], capture_output=True, text=True,
                                   cwd=repo, errors="replace")
            subprocess.run(link_cmd, capture_output=True, text=True, cwd=repo)
            if not verify_layout(dll, layout_h):
                die(f"layout did not converge for {variant}")
        print(f"==> {variant}: layout verified ({len(regions)} regions)")

    size = os.path.getsize(dll)
    print(f"==> {variant}: {dll} ({size} bytes)")
    sizes_path = f"{out_dir}/_sizes.json"
    entries = []
    if os.path.exists(sizes_path):
        with open(sizes_path) as f:
            entries = json.load(f)
    entries.append({"variant": variant, "dll": os.path.basename(dll),
                    "bytes": size, "objs": len(tasks)})
    with open(sizes_path, "w") as f:
        json.dump(entries, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# archive — leftovers from the CMake standardization

Nothing here is deleted. These trees are off the product DAG
(`cmake --preset default|llvm`, `.github/workflows/ci.yml`).
CI and CMake do not read this directory.

## Layout

| subdir | what | why it left the product root |
|---|---|---|
| `llvm-driver/` | Retired Python/JSON variant driver: `layout_two_pass.py`, frozen `manifests/*.json`, `freeze_manifests.py`, `compare_exports.py`, `scan_seed.py`, `sizes_table.py`, the old `tools/llvm/CMakeLists.txt` (FATAL_ERROR), and `LLVM-MIGRATION.md` | Root CMake + `cmake/sources.cmake` + `apply_layout.py` replaced this. Manifests were a vcxproj freeze. |
| `live-scratch/_re/` | One-off patch/probe/CI-poll scripts from live sessions | Not a build input. |
| `trimmed-libs/` | `_trimmed.zip` and `_trimmed_out/*.lib` | Duplicate of vendored `lib/`. Rebuild recipe stays in `thirdparty/`. |
| `session-docs/` | CMD117 / NEXT / LIVE-HTTP / SLEEP-MASK handoff and feedback notes | Session logs, not product spec. Specs that remain in `docs/`: BUILD, WIRE-PROTOCOL, CONCURRENCY, MATRIX, INJECTION-412, EVASION-ROADMAP, LIVE-OPS. |
| `harness-history/` | `ec_stage2_harness_v5/v6/v7.py`, `fix_eclog_path.py` | Superseded by `tools/ec_stage2_harness.py`. |

## Still in the product tree (on purpose)

These look messy but CMake or CI still needs them, or they are product modules not yet on the DAG:

- `tools/llvm/pass/` — mutation plugin (`BEACON_OBF=ON`)
- `tools/llvm/apply_layout.py` — PE layout pass-1/verify
- `tools/llvm/gen_yara.py` — Linux CI YARA gate
- `tools/llvm/setup-host.sh` — pinned LLVM + xwin
- `tools/asyncbof/` — postex asyncdll
- `tools/earlycascade_scan.py`, `tools/ec_stage2_harness.py` — current EarlyCascade tools
- `evasion-lab/` — research lab (no CMake target yet)
- `covertvpn-v2/` — VPN driver sources (no CMake target yet)

To restore a file, `git mv` it back. Do not point CI at this folder.
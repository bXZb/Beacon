#!/usr/bin/env bash
# tools/llvm/setup-host.sh — pinned cross toolchain for the LLVM sidecar build.
#
# Installs, idempotently, under $HOME/.llvm-cross (cacheable by CI):
#   - LLVM $LLVM_VERSION (same release on Linux and Windows hosts so the
#     dual-host /Brepro byte-diff is meaningful)
#   - an xwin "splat" of the Windows SDK + MSVC CRT headers/libs (x86_64+x86)
#       crt/include, sdk/include/{ucrt,um,shared}
#       crt/lib/<arch>, sdk/lib/{um,ucrt}/<arch>
#
# Writes $HOME/.llvm-cross/toolpath.env (LLVM_CLANG/LLVM_LLD/LLVM_READOBJ/
# XWIN_SPLAT) for build steps to source. Mixed-style C:/ paths on windows —
# python subprocess/CreateProcess accepts forward slashes with a drive letter.
#
# Runs on ubuntu runners as-is; on windows runners use `shell: bash` (git-bash).
set -euo pipefail

LLVM_VERSION="${LLVM_VERSION:-19.1.7}"
XWIN_VERSION="${XWIN_VERSION:-0.10.0}"
ROOT="$HOME/.llvm-cross"
mkdir -p "$ROOT"

EXE=""   # .exe suffix on windows, empty on linux
OS="$(uname -s)"
case "$OS" in
  Linux)
    LLVM_BASE="$ROOT/llvm"
    if [[ ! -x "$LLVM_BASE/bin/clang-cl" ]]; then
      echo "==> fetching LLVM $LLVM_VERSION (linux)"
      curl -sSL --retry 3 -o "$ROOT/llvm.tar.xz" \
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-Linux-X64.tar.xz"
      mkdir -p "$LLVM_BASE"
      tar -xf "$ROOT/llvm.tar.xz" -C "$LLVM_BASE" --strip-components=1
      rm -f "$ROOT/llvm.tar.xz"
    fi
    XWIN_ASSET="xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    EXE=".exe"
    # pinned install under $ROOT (cacheable) — the runner's preinstalled
    # C:\Program Files\LLVM is an uncontrolled version, so we never use it
    LLVM_BASE="$(cygpath -u "$ROOT")/llvm-win"
    if [[ ! -x "$LLVM_BASE/bin/clang-cl.exe" ]]; then
      echo "==> installing LLVM $LLVM_VERSION (windows, pinned dir)"
      curl -sSL --retry 3 -o "$ROOT/llvm-inst.exe" \
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-win64.exe"
      # NSIS: /S silent; /D= must be LAST, unquoted, windows path
      WIN_DST="$(cygpath -w "$ROOT/llvm-win")"
      cmd //c "$(cygpath -w "$ROOT/llvm-inst.exe") /S /D=$WIN_DST"
      rm -f "$ROOT/llvm-inst.exe"
    fi
    XWIN_ASSET="xwin-${XWIN_VERSION}-x86_64-pc-windows-msvc.tar.gz"
    ;;
  *)
    echo "unsupported host: $OS" >&2; exit 1;;
esac

if [[ ! -d "$ROOT/xwin-splat/sdk/lib" ]]; then
  echo "==> fetching xwin $XWIN_VERSION + splatting SDK/CRT (x86_64+x86)"
  curl -sSL --retry 3 -o "$ROOT/xwin.tar.gz" \
    "https://github.com/Jake-Shadle/xwin/releases/download/${XWIN_VERSION}/${XWIN_ASSET}"
  tar -xzf "$ROOT/xwin.tar.gz" -C "$ROOT"
  XWIN_BIN="$(find "$ROOT" -maxdepth 2 -type f -name 'xwin*' ! -name '*.tar.gz' | head -1)"
  chmod +x "$XWIN_BIN" 2>/dev/null || true
  # --cache-dir must sit on the SAME drive as the splat output, else the
  # vsix->splat rename fails with "cannot move to a different disk drive"
  SPLAT_FLAGS=(--accept-license --arch x86_64 --arch x86
               --cache-dir "$ROOT/xwin-dl" splat --output "$ROOT/xwin-splat")
  if [[ "$OS" != Linux ]]; then
    # symlinked casings need dev mode on windows; real copies are equivalent
    SPLAT_FLAGS+=(--disable-symlinks)
  fi
  "$XWIN_BIN" "${SPLAT_FLAGS[@]}"
  rm -f "$ROOT/xwin.tar.gz"
fi

emit() { # emit VAR path — mixed-style on windows for python/CreateProcess
  if [[ "$OS" == Linux ]]; then echo "$1=\"$2\""; else echo "$1=\"$(cygpath -m "$2")\""; fi
}
{
  emit LLVM_CLANG   "$LLVM_BASE/bin/clang-cl$EXE"
  emit LLVM_LLD     "$LLVM_BASE/bin/lld-link$EXE"
  emit LLVM_READOBJ "$LLVM_BASE/bin/llvm-readobj$EXE"
  emit XWIN_SPLAT   "$ROOT/xwin-splat"
} > "$ROOT/toolpath.env"

echo "==> toolchain ready:"
"$LLVM_BASE/bin/clang-cl$EXE" --version | head -1
"$LLVM_BASE/bin/lld-link$EXE" --version | head -1 || true
cat "$ROOT/toolpath.env"

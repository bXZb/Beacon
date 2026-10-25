#!/usr/bin/env bash
# tools/llvm/setup-host.sh — pinned cross toolchain for the LLVM sidecar build.
#
# Installs, idempotently, under $HOME/.llvm-cross (cacheable by CI):
#   - LLVM $LLVM_VERSION (same release on Linux and Windows hosts so the
#     dual-host /Brepro byte-diff is meaningful)
#   - an xwin "splat" of the Windows SDK + MSVC CRT headers/libs (x64+x86)
#       crt/include, sdk/include/{ucrt,um,shared}
#       crt/lib/<arch>, sdk/lib/{um,ucrt}/<arch>
#
# Runs on ubuntu runners as-is; on windows runners use `shell: bash` (git-bash).
set -euo pipefail

LLVM_VERSION="${LLVM_VERSION:-19.1.7}"
XWIN_VERSION="${XWIN_VERSION:-0.10.0}"
ROOT="$HOME/.llvm-cross"
mkdir -p "$ROOT"

OS="$(uname -s)"
case "$OS" in
  Linux)
    LLVM_BASE="$ROOT/llvm"
    LLVM_CLANG="$LLVM_BASE/bin/clang-cl"
    if [[ ! -x "$LLVM_CLANG" ]]; then
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
    LLVM_BASE="/c/Program Files/LLVM"
    LLVM_CLANG="$LLVM_BASE/bin/clang-cl.exe"
    if [[ ! -x "$LLVM_CLANG" ]]; then
      echo "==> installing LLVM $LLVM_VERSION (windows)"
      curl -sSL --retry 3 -o "$ROOT/llvm-inst.exe" \
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-win64.exe"
      # NSIS silent install to the default dir
      "$ROOT/llvm-inst.exe" /S
      rm -f "$ROOT/llvm-inst.exe"
    fi
    XWIN_ASSET="xwin-${XWIN_VERSION}-x86_64-pc-windows-msvc.tar.gz"
    ;;
  *)
    echo "unsupported host: $OS" >&2; exit 1;;
esac

if [[ ! -d "$ROOT/xwin-splat/sdk/lib" ]]; then
  echo "==> fetching xwin $XWIN_VERSION + splatting SDK/CRT (x64+x86)"
  curl -sSL --retry 3 -o "$ROOT/xwin.tar.gz" \
    "https://github.com/Jake-Shadle/xwin/releases/download/${XWIN_VERSION}/${XWIN_ASSET}"
  tar -xzf "$ROOT/xwin.tar.gz" -C "$ROOT"
  XWIN_BIN="$(find "$ROOT" -maxdepth 2 -type f -name 'xwin*' | head -1)"
  chmod +x "$XWIN_BIN" 2>/dev/null || true
  if [[ "$OS" == Linux ]]; then
    "$XWIN_BIN" --accept-license --arch x86_64 --arch x86 \
      splat --output "$ROOT/xwin-splat"
  else
    # symlinked casings need dev mode on windows; real copies are equivalent
    "$XWIN_BIN" --accept-license --arch x86_64 --arch x86 \
      splat --disable-symlinks --output "$ROOT/xwin-splat"
  fi
  rm -f "$ROOT/xwin.tar.gz"
fi

echo "==> toolchain ready:"
"$LLVM_CLANG" --version | head -1
"$LLVM_BASE/bin/lld-link" --version | head -1 || true
ls "$ROOT/xwin-splat" || true

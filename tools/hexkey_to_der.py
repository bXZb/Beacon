#!/usr/bin/env python3
"""Convert hex publickey.txt (from DumpPublicKey) to DER for pack_settings.py."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("hexfile")
    ap.add_argument("outder")
    args = ap.parse_args()
    text = Path(args.hexfile).read_text(encoding="utf-8").strip()
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) % 2:
        raise SystemExit("odd hex length")
    data = bytes.fromhex(text)
    Path(args.outder).write_bytes(data)
    print(f"wrote {args.outder} ({len(data)} bytes)")


if __name__ == "__main__":
    main()

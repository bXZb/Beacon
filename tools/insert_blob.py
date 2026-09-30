#!/usr/bin/env python3
"""settings.bin (4096, XOR-masked) → C include string for settings_blob.inc"""
from __future__ import annotations

import argparse
from pathlib import Path

PATCH = 4096


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("settings_bin")
    ap.add_argument("out_inc")
    args = ap.parse_args()

    data = Path(args.settings_bin).read_bytes()
    if len(data) < PATCH:
        data = data + bytes([0x2E] * (PATCH - len(data)))
    else:
        data = data[:PATCH]

    lines = []
    for i in range(0, PATCH, 16):
        chunk = data[i : i + 16]
        lines.append('"' + "".join(f"\\x{b:02x}" for b in chunk) + '"')
    Path(args.out_inc).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out_inc}")


if __name__ == "__main__":
    main()

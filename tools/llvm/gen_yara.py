#!/usr/bin/env python3
"""gen_yara.py — Phase 3 YARA self-check rule generator.

Derives code signatures from the UNMUTATED baseline build's .text: four
32-byte windows at deterministic scan positions (high byte-diversity, no
long zero runs so we never grab padding). The rules are then asserted to
MATCH the baseline and NOT match the mutated build — proving the pass
reshaped every sampled code region.

Usage: gen_yara.py <baseline.dll> <out.yar>
"""
import struct
import sys


def text_section(d):
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, lf + 6)[0]
    o2 = struct.unpack_from("<H", d, lf + 20)[0]
    for i in range(n):
        off = lf + 24 + o2 + i * 40
        name = d[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", d, off + 8)
        if name == ".text" and rsz > 0:
            return d[rp:rp + rsz]
    raise SystemExit(".text not found")


def window_ok(b):
    if len(set(b)) < 16:          # low diversity = padding/align region
        return False
    if b.count(0) > 8:            # zero-heavy = pad/imm64 tail
        return False
    return True


def main():
    dll, out = sys.argv[1], sys.argv[2]
    d = open(dll, "rb").read()
    text = text_section(d)

    parts = []
    span = len(text)
    for k, frac in enumerate((0.10, 0.32, 0.55, 0.78)):
        pos = int(span * frac)
        found = None
        while pos + 32 <= span:
            w = text[pos:pos + 32]
            if window_ok(w):
                found = (pos, w)
                break
            pos += 1
        if found is None:
            raise SystemExit("no suitable window at frac %.2f" % frac)
        p, w = found
        hexpat = " ".join("%02X" % b for b in w)
        parts.append(
            'rule bw_sig_%d {\n'
            '  meta:\n'
            '    author = "beacon-llvm-matrix"\n'
            '    desc = "self signature: .text window @0x%x of the unmutated baseline"\n'
            '  strings:\n'
            '    $a = { %s }\n'
            '  condition:\n'
            '    $a\n'
            '}\n' % (k, p, hexpat))

    open(out, "w").write("\n".join(parts))
    print("wrote %d rules to %s" % (len(parts), out))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""gen_yara.py — Phase 3 YARA self-check rule generator (map-guided).

Samples 32-byte windows ONLY inside functions that came from OUR objects
(the lld map's object column contains "/obj/") — prebuilt CRT/static-lib
code is never processed by the mutation pass, so sampling there would
produce signatures the mutated build can never lose. Windows are checked
for byte diversity (no padding regions).

Usage: gen_yara.py <baseline.dll> <baseline.map> <out.yar>
"""
import re
import struct
import sys


def sections(d):
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, lf + 6)[0]
    o2 = struct.unpack_from("<H", d, lf + 20)[0]
    out = []
    for i in range(n):
        off = lf + 24 + o2 + i * 40
        name = d[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", d, off + 8)
        out.append((name, va, vsz, rp, rsz))
    return out


def rva_to_file(secs, rva):
    for name, va, vsz, rp, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return rp + (rva - va)
    return None


def our_function_ranges(map_path):
    """[(start_rva, end_rva)] for symbols whose object column has /obj/."""
    ranges = []
    cur = None
    for line in open(map_path, errors="replace"):
        m = re.match(r"\s*([0-9a-f]{4}):([0-9a-f]+)\s+(\S+)\s+([0-9a-f]{12,16})\s+(\S.*)",
                     line)
        if m:
            # the RVA lives in the Rva+Base column (group 4, image base
            # 0x180000000) — group 2 is only the section offset
            rva = int(m.group(4), 16) - 0x180000000
            obj = m.group(5).strip()
            if rva <= 0:
                continue
            if "/obj/" in obj or obj.endswith(".obj"):
                if cur is not None and cur[0] < rva:
                    ranges.append((cur[0], rva))
                cur = (rva, None)
    if cur is not None:
        ranges.append((cur[0], cur[0] + 0x1000))
    return ranges


def window_ok(b):
    if len(set(b)) < 16:
        return False
    if b.count(0) > 8:
        return False
    return True


def main():
    dll, mapp, out = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(dll, "rb").read()
    secs = sections(d)
    text = [s for s in secs if s[0] == ".text"][0]
    franges = our_function_ranges(mapp)
    if not franges:
        raise SystemExit("no our-obj function ranges found in map")

    parts = []
    TARGET = 8
    picked = 0
    i = len(franges) // 3
    dbg = {"small": 0, "nofile": 0, "badwin": 0}
    while i < len(franges) and picked < TARGET:
        start, end = franges[i]
        i += 1  # linear scan: ICF-folded functions share RVAs (span 0),
                # striding over them burns the sample budget
        span = end - start
        if span < 0x80:
            dbg["small"] += 1
            continue
        # window 0x40 bytes into the function (skip prologue), 32 bytes long
        rva = start + 0x40
        fo = rva_to_file(secs, rva)
        if fo is None:
            dbg["nofile"] += 1
            continue
        w = d[fo:fo + 32]
        if len(w) != 32 or not window_ok(w):
            dbg["badwin"] += 1
            continue
        hexpat = " ".join("%02X" % b for b in w)
        parts.append(
            'rule bw_sig_%d {\n'
            '  meta:\n'
            '    author = "beacon-llvm-matrix"\n'
            '    desc = "self signature: our-code function @rva 0x%x (obj-backed)"\n'
            '  strings:\n'
            '    $a = { %s }\n'
            '  condition:\n'
            '    $a\n'
            '}\n' % (picked, rva, hexpat))
        picked += 1
    if picked < 6:
        raise SystemExit("only %d windows sampled (franges=%d, dbg=%s, text=%s)"
                         % (picked, len(franges), dbg,
                            [(s[0], hex(s[1]), hex(s[2])) for s in secs[:3]]))

    open(out, "w").write("\n".join(parts))
    print("wrote %d rules (from %d our-obj functions) to %s" %
          (picked, len(franges), out))


if __name__ == "__main__":
    main()

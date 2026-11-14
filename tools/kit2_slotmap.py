# -*- coding: utf-8 -*-
"""kit2_slotmap.py - remap BOF wire reloc slot indexes from OUR 43-slot table
to the KIT's 16-slot table (by API name), then run the two-pipe harness.
ours: 0 LoadLibraryA/1 FreeLibrary/2 GetProcAddress/3 GetModuleHandleA/
      4 DataParse/5 DataPtr/6 DataInt/7 DataShort/8 DataLength/9 DataExtract/
      10 FAlloc/11 FReset/12 FAppend/13 FPrintf/14 FToString/15 FFree/
      16 FInt/17 BeaconOutput/18 BeaconPrintf
kit:  0 FAlloc/1 FReset/2 FAppend/3 FPrintf/4 FToString/5 FFree/6 FInt/
      7 DataParse/8 DataInt/9 DataShort/10 DataLength/11 DataExtract/
      12 BeaconOutput/13 BeaconPrintf/14 InputAvailable/15 InputRead"""
import struct
import sys

MAP = {4: 7, 5: None, 6: 8, 7: 9, 8: 10, 9: 11,
       10: 0, 11: 1, 12: 2, 13: 3, 14: 4, 15: 5, 16: 6,
       17: 12, 18: 13}


def remap_wire(full):
    b = bytearray(full)
    # relocs data @236 (bt_hello layout: 8CB+4bss+148text+36rdata+4data+16xdata+16pdata+4len)
    off = 236
    n = 0
    while off + 16 <= len(b) - 8:
        sec, typ, sym = struct.unpack_from("<ihh", b, off)
        if sym == 1028:
            break
        if 1024 <= sec <= 1031 and typ in (4, 9, 6):
            newsym = MAP.get(sym, MAP.get(sym))
            if sym in MAP:
                newsym = MAP[sym]
                if newsym is None:
                    print("drop reloc (no kit slot): ours=%d" % sym)
                else:
                    struct.pack_into("<h", b, off + 6, newsym)
                    n += 1
        off += 16
    print("remapped %d relocs" % n)
    return bytes(b)


if __name__ == "__main__":
    FULL = bytes.fromhex(open(r"C:\Users\Public\bt_hello_wire.hex").read().strip())
    w = remap_wire(FULL)
    open(r"C:\Users\Public\bt_hello_kitslot_wire.bin", "wb").write(w)
    print("written", len(w))

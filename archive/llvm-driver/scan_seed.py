#!/usr/bin/env python3
"""scan_seed.py — verify the mutation pass actually ran: the obf-bogo
volatile seed global carries the seed value into .data; scan for its
8-byte LE pattern. Usage: scan_seed.py <dll> <seed>   (prints hit count)
"""
import struct, sys

d = open(sys.argv[1], 'rb').read()
seed = int(sys.argv[2])
pat = struct.pack('<Q', (seed ^ 0xB70C1A2E4D9F8C37) & 0xFFFFFFFFFFFFFFFF)
print(d.count(pat))

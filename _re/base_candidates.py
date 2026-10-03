import pefile, struct

RUN = r"C:\Users\Administrator\Desktop\cobaltstrike\ci-artifacts\37103138557"
DLL = RUN + r"\beacon.x64.dll"
CRASH = 0xd350ca
AFTER = CRASH + 6

bases = [13828096, 14155776, 10551296, 13697024, 14155776, 13762560]

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

# import thunk slot rva -> "dll!name"
thunks = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        thunks[imp.address - pe.OPTIONAL_HEADER.ImageBase] = "%s!%s" % (dll, imp.name.decode() if imp.name else "ord%d" % imp.ordinal)
print("import thunk array spans: %s .. %s  (%d slots)" %
      (hex(min(thunks)), hex(max(thunks)), len(thunks)))

data = pe.__data__

for b in sorted(set(bases)):
    rva = CRASH - b
    if rva < 0:
        print("base %08X: negative rva, skip" % b); continue
    try:
        raw = pe.get_data(rva, 6)
    except Exception as e:
        print("base %08X rva %X: unreadable (%s)" % (b, rva, e)); continue
    hexs = " ".join("%02x" % x for x in raw)
    verdict = ""
    if raw[0] == 0xFF and raw[1] == 0x15:
        disp = struct.unpack("<i", raw[2:6])[0]
        slot = (AFTER - b) + disp
        verdict = "ff15 disp=%+d -> slot RVA %X = %s" % (disp, slot, thunks.get(slot, "NOT-A-THUNK"))
    print("base %08X  rva %06X  bytes[%s]  %s" % (b, rva, hexs, verdict))

# also scan the whole .text for every ff15/ff25 whose slot lands on a thunk,
# and report which of those call sites are plausible per-base matches
print("\n-- all IAT call sites (ff15) whose slot is a real thunk --")
hits = []
text = pe.sections[0]
tva, tsz = text.VirtualAddress, text.Misc_VirtualSize
td = pe.get_data(tva, tsz)
i = 0
while i < len(td) - 6:
    if td[i] == 0xFF and td[i+1] == 0x15:
        disp = struct.unpack("<i", td[i+2:i+6])[0]
        slot = tva + i + 6 + disp
        if slot in thunks:
            hits.append((tva + i, slot, thunks[slot]))
    i += 1
print("total %d; sample:" % len(hits))
for insn_rva, slot, name in hits[:8]:
    print("  insn %06X -> slot %X %s" % (insn_rva, slot, name))
# candidates whose insn rva equals crash rva for some base
for b in sorted(set(bases)):
    rva = CRASH - b
    for insn_rva, slot, name in hits:
        if insn_rva == rva:
            print("MATCH base %08X: insn %06X -> %s" % (b, insn_rva, name))

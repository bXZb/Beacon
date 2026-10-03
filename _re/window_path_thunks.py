import pefile, struct

RUN = r"C:\Users\Administrator\Desktop\cobaltstrike\ci-artifacts\37103138557"
MAP = RUN + r"\beacon.x64.map"
DLL = RUN + r"\beacon.x64.dll"
BASE = 0x180000000

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
thunks = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        thunks[imp.address - pe.OPTIONAL_HEADER.ImageBase] = "%s!%s" % (dll, imp.name.decode() if imp.name else "ord%d" % imp.ordinal)

syms = {}
order = []
for line in open(MAP, errors="replace"):
    parts = line.split()
    if len(parts) >= 4 and parts[0].startswith("0001:"):
        try:
            pref = int(parts[2], 16)
        except ValueError:
            continue
        syms[pref] = parts[1]
        order.append(pref)
order.sort()

watch = ["?g3_rc4", "g3_rc4", "g3_mask_all_cb", "g3_log", "gen3_sleep", "g3_stack_spoof_sleep",
         "g3_snapshot_blocks", "g3_child_sp", "g3_chk", "g3_log_n"]
print("== g3/gen3 function spans ==")
spans = []
for idx, pref in enumerate(order):
    name = syms[pref]
    if any(w in name for w in watch):
        end = order[idx + 1] if idx + 1 < len(order) else pref + 0x2000
        spans.append((pref - BASE, end - BASE, name))
        print("  rva %06X..%06X  %s" % (pref - BASE, end - BASE, name))

# scan every ff15/ff25 (incl. e8/e9 direct CRT calls) inside those spans
text = pe.sections[0]
tva, tsz = text.VirtualAddress, text.Misc_VirtualSize
td = pe.get_data(tva, tsz)
crt_syms = {p - BASE: syms[p] for p in order if any(k in syms[p] for k in ("memcpy", "memset", "memmove", "__security", "RTC_", "chkstk"))}

print("\n== calls inside window-path functions ==")
for lo, hi, name in spans:
    i = lo - tva
    endi = hi - tva
    while i < endi and i < len(td) - 6:
        rva = tva + i
        # ff15 / ff25 indirect through rip
        if td[i] == 0xFF and td[i+1] in (0x15, 0x25):
            disp = struct.unpack("<i", td[i+2:i+6])[0]
            slot = rva + 6 + disp
            tgt = thunks.get(slot, "rdata+%X(not thunk)" % slot)
            print("  [%s] rva %06X  ff%02x -> %s" % (name, rva, td[i+1], tgt))
            i += 6
            continue
        # e8 direct call
        if td[i] == 0xE8:
            disp = struct.unpack("<i", td[i+1:i+5])[0]
            tgt_rva = rva + 5 + disp
            tname = None
            for p in order:
                if p - BASE == tgt_rva:
                    tname = syms[p]; break
            if tname and any(k in tname.lower() for k in ("mem", "security", "rtc", "chkstk", "str", "rand")):
                print("  [%s] rva %06X  e8 -> %s" % (name, rva, tname))
            i += 5
            continue
        i += 1
print("done")

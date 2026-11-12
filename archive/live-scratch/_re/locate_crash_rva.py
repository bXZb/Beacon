import pefile, bisect

RUN = r"C:\Users\Administrator\Desktop\cobaltstrike\ci-artifacts\37103138557"
MAP = RUN + r"\beacon.x64.map"
DLL = RUN + r"\beacon.x64.dll"

CRASH_RVA = 0x230CA          # faulting call instruction
SLOT_RVA  = 0x230D0 + 0x1C220  # rip-after + disp32 = 0x3F2F0

# ---- 1) nearest map symbol at/below the crash RVA ----
syms = []
for line in open(MAP, errors="replace"):
    parts = line.split()
    if len(parts) >= 4 and parts[0].startswith("0001:"):
        try:
            pref = int(parts[2], 16)
        except ValueError:
            continue
        syms.append((pref, parts[1], parts[3] if len(parts) > 3 else ""))
syms.sort()
prefs = [s[0] for s in syms]
BASE = 0x180000000
i = bisect.bisect_right(prefs, BASE + CRASH_RVA) - 1
print("== crash RVA 0x%X context ==" % CRASH_RVA)
for j in range(max(0, i - 2), min(len(syms), i + 3)):
    mark = ">>" if j == i else "  "
    print("%s %08X rva=%06X  %s  (%s)" % (mark, syms[j][0], syms[j][0] - BASE, syms[j][1], syms[j][2][:60]))

# ---- 2) which import owns the IAT slot RVA ----
pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
th_base = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress  # IAT dir
print("\n== IAT slot RVA 0x%X ==" % SLOT_RVA)
found = False
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.address - pe.OPTIONAL_HEADER.ImageBase == SLOT_RVA:
            print("slot -> %s!%s  (hint %s)" % (dll, imp.name, imp.hint))
            found = True
if not found:
    print("slot not in import table; dumping raw bytes at slot RVA from file")
    data = pe.get_data(SLOT_RVA, 16)
    print(" ".join("%02x" % b for b in data))
    # also try thunk RVA directly bound to first thunk entries
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        ft = entry.struct.FirstThunk
        n = len(entry.imports)
        if ft <= SLOT_RVA < ft + 8 * n:
            imp = entry.imports[(SLOT_RVA - ft) // 8]
            print("within %s FirstThunk range -> %s" % (entry.dll.decode(), imp.name))

# ---- 3) section layout for reference ----
print("\n== sections ==")
for s in pe.sections:
    print("%-8s va=%06X vsz=%06X rawsz=%06X chars=%08X" %
          (s.Name.decode().rstrip('\x00'), s.VirtualAddress, s.Misc_VirtualSize,
           s.SizeOfRawData, s.Characteristics))

# -*- coding: utf-8 -*-
"""kit_iat_map.py - resolve the kit dll's IAT entries to import names so the
runner's indirect calls get identified statically."""
import struct

DLL = r"C:\Users\Public\kit_async.x64.dll"
d = open(DLL, "rb").read()

e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
opt = e_lfanew + 0x18
imp_rva = struct.unpack_from("<I", d, opt + 120)[0]   # data dir 1 (imports)

secs = []
nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
sect = e_lfanew + 0x18 + 0xF0
for i in range(nsec):
    s = sect + i * 40
    vsz, va, rsz, ro = (struct.unpack_from("<I", d, s + 8)[0],
                        struct.unpack_from("<I", d, s + 12)[0],
                        struct.unpack_from("<I", d, s + 16)[0],
                        struct.unpack_from("<I", d, s + 20)[0])
    secs.append((va, vsz, ro, rsz))


def rva2off(rva):
    for va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


iat = {}
o = rva2off(imp_rva)
while True:
    oft, tds, fc, name_rva, ft = struct.unpack_from("<IIIII", d, o)
    if name_rva == 0:
        break
    no = rva2off(name_rva)
    dllname = d[no:d.index(b"\x00", no)].decode()
    # thunk table
    t = rva2off(oft if oft else ft)
    idx = 0
    while True:
        val = struct.unpack_from("<Q", d, t + idx * 8)[0]
        if val == 0:
            break
        if val & (1 << 63):
            fname = "#ord%d" % (val & 0xFFFF)
        else:
            ho = rva2off(val & 0xFFFFFFFF)
            fname = d[ho + 2:d.index(b"\x00", ho + 2)].decode()
        # the IAT slot address = ft + idx*8
        iat[ft + idx * 8] = dllname + "!" + fname
        idx += 1
    o += 20

print("IAT entries:", len(iat))
# the runner's call sites: call [rip+disp] at addr A with len L -> slot = A+L+disp
for site, disp, tag in (
        (0x3e39, 0x2e2f1, "runner create-pipe"),
        (0x3ea6, 0x2e204, "runner loop wait"),
        (0x3eb7, 0x2e193, "runner loop sleep"),
        (0x3e49, 0x2e209, "create-fail path A"),
        (0x3e72, 0x2e220, "create-fail msgbox?"),
        (0x3e7c, 0x2e206, "create-fail path B"),
        (0x3e93, 0x2e2af, "post-create setter"),
        (0x3dd2, 0x2e5b8, "executor bswap"),
        (0x4581, 0x2dbe9, "bg loop read"),
        (0x4436, 0x2dc9c, "realmain create"),
        (0x44c5, 0x2dc1d, "realmain bg-thread"),
        (0x44f2, 0x2dbd0, "bg loop reset"),
        (0x451b, 0x2dc57, "bg loop call"),
        (0x4529, 0x2db29, "bg wait"),
        (0x453d, 0x2db0d, "bg sleep"),
        (0x45de, 0x2db0c, "bg closehandle"),
        (0x45ec, 0x2daee, "bg terminate"),
        (0x4605, 0x2da5a, "bg closehandle2"),
        (0x16a1, 0x30ce9, "exec bswap1"),
        (0x180b, 0x30927, "exec heap-write"),
):
    L = {0x16a1: 5, 0x3e39: 6, 0x3ea6: 6, 0x3eb7: 6, 0x3e49: 6, 0x3e72: 6,
         0x3e7c: 6, 0x3e93: 6, 0x3dd2: 6, 0x4581: 6, 0x4436: 6, 0x44c5: 6,
         0x44f2: 6, 0x451b: 6, 0x4529: 6, 0x453d: 6, 0x45de: 6, 0x45ec: 6,
         0x4605: 6, 0x4608: 6, 0x180b: 6}.get(site, 6)
    slot = site + L + disp
    print("%-22s @%04x -> IAT %05x = %s" % (tag, site, slot, iat.get(slot, "?")))

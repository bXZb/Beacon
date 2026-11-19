from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()
NL = b"\r\n" if b"\r\n" in t[:400] else b"\n"

# The wire order is TEXT, RDATA, DATA, XDATA, PDATA (BSS has NO wire blob -
# it is allocated from bssSize). Both parse loops must read FIVE len-strs,
# skipping BSS by INDEX not by stopping.
old1 = (b"\tbssSize = dp_int(&d);" + NL +
        b"\tfor (i = 0; i < SEC_MAX; i++) {" + NL +
        b"\t\tif (i == SEC_BSS) break;" + NL +
        b"\t\tsecs[i] = dp_lenstr(&d, &seclen[i]);" + NL +
        b"\t}" + NL +
        b"\trelocs = dp_lenstr(&d, &relocLen);")
new1 = (b"\tbssSize = dp_int(&d);" + NL +
        b"\t/* wire order: text, rdata, data, xdata, pdata (BSS has no blob -\r\n"
        b"\t * it is allocated from bssSize). The old loop STOPPED at SEC_BSS(3),\r\n"
        b"\t * consuming only 3 of 5 sections and leaving entry=0 -> exec at the\r\n"
        b"\t * all-zero text base (C-22 dump: rip=text+0, bytes 00 00). */\r\n"
        b"\tfor (i = 0; i < SEC_MAX; i++) {" + NL +
        b"\t\tif (i == SEC_BSS) continue;" + NL +
        b"\t\tsecs[i] = dp_lenstr(&d, &seclen[i]);" + NL +
        b"\t}" + NL +
        b"\trelocs = dp_lenstr(&d, &relocLen);")
assert old1 in t, "parse loop anchor"
t = t.replace(old1, new1, 1)

old2 = (b"\td2.b = wire; d2.n = wireLen;" + NL +
        b"\tdp_int(&d2);" + NL +
        b"\tfor (i = 0; i < SEC_MAX; i++) {" + NL +
        b"\t\tif (i == SEC_BSS) break;" + NL +
        b"\t\t{" + NL +
        b"\t\t\tint l; char * p = dp_lenstr(&d2, &l);" + NL +
        b"\t\t\tif (p && l > 0) memcpy(secs[i], p, l);" + NL +
        b"\t\t}" + NL +
        b"\t}")
new2 = (b"\td2.b = wire; d2.n = wireLen;" + NL +
        b"\tdp_int(&d2);" + NL +
        b"\tfor (i = 0; i < SEC_MAX; i++) {" + NL +
        b"\t\tif (i == SEC_BSS) continue;" + NL +
        b"\t\t{" + NL +
        b"\t\t\tint l; char * p = dp_lenstr(&d2, &l);" + NL +
        b"\t\t\tif (p && l > 0) memcpy(secs[i], p, l);" + NL +
        b"\t\t}" + NL +
        b"\t}")
assert old2 in t, "copy loop anchor"
t = t.replace(old2, new2, 1)
p.write_bytes(t)
print("both loops fixed: continue over BSS, read all 5 sections")

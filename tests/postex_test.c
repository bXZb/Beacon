/*
 * postex_test.c - 4.10 execute-dll parity test DLL.
 *
 * Dual contract so it works with BOTH loaders:
 *   - 4.9 lineage postex loader (our sleeve): everything runs from
 *     DllMain(PROCESS_ATTACH); user arguments arrive through the patched
 *     gPostexUserArgs buffer (gPostexArgumentsBuffer carries the size).
 *   - 4.10 Postex Kit loader: DllMain(DLL_POSTEX_ATTACH=4) with arguments
 *     in lpReserved (the thread parameter), kit chunk framing.
 *
 * Markers (patched client-side):
 *   "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE"
 *   "_POSTEX_ARGUMENTS_"        (POSTEX_ARGUMENTS struct)
 *   "__POSTEX_USER_ARGS__"      (bof_pack blob, 4.9 path)
 *
 * Live proof markers:
 *   POSTEXOK arglen=<n> int=<i> str=<s> / JOBDATA <text> / POSTEXDONE
 */
#include <windows.h>

#define DLL_POSTEX_ATTACH 4
#define CALLBACK_OUTPUT   0
#define MAX_PACKET_SIZE   (1024 * 1024)

/* kit markers - do not change */
volatile const char gPipeName[] = "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";
volatile char gPostexArgumentsBuffer[20] = "_POSTEX_ARGUMENTS_";
/* 4.9-lineage sleeve-loader config marker (PostExLoader patches it with the
 * magic/key/cleanup config; the stub scans for the patched magic before it
 * runs the DllMain(1) + DllMain(4, param) sequence) */
volatile char gLoaderConfig[24] = "ZZZZZZZXXXXWYYYY";
/* 4.9-path argument blob (patched in place) */
volatile char gPostexUserArgs[256] = "__POSTEX_USER_ARGS__";

typedef struct {
	DWORD ExitFunc;
	char  ObfuscateKey[4];
	char  CleanupLoader;
	int   MaxPacketSize;
	int   UserArgumentBufferSize;
} POSTEX_ARGUMENTS;

static HANDLE gPipe = INVALID_HANDLE_VALUE;
static char gChunk[4112]; /* no CRT (__chkstk): keep big buffers off the stack */

static void copy_bytes(char * dst, const char * src, unsigned int n) {
	unsigned int i;
	for (i = 0; i < n; i++) {
		dst[i] = src[i];
	}
}

static unsigned int swap32(unsigned int v) {
	return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
}

/* kit BeaconOutput framing: one WriteFile message per chunk
 * { int32 BE len(=4+payload), int32 BE flags|chunkId, int32 BE type, payload } */
static void out(int type, const char * data, int length) {
	char       * chunk = gChunk;
	unsigned int payload = length;
	unsigned int flags   = 1 << 16; /* final chunk */
	unsigned int len     = 4 + payload;

	if (12 + payload > 4112 - 16) {
		payload = 4112 - 16 - 12;
		len = 4 + payload;
	}

	((unsigned int *)chunk)[0] = swap32(len);
	((unsigned int *)chunk)[1] = swap32(flags);
	((unsigned int *)chunk)[2] = swap32((unsigned int)type);
	copy_bytes(chunk + 12, data, payload);

	WriteFile(gPipe, chunk, 12 + payload, NULL, NULL);
}

static void outf(const char * fmt, const char * a, int b) {
	/* tiny two-argument formatter keeps this CRT-free */
	char buf[512];
	int  i = 0;
	const char * p = fmt;
	const char * s = a;
	char num[12];
	int  n = 0;
	int  v = b;

	while (*p && i < 500) {
		if (p[0] == '%' && p[1] == 's') {
			while (s && *s && i < 500) buf[i++] = *s++;
			p += 2;
		}
		else if (p[0] == '%' && p[1] == 'd') {
			if (v < 0) { buf[i++] = '-'; v = -v; }
			if (v == 0) num[n++] = '0';
			while (v > 0 && n < 11) { num[n++] = (char)('0' + (v % 10)); v /= 10; }
			while (n > 0 && i < 500) buf[i++] = num[--n];
			p += 2;
		}
		else {
			buf[i++] = *p++;
		}
	}
	buf[i] = 0;
	out(CALLBACK_OUTPUT, buf, i);
}

static DWORD input_available(void) {
	DWORD avail = 0;
	if (!PeekNamedPipe(gPipe, NULL, 0, NULL, &avail, 0)) {
		return 0;
	}
	return avail;
}

static BOOL input_read(char * buffer, DWORD length) {
	DWORD got = 0;
	return ReadFile(gPipe, buffer, length, &got, NULL) && got == length;
}

static void postex_main(char * args, int alen) {
	int   ival = 0;
	char *str  = NULL;

	outf("POSTEXOK arglen=%d\n", NULL, alen);

	if (args != NULL && alen >= 4) {
		/* bof_pack "i": raw int32 (z-strings arrive beacon-encoded; the
		 * official kit decodes them via BeaconDataExtract, our test DLL
		 * only asserts the raw int) */
		copy_bytes((char *)&ival, args, 4);
		ival = (int)swap32((unsigned int)ival); /* bof_pack ships big-endian */
		outf("POSTEXARG int=%d\n", NULL, ival);
	}

	/* wait ~60s for bjob_send_data to push something through the pipe */
	for (int t = 0; t < 60; t++) {
		DWORD n = input_available();
		if (n > 0) {
			char b[256];
			if (n > 255) {
				n = 255;
			}
			if (input_read(b, n)) {
				b[n] = 0;
				outf("JOBDATA %s", b, 0);
			}
		}
		Sleep(1000);
	}

	out(CALLBACK_OUTPUT, "POSTEXDONE\n", 11);
}

static void debug_mark(const char * name, int value) {
	HANDLE f = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	char b[24];
	int i = 0;
	if (value >= 0) {
		char num[12];
		int n = 0;
		int v = value;
		if (v == 0) num[n++] = '0';
		while (v > 0 && n < 11) { num[n++] = (char)('0' + (v % 10)); v /= 10; }
		while (n && i < 20) b[i++] = num[--n];
	}
	b[i] = 0;
	if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, b, i, &w, NULL); CloseHandle(f); }
}

static BOOL run_postex(char * args, int alen) {
	gPipe = CreateNamedPipeA((LPCSTR)gPipeName, PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1,
		MAX_PACKET_SIZE, MAX_PACKET_SIZE, 0, NULL);
	if (gPipe == INVALID_HANDLE_VALUE) {
		debug_mark("C:\Users\Public\postex_pipe_err.txt", (int)GetLastError());
		return FALSE;
	}
	debug_mark("C:\Users\Public\postex_dllmain.txt", alen);

	if (!ConnectNamedPipe(gPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
		CloseHandle(gPipe);
		return FALSE;
	}

	postex_main(args, alen);

	FlushFileBuffers(gPipe);
	DisconnectNamedPipe(gPipe);
	CloseHandle(gPipe);
	return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
	POSTEX_ARGUMENTS * pa;

	if (reason == DLL_POSTEX_ATTACH) {
		/* 4.10 kit loader: arguments ride lpReserved */
		return run_postex((char *)reserved, ((POSTEX_ARGUMENTS *)gPostexArgumentsBuffer)->UserArgumentBufferSize);
	}

	if (reason == DLL_PROCESS_ATTACH) {
		/* 4.9 lineage loader: arguments patched into gPostexUserArgs */
		pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;
		if (pa->UserArgumentBufferSize > 0) {
			return run_postex((char *)gPostexUserArgs, pa->UserArgumentBufferSize);
		}
		return run_postex(NULL, 0);
	}

	return TRUE;
}

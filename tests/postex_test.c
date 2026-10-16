/*
 * postex_test.c - 4.10 execute-dll parity test DLL (Postex Kit contract).
 *
 * Mirrors the official Postex Kit (arsenal-kit 20240716) template:
 *   - gPipeName: patched client-side (same marker string as the kit)
 *   - gPostexArgumentsBuffer: patched with POSTEX_ARGUMENTS
 *   - DllMain(DLL_POSTEX_ATTACH=4) starts the message-mode duplex pipe
 *     server, Beacon hands it arguments via lpReserved, output travels in
 *     the kit's big-endian chunk framing (see base/beacon.cpp of the kit).
 *
 * Live proof markers:
 *   POSTEXOK arglen=<n> int=<i> str=<s>   (bof_pack iz arguments)
 *   JOBDATA <text>                        (bjob_send_data round trip)
 *   POSTEXDONE                            (clean exit)
 */
#include <windows.h>

#define DLL_POSTEX_ATTACH 4
#define CALLBACK_OUTPUT   0
#define CALLBACK_ERROR    0x1f
#define MAX_PACKET_SIZE   (1024 * 1024)

/* kit markers - do not change */
volatile const char gPipeName[] = "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";
volatile char gPostexArgumentsBuffer[20] = "_POSTEX_ARGUMENTS_";

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
		/* bof_pack "iz": int32 then z-string */
		copy_bytes((char *)&ival, args, 4);
		str = args + 4;
		outf("POSTEXARG int=%d str=%s\n", str, ival);
	}

	/* wait ~25s for bjob_send_data to push something through the pipe */
	for (int t = 0; t < 25; t++) {
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

BOOL APIENTRY DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
	POSTEX_ARGUMENTS * pa;

	if (reason == DLL_POSTEX_ATTACH) {
		pa = (POSTEX_ARGUMENTS *)gPostexArgumentsBuffer;

		gPipe = CreateNamedPipeA((LPCSTR)gPipeName, PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1,
			MAX_PACKET_SIZE, MAX_PACKET_SIZE, 0, NULL);
		if (gPipe == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		if (!ConnectNamedPipe(gPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
			CloseHandle(gPipe);
			return FALSE;
		}

		postex_main((char *)reserved, pa->UserArgumentBufferSize);

		FlushFileBuffers(gPipe);
		DisconnectNamedPipe(gPipe);
		CloseHandle(gPipe);
		return TRUE;
	}

	return TRUE;
}

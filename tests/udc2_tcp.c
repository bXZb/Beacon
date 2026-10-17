/*
 * udc2_tcp.c - 4.12 UDC2 test BOF: a TCP channel over the udc2-vs contract.
 *
 * BOF-packaging rules learned during bring-up (docs/TIER2-BATTLE.md):
 *  - all imports as dll$func dynamic declarations
 *  - /O0 /Gy- /Gw-: no auto-vectorization (movdqa alignment), single
 *    .text (COMDAT sections get dropped), no split string .rdata
 *  - literal-free strings
 *
 * Bring-up bisect stage: go() marks steps and installs trivial
 * proxy/close stubs (NO winsock yet). If the beacon boots through the
 * config with markers 1 and 10, winsock gets layered back next.
 */
#include <winsock2.h>
#include <windows.h>

typedef int(*UDC2PROXY)(const char *, int, char *, int);
typedef void(*UDC2CLOSE)(void);

typedef struct {
	DWORD     version;
	UDC2PROXY proxy;
	UDC2CLOSE close;
} UDC2INFO;

EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

static void path_udc2_step(char * buf, int max) {
	char parts[30];
	int i;
	parts[0]='C'; parts[1]=':'; parts[2]='\\'; parts[3]='U'; parts[4]='s';
	parts[5]='e'; parts[6]='r'; parts[7]='s'; parts[8]='\\'; parts[9]='P';
	parts[10]='u'; parts[11]='b'; parts[12]='l'; parts[13]='i'; parts[14]='c';
	parts[15]='\\'; parts[16]='u'; parts[17]='d'; parts[18]='c'; parts[19]='2';
	parts[20]='_'; parts[21]='s'; parts[22]='t'; parts[23]='e'; parts[24]='p';
	parts[25]='.'; parts[26]='t'; parts[27]='x'; parts[28]='t'; parts[29]=0;
	for (i = 0; parts[i] && i < max - 1; i++)
		buf[i] = parts[i];
	buf[i] = 0;
}

static void mark(int v) {
	char path[40];
	HANDLE f;
	char b[16];
	int i = 0;
	char num[12];
	int n = 0;
	int x = v;
	DWORD w;

	path_udc2_step(path, 40);
	f = kernel32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	if (x == 0)
		num[n++] = '0';
	while (x > 0 && n < 11) {
		num[n++] = (char)('0' + (x % 10));
		x /= 10;
	}
	while (n && i < 14)
		b[i++] = num[--n];
	b[i] = 0;
	kernel32$WriteFile(f, b, i, &w, NULL);
	kernel32$CloseHandle(f);
}

/* stage stubs: proxy returns -1 (error) so the beacon falls back cleanly */
static int stub_proxy(const char * a, int b, char * c, int d) {
	(void)a; (void)b; (void)c; (void)d;
	mark(20);
	return -1;
}

static void stub_close(void) {
	mark(21);
}

void go(UDC2INFO * info) {
	mark(1);

	if (info == NULL)
		return;

	mark(2);
	info->proxy = stub_proxy;
	info->close = stub_close;
	mark(10);
}

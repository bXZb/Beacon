/* tier2 item6 diagnostic: does the BOF loader relocate ADDR64 references
 * to INTERNAL symbols (taking a function's address)? The UDC2 contract
 * (info->proxy = udc2Proxy) depends on it. Run via the proven
 * inline_execute channel: marker file SELFPTR 42 = works; nothing/crash =
 * the internal ADDR64 path is broken. bof_args-style dynamic imports +
 * marker file (no BeaconPrintf dependency). */
#include <windows.h>

EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

static char g_path[] = "C:\\Users\\Public\\selfptr_probe.txt";

static int forty_two(void) {
	return 42;
}

void go(char * args, int len)
{
	int (*fn)(void);
	int v;
	char buf[16];
	int i;
	DWORD wr = 0;
	HANDLE h;

	fn = forty_two;
	v = fn();

	buf[0] = 'S'; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F'; buf[4] = 'P';
	buf[5] = 'T'; buf[6] = 'R'; buf[7] = ' ';
	if (v == 0) {
		buf[8] = '0';
		i = 9;
	}
	else {
		char num[12];
		int n = 0;
		int x = v;
		while (x > 0 && n < 11) { num[n++] = (char)('0' + (x % 10)); x /= 10; }
		i = 8;
		while (n && i < 14) buf[i++] = num[--n];
	}
	buf[i] = 0;

	h = kernel32$CreateFileA(g_path, GENERIC_WRITE, 0, NULL,
	                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	kernel32$WriteFile(h, buf, (DWORD)i, &wr, NULL);
	kernel32$CloseHandle(h);
}

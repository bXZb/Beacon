/* P3 admission-matrix BOF (mixed cell): a Beacon API import
 * (BeaconPrintf via the __imp_ bapi whitelist -> ftable) MIXED with
 * dynamic kernel32 imports in the same object. boff.cpp must classify
 * it beacon_api_used and run it UNMASKED - "bofwin skipped
 * (api/nook/threads)" in the output and the BeaconPrintf text still
 * delivered. The mixed class must never enter the masked window (any
 * ftable call would execute ciphertext beacon .text). */
#include <windows.h>

#define CALLBACK_OUTPUT 0x00

EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, char * fmt, ...);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTickCount(void);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

static char g_path[] = "C:\\Users\\Public\\bw_mixed_probe.txt";
static char g_msg[] = "MIXED-RAN-UNMASKED";
static char g_fmt[] = "mixed bof ran unmasked: tick=%lu argslen=%d\n";

void go(char * args, int len)
{
	DWORD tick = kernel32$GetTickCount();
	DWORD wr = 0;
	HANDLE h;

	h = kernel32$CreateFileA(g_path, GENERIC_WRITE, 0, NULL,
	                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		kernel32$WriteFile(h, g_msg, 18, &wr, NULL);
		kernel32$CloseHandle(h);
	}
	BeaconPrintf(CALLBACK_OUTPUT, g_fmt, tick, len);
	(void)args;
}

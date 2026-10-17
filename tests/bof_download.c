/* tier-3 item 9: BeaconDownload BOF API live-fire BOF.
 *
 * Stages a deterministic pattern buffer in memory (BOF-owned .bss, no CRT
 * heap needed), hands it to BeaconDownload("tier3_dl.bin"), and prints the
 * API verdict. The live test hashes the file that lands in the team
 * server's downloads/ view and compares it against the same pattern
 * regenerated offline.
 *
 * Import shape follows the P3 admission-matrix BOFs: BeaconDownload rides
 * the __imp_ bapi whitelist into the ftable, kernel32 helpers go through
 * dynamic dll$func imports so the object stays free of static CRT/kernel32
 * references the linker cannot resolve. */
#include <windows.h>

EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, char * fmt, ...);
EXTERN_C __declspec(dllimport) BOOL __cdecl BeaconDownload(const char * filename, const char * buffer, unsigned int length);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$GetProcessHeap(void);
EXTERN_C __declspec(dllimport) LPVOID WINAPI kernel32$HeapAlloc(HANDLE, DWORD, SIZE_T);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$HeapFree(HANDLE, DWORD, LPVOID);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#define DL_SIZE (64 * 1024)

static char g_buf[DL_SIZE];

void go(char * args, int alen)
{
	BOOL ok;
	char hex[16] = "0123456789abcdef";
	unsigned int i;
	int seed = 0;

	/* optional decimal ASCII seed in the raw args string */
	if (args != NULL && alen >= 1) {
		char * p;
		for (p = args; *p >= '0' && *p <= '9'; p++)
			seed = seed * 10 + (*p - '0');
	}

	for (i = 0; i + 12 <= DL_SIZE; i += 12) {
		unsigned int v = (unsigned int)seed + (i / 12);
		g_buf[i + 0] = 'T'; g_buf[i + 1] = 'I'; g_buf[i + 2] = 'E'; g_buf[i + 3] = 'R';
		g_buf[i + 4] = '3'; g_buf[i + 5] = 'D'; g_buf[i + 6] = 'L'; g_buf[i + 7] = ':';
		g_buf[i + 8]  = hex[(v >> 28) & 0xF];
		g_buf[i + 9]  = hex[(v >> 24) & 0xF];
		g_buf[i + 10] = hex[(v >> 20) & 0xF];
		g_buf[i + 11] = '\n';
	}

	ok = BeaconDownload("tier3_dl.bin", g_buf, DL_SIZE);

	BeaconPrintf(ok ? CALLBACK_OUTPUT : CALLBACK_ERROR,
		"bof_download: BeaconDownload(%u bytes, seed %d) -> %s",
		DL_SIZE, seed, ok ? "TRUE" : "FALSE");

	/* official contract says Beacon made its own copy; the .bss buffer
	   simply goes back to sleep with the beacon */
}

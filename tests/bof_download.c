/* tier-3 item 9: BeaconDownload BOF API live-fire BOF.
 *
 * Stages a deterministic pattern buffer in memory (BOF-owned heap, freed
 * right after the API call - proving Beacon's own copy), hands it to
 * BeaconDownload("tier3_dl.bin"), and prints the API verdict. The live
 * test hashes the file that lands in the team server's downloads/ view
 * and compares it against the same pattern regenerated offline.
 *
 * Pattern: 64KiB of "TIER3DL:xxxxxxx\n" 12-byte lines salted by an int
 * seed packed as the task args (bof_pack i -> 4-byte LE prefix, read the
 * same way BeaconDataInt would). */
#include <windows.h>

EXTERN_C __declspec(dllimport) BOOL __cdecl BeaconDownload(const char * filename, const char * buffer, unsigned int length);
EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, char * fmt, ...);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#define DL_SIZE (64 * 1024)

void go(char * args, int alen)
{
	char * buf;
	unsigned int i;
	int seed = 0;
	BOOL ok;
	char hex[16] = "0123456789abcdef";

	/* optional packed arg: the pattern seed as a decimal ASCII string
	 * (the harness ships raw console text, so parse digits manually) */
	if (args != NULL && alen >= 1) {
		char * p;
		for (p = args; *p >= '0' && *p <= '9'; p++)
			seed = seed * 10 + (*p - '0');
	}

	buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DL_SIZE);
	if (buf == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "bof_download: HeapAlloc failed");
		return;
	}

	for (i = 0; i + 12 <= DL_SIZE; i += 12) {
		unsigned int v = (unsigned int)seed + (i / 12);
		buf[i + 0] = 'T'; buf[i + 1] = 'I'; buf[i + 2] = 'E'; buf[i + 3] = 'R';
		buf[i + 4] = '3'; buf[i + 5] = 'D'; buf[i + 6] = 'L'; buf[i + 7] = ':';
		buf[i + 8]  = hex[(v >> 28) & 0xF];
		buf[i + 9]  = hex[(v >> 24) & 0xF];
		buf[i + 10] = hex[(v >> 20) & 0xF];
		buf[i + 11] = '\n';
	}

	ok = BeaconDownload("tier3_dl.bin", buf, DL_SIZE);

	/* free our original immediately: official contract says Beacon made
	 * its own copy and the BOF may keep running / release the memory */
	HeapFree(GetProcessHeap(), 0, buf);

	BeaconPrintf(ok ? CALLBACK_OUTPUT : CALLBACK_ERROR,
		"bof_download: BeaconDownload(%u bytes, seed %d) -> %s",
		DL_SIZE, seed, ok ? "TRUE" : "FALSE");
}

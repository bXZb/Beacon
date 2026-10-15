/* BOF-PE test payload (4.13 inline-execute-pe parity).
 *
 * A real DLL that mixes a standard kernel32 import (marker file write)
 * with a virtual beacon.dll import (BeaconPrintf) so the beacon-side PE
 * loader proves both resolution paths:
 *   - kernel32!CreateFileA/WriteFile/CloseHandle via LoadLibrary/IAT
 *   - beacon.dll!BeaconPrintf plugged straight into BOFF_FUNCTIONS
 *
 * The PE loader executes the exported `go` (BOF entry contract) and the
 * operator sees "BOFPEOK" on disk plus a BeaconPrintf line in the console.
 */
#include <windows.h>

/* the loader substitutes these from the BOFF_FUNCTIONS table */
EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, const char * fmt, ...);

#define BOFPE_CALLBACK_OUTPUT 0x00

static char g_path[]  = "C:\\Users\\Public\\bw_bofpe_probe.txt";
static char g_magic[] = "BOFPEOK";

__declspec(dllexport) void __cdecl go(const char * args, int len)
{
	HANDLE f;
	DWORD w = 0;

	(void)args;
	(void)len;

	f = CreateFileA(g_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
	                FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		WriteFile(f, g_magic, (DWORD)sizeof(g_magic) - 1, &w, NULL);
		CloseHandle(f);
		BeaconPrintf(BOFPE_CALLBACK_OUTPUT, "BOF-PE marker written (%d bytes)", (int)w);
	}
	else {
		BeaconPrintf(BOFPE_CALLBACK_OUTPUT, "BOF-PE CreateFileA failed %lu",
		             (unsigned long)GetLastError());
	}
}

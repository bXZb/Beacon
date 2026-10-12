/* P3 admission-matrix BOF (args + entry-shape cell): Win32-only through
 * dynamic dll$func imports - zero ftable/Beacon-API relocations, so
 * boff.cpp admits it to the BOFWIN masked window. Reads its args blob
 * MID-WINDOW and writes the exact bytes plus in-window forensics to a
 * marker file.
 *
 * Proves four contracts at once:
 *  - bofwin_window's pre-mask args copy: the wire blob points into the
 *    tracked task buffer (ciphertext mid-window); without the private
 *    plaintext copy the file would contain RC4 garbage.
 *  - dynamic imports (kernel32$Func -> the client's dll!func packer
 *    path) land in untracked ftable other[] slots and stay callable
 *    while the entire beacon image is ciphertext.
 *  - ENTRY SHAPE from inside a real compiled BOF: the round-1..4 enter
 *    shapes entered with rsp%16==0 and no shadow - a compiled prologue
 *    would fault. _AddressOfReturnAddress()%16 must be 8 (ABI-perfect
 *    call entry) and _ReturnAddress()&0xFFF must be 0x080 ([rsp] is
 *    exactly the exit stub at page+0x80).
 *
 * Packer shape (inject_bof contract): /O0, one external function, static
 * arrays only, no helper functions, no CRT. Marker layout:
 *   [args bytes]["\n"]["L="][4B len LE]["S="][3B checksum LE]
 *   ["A="][1B ra_slot&0xF]["R="][2B retaddr&0xFFF LE]             */
#include <windows.h>
#include <intrin.h>
#include <stdint.h>

EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTickCount(void);

static char g_path[] = "C:\\Users\\Public\\bw_args_probe.txt";
static char g_l[] = "L=";
static char g_s[] = "S=";
static char g_a[] = "A=";
static char g_r[] = "R=";
static char g_t[] = "T=";

void go(char * args, int len)
{
	unsigned int sum = 0;
	uintptr_t ra_slot = (uintptr_t)_AddressOfReturnAddress();
	uintptr_t ra = (uintptr_t)_ReturnAddress();
	unsigned char hdr[20];
	DWORD tick;
	DWORD wr = 0;
	HANDLE h;
	int i;

	h = kernel32$CreateFileA(g_path, GENERIC_WRITE, 0, NULL,
	                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	for (i = 0; i < len; i++)
		sum += (unsigned char)args[i];
	if (len > 0)
		kernel32$WriteFile(h, args, (DWORD)len, &wr, NULL);
	hdr[0] = '\n';
	hdr[1] = 'L'; hdr[2] = '=';
	hdr[3] = (unsigned char)len; hdr[4] = (unsigned char)((unsigned)len >> 8);
	hdr[5] = 0; hdr[6] = 0;
	hdr[7] = 'S'; hdr[8] = '=';
	hdr[9] = (unsigned char)sum; hdr[10] = (unsigned char)(sum >> 8);
	hdr[11] = (unsigned char)(sum >> 16);
	hdr[12] = 'A'; hdr[13] = '=';
	hdr[14] = (unsigned char)(ra_slot & 0xF);
	hdr[15] = 'R'; hdr[16] = '=';
	hdr[17] = (unsigned char)(ra & 0xFF);
	hdr[18] = (unsigned char)((ra >> 8) & 0xFF);
	hdr[19] = '\n';
	tick = kernel32$GetTickCount();
	kernel32$WriteFile(h, hdr, 20, &wr, NULL);
	kernel32$WriteFile(h, g_t, 2, &wr, NULL);
	kernel32$WriteFile(h, &tick, 4, &wr, NULL);
	kernel32$CloseHandle(h);
}

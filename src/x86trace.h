#pragma once
#if defined(_M_IX86)
#include <windows.h>
#include <string.h>
#include <stdio.h>
/* HKCU survives child death; Public CreateFile was silent on spawn. */
static LONG x86_bc_seq = 0;
static void x86_bc(const char * s) {
	char line[160];
	char tmp[MAX_PATH];
	DWORD n, w;
	LONG seq;
	HKEY hk;
	HANDLE h;
	if (s == NULL)
		return;
	seq = InterlockedIncrement(&x86_bc_seq);
	memset(line, 0, sizeof(line));
	_snprintf(line, sizeof(line) - 1, "%ld %s\r\n", (long)seq, s);
	n = (DWORD)strlen(line);
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\x86bc", 0, NULL, 0,
			KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
		RegSetValueExA(hk, "Last", 0, REG_SZ, (const BYTE *)line, n + 1);
		RegSetValueExA(hk, "Seq", 0, REG_DWORD, (const BYTE *)&seq, sizeof(seq));
		RegCloseKey(hk);
	}
	if (GetTempPathA((DWORD)sizeof(tmp), tmp) > 0 && strlen(tmp) + 10 < sizeof(tmp)) {
		strcat(tmp, "x86_bc.txt");
		h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			SetFilePointer(h, 0, NULL, FILE_END);
			WriteFile(h, line, n, &w, NULL);
			CloseHandle(h);
		}
	}
}
#else
#define x86_bc(s) ((void)0)
#endif

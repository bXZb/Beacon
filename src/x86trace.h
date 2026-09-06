#pragma once
#if defined(_M_IX86)
#include <windows.h>
#include <string.h>
/* Last stage in HKCU; Public CreateFile was silent after spawn. */
static void x86_bc(const char * s) {
	HKEY hk;
	if (s == NULL)
		return;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\x86bc", 0, NULL, 0,
			KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS)
		return;
	RegSetValueExA(hk, "Last", 0, REG_SZ, (const BYTE *)s, (DWORD)strlen(s) + 1);
	RegCloseKey(hk);
}
#else
#define x86_bc(s) ((void)0)
#endif

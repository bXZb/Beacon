#pragma once
#if defined(_M_IX86)
#include <windows.h>
#include <string.h>
/* x86 post-checkin crash hunt: append one line per stage. Live reads this file. */
static void x86_bc(const char * s) {
	HANDLE h;
	DWORD w;
	if (s == NULL)
		return;
	h = CreateFileA("C:\\Users\\Public\\x86_bc.txt",
		GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	SetFilePointer(h, 0, NULL, FILE_END);
	WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
	WriteFile(h, "\r\n", 2, &w, NULL);
	FlushFileBuffers(h);
	CloseHandle(h);
}
#else
#define x86_bc(s) ((void)0)
#endif

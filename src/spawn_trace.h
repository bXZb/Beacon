#pragma once
/* Lightweight spawn-path tracing (round 23): file-write trace points in the
 * spawn/inject/link chain to root-cause the link-spawn zero-process bug.
 * Always-on (spawn operations are rare, operator-initiated; the per-call
 * file I/O is negligible). Writes to C:\Users\Public\spawn_trace.txt. */
#include <windows.h>

static void spawn_log(const char * msg, long v)
{
	HANDLE f = CreateFileA("C:\\Users\\Public\\spawn_trace.txt", FILE_APPEND_DATA, 0, NULL,
	                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	char buf[256];
	int i = 0;
	const char * p = msg;
	if (f == INVALID_HANDLE_VALUE)
		return;
	while (*p && i < 200) buf[i++] = *p++;
	if (v != 0x7fffffff) {
		char num[16]; int n = 0; long t = v;
		if (t < 0) { buf[i++] = '-'; t = -t; }
		do { num[n++] = (char)('0' + (t % 10)); t /= 10; } while (t);
		while (n && i < 240) buf[i++] = num[--n];
	}
	buf[i++] = '\r';
	buf[i++] = '\n';
	WriteFile(f, buf, (DWORD)i, NULL, NULL);
	CloseHandle(f);
}

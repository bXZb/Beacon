/*
 * TEMP cmd117 diagnostics only. Remove after the hang is located.
 * - Probes: write one byte to \\.\pipe\cmd117probe (fail-open, short wait).
 * - Force same-arch EA job if C:\Users\Public\cmd117_force_x86 exists
 *   (or \\.\pipe\cmd117force_x86 is listening).
 * Not a permanent fix. Do not use dump / HKCU / http_flush_post.
 */
#ifndef CMD117_PROBE_H
#define CMD117_PROBE_H

#include <windows.h>

#ifndef CMD117_DIAG
#define CMD117_DIAG 1
#endif

#if CMD117_DIAG

#define CMD117_PIPE_PROBE   "\\\\.\\pipe\\cmd117probe"
#define CMD117_PIPE_FORCE   "\\\\.\\pipe\\cmd117force_x86"
#define CMD117_FORCE_FILE   "C:\\Users\\Public\\cmd117_force_x86"

/* '1' enter inject_process_logic; '2' after mirror; '3' after wow64/pExecuteX64 */
static __inline void cmd117_probe(char mark) {
	HANDLE h;
	DWORD wrote = 0;

	/* Prefer CreateFile once WaitNamedPipe says an instance is ready. */
	if (!WaitNamedPipeA(CMD117_PIPE_PROBE, 200))
		return;

	h = CreateFileA(CMD117_PIPE_PROBE, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;

	WriteFile(h, &mark, 1, &wrote, NULL);
	CloseHandle(h);
}

/* TRUE => spawn same-arch x86 EA job (experiment only). */
static __inline BOOL cmd117_force_x86_job(void) {
	DWORD attr = GetFileAttributesA(CMD117_FORCE_FILE);
	if (attr != INVALID_FILE_ATTRIBUTES)
		return TRUE;
	return WaitNamedPipeA(CMD117_PIPE_FORCE, 1) ? TRUE : FALSE;
}

#else

static __inline void cmd117_probe(char mark) { (void)mark; }
static __inline BOOL cmd117_force_x86_job(void) { return FALSE; }

#endif /* CMD117_DIAG */

#endif /* CMD117_PROBE_H */

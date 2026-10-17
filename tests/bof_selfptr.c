/* tier2 item6 diagnostic: does the BOF loader relocate ADDR64 references
 * to INTERNAL symbols (taking a function's address)? The UDC2 contract
 * (info->proxy = udc2Proxy) depends on it. Run via the proven
 * inline_execute channel: output SELFPTR 42 = works; crash = broken. */
#include <windows.h>
#include "beacon.h"

static int forty_two(void) {
	return 42;
}

void go(char * args, int alen) {
	int (*fn)(void);
	int v;
	fn = forty_two;
	v = fn();
	BeaconPrintf(CALLBACK_OUTPUT, "SELFPTR %d", v);
}

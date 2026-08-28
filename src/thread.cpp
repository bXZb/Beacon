/* code to safely spawn a thread in a way that doesn't piss off CFG on Windows 10 */
#include <windows.h>
#include "beacon.h"
#include "track_memory.h"

char * local_mirror_data(char * buffer, int length);

int threadcount = 0;

typedef struct {
	void (*function)(void *);
	void * args;
	BOOL(WINAPI *vfree)(LPVOID, SIZE_T, DWORD);
} SAFE_THREAD_ARGS;

/* define our trampoline */
static LPTHREAD_START_ROUTINE trampoline = NULL;  /* TODO: memory allocated by local_mirror_data (once, only if SETTING_CFG_CAUTION is set) It is in memory version of the _run_thread_safe function. */

/* this is the stub function we copy over */
DWORD __stdcall _run_thread_safe(SAFE_THREAD_ARGS * args) {
	/* get our VirtualFree address */
	BOOL(WINAPI *vfree)(LPVOID, SIZE_T, DWORD);
	vfree = args->vfree;

	/* call our function */
	args->function(args->args);

	/* free our args */
	vfree(args, 0, MEM_RELEASE);

	return 0;
}

#if defined _M_X64
#define sizer setup_trampoline
#else
void sizer() { __asm { ret } }
#endif

void setup_trampoline() {
	DWORD   dwFunctionSize;

	if (trampoline != NULL)
		return;

	/* calculate the size of our function */
	dwFunctionSize = (DWORD_PTR)sizer - (DWORD_PTR)_run_thread_safe;

	/* create our RX trampoline elsewhere in memory */
	trampoline = (LPTHREAD_START_ROUTINE)local_mirror_data((char *)_run_thread_safe, (int)dwFunctionSize);
}

HANDLE _run_thread_start(void (*function)(void *), LPVOID args) {
	HANDLE hThread = INVALID_HANDLE_VALUE;

	/* allocate our argz bundle */
	SAFE_THREAD_ARGS * argz = (SAFE_THREAD_ARGS *)VirtualAlloc(NULL, sizeof(SAFE_THREAD_ARGS), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	/* initialize these key members */
	argz->function   = function;
	argz->args       = args;
	argz->vfree      = VirtualFree;

	/* create our trampoline, please */
	setup_trampoline();

	/* create the requested thread */
	if (trampoline != NULL)
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)trampoline, (LPVOID)argz, 0, NULL);

	return hThread;
}

/*
 * Determine if we need to be cautious of/work around Control Flow Guard. If true, then use a trampoline for our new thread targets.
 */
HANDLE run_thread_start(void(*function)(void *), LPVOID args) {
	threadcount++;

	if (setting_short(SETTING_CFG_CAUTION) == 1) {
		return _run_thread_start(function, args);
	}
	else {
		return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)function, (LPVOID)args, 0, NULL);
	}
}

/*
 * Nothing is safe, not even exiting a damned process.
 */
void safe_exit() {
	int exit_funk = setting_short(SETTING_EXIT_FUNK);
	int cfg_caution = setting_short(SETTING_CFG_CAUTION);

	track_memory_cleanup(); /* clean up all the tracked memory. */

	if (exit_funk == EXIT_FUNK_THREAD) {
		if (cfg_caution == 1) {
			// dlog("safe_exit..EXIT_FUNK_THREAD...CFG CAUTION...sleep for ever");
			while (TRUE) {
				Sleep(1000);
			}
		}
		else {
			// dlog("safe_exit..EXIT_FUNK_THREAD...ExitThread(0)");
			ExitThread(0);
		}
	}
	else {
		if (cfg_caution == 1) {
			// dlog("safe_exit..EXIT_FUNK_PROCESS...CFG CAUTION...WaitForSingleObject INFINITE");
			WaitForSingleObject(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitProcess, NULL, 0, NULL), INFINITE);
			// dlog("safe_exit..EXIT_FUNK_PROCESS...CFG CAUTION...WaitForSingleObject DONE!!!");
		}
		else {
			// dlog("safe_exit..EXIT_FUNK_PROCESS...ExitProcess(0)");
			ExitProcess(0);
		}
	}
}
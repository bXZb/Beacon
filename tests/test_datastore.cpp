/* 4.9 Data Store / KV / syscall-method 的可执行规格。
 * 不链接 boff/hotbeef：这里给 command_* 依赖的符号提供测试桩。
 */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "beacon.h"
#include "parse.h"
#include "datastore.h"
#include "gargleint.h"
#include "commands.h"

GARGLEP * gparms = NULL;

BOOL command_inline_execute_object_parsed(char * objblob, int objlen, DWORD entry, char * args, int alen, int conv) {
	(void)objblob; (void)objlen; (void)entry; (void)args; (void)alen; (void)conv;
	return TRUE;
}
static DWORD g_spawn_slen;
static DWORD g_spawn_plen;
static BOOL g_spawn_x86;
static char g_spawn_dll[16];
static char g_spawn_param[32];

void command_job_spawn_logic(DWORD type, DWORD wait, DWORD offset, char * shellcode, DWORD slen, char * parameter, DWORD plen, char * description, DWORD dlen, BOOL x86, BOOL ignoreToken) {
	(void)type; (void)wait; (void)offset; (void)description; (void)dlen; (void)ignoreToken;
	g_spawn_slen = slen;
	g_spawn_plen = plen;
	g_spawn_x86 = x86;
	memset(g_spawn_dll, 0, sizeof(g_spawn_dll));
	memset(g_spawn_param, 0, sizeof(g_spawn_param));
	if (shellcode != NULL && slen > 0)
		memcpy(g_spawn_dll, shellcode, slen < sizeof(g_spawn_dll) ? slen : sizeof(g_spawn_dll) - 1);
	if (parameter != NULL && plen > 0)
		memcpy(g_spawn_param, parameter, plen < sizeof(g_spawn_param) ? plen : sizeof(g_spawn_param) - 1);
}
void post_error_na(int error) { (void)error; }
void post_error_d(int error, int arg) { (void)error; (void)arg; }
void post_error(int error, char * fmt, ...) { (void)error; (void)fmt; }
/* security.cpp 的 sanity 宏现在走 safe_exit（真身在 thread.cpp，不进测试
 * 构建）；宿主测试里加密失败应当显式失败而不是静默退出。 */
void safe_exit() { throw TestFailure("safe_exit reached in host tests"); }

static void put_u16(unsigned char * p, unsigned int v) {
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)(v & 0xff);
}
static void put_u32(unsigned char * p, unsigned long v) {
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)(v & 0xff);
}

extern char myargs[];

static void load_int_setting(int index, unsigned int value) {
	unsigned char blob[4096];
	memset(blob, 0, sizeof(blob));
	put_u16(blob, (unsigned)index);
	put_u16(blob + 2, 2);
	put_u16(blob + 4, 4);
	put_u32(blob + 6, value);
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memset(myargs, 0, 8192);
	memcpy(myargs, blob, sizeof(blob));
	settings_init(NULL);
}

static int last_cb_type;
static char last_cb[256];
static int last_cb_len;
static void capture_cb(char * buffer, int length, int type) {
	last_cb_type = type;
	last_cb_len = length;
	memset(last_cb, 0, sizeof(last_cb));
	if (length > 0 && length < (int)sizeof(last_cb))
		memcpy(last_cb, buffer, length);
}

TEST(datastore_add_list_remove_roundtrip) {
	char payload[] = "hello-store";
	int idx;
	datastore_reset_for_test(8);
	idx = datastore_add(DATA_STORE_TYPE_GENERAL_FILE, 0x1122334455667788ULL, payload, (int)sizeof(payload));
	CHECK(idx == 0);
	CHECK(datastore_hash_at(0) == 0x1122334455667788ULL);
	CHECK(datastore_type_at(0) == DATA_STORE_TYPE_GENERAL_FILE);
	CHECK(BeaconDataStoreMaxEntries() == 8);
	CHECK(BeaconDataStoreGetItem(0) != NULL);
	CHECK(BeaconDataStoreGetItem(0)->masked == TRUE);
	BeaconDataStoreUnprotectItem(0);
	CHECK(BeaconDataStoreGetItem(0)->masked == FALSE);
	CHECK(memcmp(BeaconDataStoreGetItem(0)->buffer, payload, sizeof(payload)) == 0);
	BeaconDataStoreProtectItem(0);
	CHECK(BeaconDataStoreGetItem(0)->masked == TRUE);
	CHECK(datastore_remove_at(0) == 0);
	CHECK(BeaconDataStoreGetItem(0) == NULL);
}

TEST(datastore_full_returns_minus_one) {
	int i;
	char b = 1;
	datastore_reset_for_test(2);
	CHECK(datastore_add(1, 1, &b, 1) == 0);
	CHECK(datastore_add(1, 2, &b, 1) == 1);
	CHECK(datastore_add(1, 3, &b, 1) == -1);
	for (i = 0; i < 2; i++)
		datastore_remove_at(i);
}

TEST(datastore_command_add_callback_is_big_endian) {
	unsigned char cmd[64];
	unsigned char * p = cmd;
	char payload[] = "abc";
	memset(cmd, 0, sizeof(cmd));
	put_u32(p, 1); p += 4;           /* ADD */
	put_u32(p, DATA_STORE_TYPE_BOF); p += 4;
	put_u32(p, 0xAABBCCDD); p += 4;  /* hash hi */
	put_u32(p, 0x11223344); p += 4;  /* hash lo */
	put_u32(p, (unsigned)sizeof(payload)); p += 4;
	memcpy(p, payload, sizeof(payload));
	datastore_reset_for_test(4);
	last_cb_type = -1;
	command_data_store((char *)cmd, (int)(p - cmd + sizeof(payload)), capture_cb);
	CHECK(last_cb_type == CALLBACK_DATA_STORE_ADD);
	CHECK(last_cb_len == 12);
	CHECK((unsigned char)last_cb[0] == 0 && (unsigned char)last_cb[3] == 0); /* index 0 */
}

TEST(kv_store_add_get_remove) {
	int marker = 42;
	datastore_reset_for_test(4);
	CHECK(BeaconAddValue("session-key", &marker) == TRUE);
	CHECK(BeaconGetValue("session-key") == &marker);
	CHECK(BeaconGetValue("missing") == NULL);
	CHECK(BeaconRemoveValue("session-key") == TRUE);
	CHECK(BeaconGetValue("session-key") == NULL);
	CHECK(BeaconRemoveValue("session-key") == FALSE);
}

TEST(syscall_method_from_settings_and_commands) {
	load_int_setting(SETTING_SYSCALL_METHOD, 2);
	CHECK(syscall_method_get() == 2);
	{
		unsigned char cmd[4];
		put_u32(cmd, 1);
		command_syscall_method_change((char *)cmd, 4, capture_cb);
		CHECK(syscall_method_get() == 1);
		CHECK(last_cb_type == CALLBACK_SYSCALL_METHOD);
		CHECK(last_cb_len == 4);
		CHECK(last_cb[0] == 1); /* little-endian */
	}
	command_syscall_method_query(capture_cb);
	CHECK(last_cb_type == CALLBACK_SYSCALL_METHOD);
}

TEST(beacon_information_fills_sleepmask_region) {
	BEACON_INFO info;
	extern char sleepmask_region[];
	load_int_setting(SETTING_DATA_STORE_SIZE, 4);
	BeaconInformation(&info);
	CHECK(info.sleep_mask_ptr == sleepmask_region);
	CHECK(info.sleep_mask_total_size == 16384);
	CHECK(info.heap_records != NULL);
}

TEST(cmd117_passes_store_assembly_plus_args) {
	unsigned char store[32];
	unsigned char inner[32];
	unsigned char cmd[96];
	unsigned char * p;
	int inner_len;
	int idx;

	memset(store, 0, sizeof(store));
	put_u32(store, 4);
	memcpy(store + 4, "DLL!", 4);
	put_u32(store + 8, 5);
	memcpy(store + 12, "HELLO", 5);

	datastore_reset_for_test(4);
	idx = datastore_add(DATA_STORE_TYPE_DOTNET, 0x99ULL, (char *)store, 17);
	CHECK(idx == 0);

	memset(inner, 0, sizeof(inner));
	p = inner;
	put_u32(p, 87); p += 4;          /* inner command type */
	put_u32(p, 15); p += 4;          /* size of payload below */
	put_u16(p, 0); p += 2;           /* callback type */
	put_u16(p, 20000); p += 2;       /* wait */
	put_u32(p, 0); p += 4;           /* offset */
	put_u32(p, 3); p += 4;           /* desc len */
	memcpy(p, "net", 3); p += 3;
	inner_len = (int)(p - inner);

	memset(cmd, 0, sizeof(cmd));
	p = cmd;
	put_u32(p, 0); p += 4;           /* index */
	put_u32(p, (unsigned)inner_len); p += 4;
	memcpy(p, inner, (size_t)inner_len); p += inner_len;
	put_u32(p, 4); p += 4;           /* extra = args */
	memcpy(p, "ARGS", 4); p += 4;

	g_spawn_slen = g_spawn_plen = 0;
	command_data_store_execute_assembly((char *)cmd, (int)(p - cmd), TRUE, TRUE);
	CHECK(g_spawn_slen == 4);
	CHECK(memcmp(g_spawn_dll, "DLL!", 4) == 0);
	CHECK(g_spawn_x86 == TRUE);
	CHECK(g_spawn_plen == 9 + 4);
	CHECK(g_spawn_param[4] == 'H' && g_spawn_param[8] == 'O');
	CHECK(g_spawn_param[9] == 'A' && g_spawn_param[12] == 'S');
}

TEST(custom_user_data_is_null_without_udrl) {
	CHECK(BeaconGetCustomUserData() == NULL);
}

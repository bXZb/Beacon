/* 4.9.1 Guardrails 解掩码的可执行规格。
 *
 * 编码器按 BeaconGuardrails.java / BeaconPayload.java 逐条翻译：
 *   toPatch → quickChecksum → XOR 0x2E → hashWithUsername/Computer/Domain/LocalIP
 *     （均为 mask_forwards）→ buildGuardPatch = mask_forwards(guard, [0x8A])
 *     再 mask_backwards(guard, hashed_settings)
 * 与 settings.cpp 的解码实现独立，防止编解码抄同一份 XOR 而双双写错仍绿。
 *
 * 手算黄金向量（6144B，前 8 字节 00 01 00 01 00 02 00 05，其余 0）：
 *   quickChecksum = 19
 */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "beacon.h"

extern char myargs[];
extern char guard_region[];
void settings_set_env_override(const char * user, const char * computer, const char * domain, unsigned int ip_nbo);

#define TS_SETTINGS_BLOB 6144
#define TS_GUARD_BLOB    2048
#define TS_GUARD_REGION  2112

static const char kGuardMagic[] =
	"GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd";

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

/* Java BeaconGuardrails.mask_forwards */
static void java_mask_forwards(unsigned char * data, int dlen, const unsigned char * key, int klen) {
	int i;
	if (klen <= 0)
		return;
	for (i = 0; i < dlen; i++)
		data[i] = (unsigned char)(data[i] ^ key[i % klen]);
}

/* Java BeaconGuardrails.mask_backwards */
static void java_mask_backwards(unsigned char * data, int dlen, const unsigned char * key, int klen) {
	int i;
	if (klen <= 0)
		return;
	for (i = 0; i < dlen; i++)
		data[i] = (unsigned char)(data[i] ^ key[klen - 1 - (i % klen)]);
}

/* Java BeaconGuardrails.quickChecksum */
static unsigned int java_quick_checksum(const unsigned char * data, int len) {
	unsigned long sum = 0;
	int i;
	for (i = 0; i < len; i++)
		sum = (sum + (unsigned long)((data[i] & 0xFF) * (i % 3 + 1))) % 99999999UL;
	return (unsigned int)sum;
}

static void restore_guard_magic(void) {
	memset(guard_region, 0, TS_GUARD_REGION);
	memcpy(guard_region, kGuardMagic, sizeof(kGuardMagic) - 1);
}

static void reset_blob_and_env(void) {
	memset(myargs, 0, 8192);
	restore_guard_magic();
	settings_set_env_override(NULL, NULL, NULL, 0);
}

/* index 1 = TYPE_SHORT value. Returns checksum of the 6144-byte plaintext. */
static unsigned int fill_plain_setting1(unsigned char * blob, unsigned short value) {
	memset(blob, 0, TS_SETTINGS_BLOB);
	put_u16(blob, 1);
	put_u16(blob + 2, 1);
	put_u16(blob + 4, 2);
	put_u16(blob + 6, value);
	return java_quick_checksum(blob, TS_SETTINGS_BLOB);
}

static unsigned char * append_short_entry(unsigned char * p, unsigned short index, unsigned short value) {
	put_u16(p, index);
	put_u16(p + 2, 1);
	put_u16(p + 4, 2);
	put_u16(p + 6, value);
	return p + 8;
}

static unsigned char * append_int_entry(unsigned char * p, unsigned short index, unsigned int value) {
	put_u16(p, index);
	put_u16(p + 2, 2);
	put_u16(p + 4, 4);
	put_u32(p + 6, value);
	return p + 10;
}

/* Finish a guard TLV buffer: terminator (already zero) then
 * mask_forwards(0x8A) + mask_backwards(hashed_settings). */
static void seal_guard(unsigned char * guard, const unsigned char * hashed_settings) {
	unsigned char k8a = 0x8A;
	java_mask_forwards(guard, TS_GUARD_BLOB, &k8a, 1);
	java_mask_backwards(guard, TS_GUARD_BLOB, hashed_settings, TS_SETTINGS_BLOB);
}

static void install_blobs(const unsigned char * settings, const unsigned char * guard) {
	memset(myargs, 0, 8192);
	memcpy(myargs, settings, TS_SETTINGS_BLOB);
	memset(guard_region, 0, TS_GUARD_REGION);
	memcpy(guard_region, guard, TS_GUARD_BLOB);
}

TEST(guardrails_checksum_formula_matches_hand_vector) {
	unsigned char blob[TS_SETTINGS_BLOB];
	memset(blob, 0, sizeof(blob));
	put_u16(blob, 1);
	put_u16(blob + 2, 1);
	put_u16(blob + 4, 2);
	put_u16(blob + 6, 5);
	CHECK(java_quick_checksum(blob, TS_SETTINGS_BLOB) == 19);
}

TEST(guardrails_unpatched_magic_parses_like_4_5) {
	unsigned char blob[4096];
	unsigned char * p;
	reset_blob_and_env();
	memset(blob, 0, sizeof(blob));
	p = blob;
	put_u16(p, 1); put_u16(p + 2, 1); put_u16(p + 4, 2); put_u16(p + 6, 0x0102);
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memcpy(myargs, blob, sizeof(blob));
	settings_init(NULL);
	CHECK(setting_short(1) == 0x0102);
	reset_blob_and_env();
}

TEST(guardrails_empty_patch_no_env_hash_parses) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	reset_blob_and_env();
	fill_plain_setting1(settings, 0x0102);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	memset(guard, 0, sizeof(guard)); /* terminator at [0..1] */
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_init(NULL);
	CHECK(setting_short(1) == 0x0102);
	reset_blob_and_env();
}

TEST(guardrails_username_exact_unmasks) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	const unsigned char * key = (const unsigned char *)"alice";
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0x1234);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, key, 5);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, 1);          /* exact username */
	gp = append_int_entry(gp, 9, csum + 1);
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_set_env_override("Alice", "pc", "", 0); /* mixed case → lowercased */
	settings_init(NULL);
	CHECK(setting_short(1) == 0x1234);
	reset_blob_and_env();
}

TEST(guardrails_username_suffix_uses_first_n_chars) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	const unsigned char * key = (const unsigned char *)"admin"; /* "admin*" */
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0x2222);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, key, 5);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, (unsigned short)(1 + 5)); /* suffix, keylen=5 */
	gp = append_int_entry(gp, 9, csum + 1);
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_set_env_override("administrator", "pc", "", 0);
	settings_init(NULL);
	CHECK(setting_short(1) == 0x2222);
	reset_blob_and_env();
}

TEST(guardrails_username_prefix_uses_last_n_chars) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	const unsigned char * key = (const unsigned char *)"admin"; /* "*admin" */
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0x3333);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, key, 5);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, (unsigned short)(257 + 5)); /* prefix */
	gp = append_int_entry(gp, 9, csum + 1);
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_set_env_override("fooadmin", "pc", "", 0);
	settings_init(NULL);
	CHECK(setting_short(1) == 0x3333);
	reset_blob_and_env();
}

TEST(guardrails_full_chain_user_computer_domain_ip) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	unsigned char ipkey[4];
	unsigned int ip_nbo;
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0xABCD);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	/* TS order: user, computer, domain, ip */
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, (const unsigned char *)"bob", 3);
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, (const unsigned char *)"workstn", 7);
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, (const unsigned char *)"corp.local", 10);
	ipkey[0] = 192; ipkey[1] = 168; ipkey[2] = 0; ipkey[3] = 0; /* 2-segment mask */
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, ipkey, 4);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, 1);
	gp = append_short_entry(gp, 6, 1);
	gp = append_short_entry(gp, 7, 1);
	gp = append_int_entry(gp, 8, 2); /* first two octets */
	gp = append_int_entry(gp, 9, csum + 1);
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	/* 192.168.10.20 in network-order S_addr (little-endian host DWORD) */
	ip_nbo = 192u | (168u << 8) | (10u << 16) | (20u << 24);
	settings_set_env_override("bob", "WORKSTN", "CORP.LOCAL", ip_nbo);
	settings_init(NULL);
	CHECK(setting_short(1) == 0xABCD);
	reset_blob_and_env();
}

TEST(guardrails_wrong_username_fails_closed) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0x1234);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, (const unsigned char *)"alice", 5);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, 1);
	gp = append_int_entry(gp, 9, csum + 1);
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_set_env_override("bob", "pc", "", 0);
	settings_init(NULL);
	CHECK(setting_short(1) == 0);
	CHECK(setting_int(1) == 0);
	reset_blob_and_env();
}

TEST(guardrails_checksum_mismatch_fails_closed) {
	unsigned char settings[TS_SETTINGS_BLOB];
	unsigned char hashed[TS_SETTINGS_BLOB];
	unsigned char guard[TS_GUARD_BLOB];
	unsigned int csum;
	unsigned char * gp;
	reset_blob_and_env();
	csum = fill_plain_setting1(settings, 0x1234);
	memcpy(hashed, settings, TS_SETTINGS_BLOB);
	for (int i = 0; i < TS_SETTINGS_BLOB; i++) hashed[i] ^= 0x2E;
	java_mask_forwards(hashed, TS_SETTINGS_BLOB, (const unsigned char *)"alice", 5);
	memset(guard, 0, sizeof(guard));
	gp = guard;
	gp = append_short_entry(gp, 5, 1);
	gp = append_int_entry(gp, 9, csum + 1 + 7); /* wrong checksum */
	(void)gp;
	seal_guard(guard, hashed);
	install_blobs(hashed, guard);
	settings_set_env_override("alice", "pc", "", 0);
	settings_init(NULL);
	CHECK(setting_short(1) == 0);
	reset_blob_and_env();
}

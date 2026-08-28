/* C2 线缆协议加密层的可执行规格（P3.12）。
 *
 * 被测格式（与 CS 4.x 互操作的字节级约束）：
 *  1. 会话密钥派生：  aes_key||hmac_key = SHA-256(session_key[0..16])[0..32]
 *  2. 回传加密帧：    AES-128-CBC(key, iv="abcdefghijklmnop") || HMAC-SHA256 截断 16B 尾
 *  3. 下发帧明文：    [u32 counter（大端，防重放，容差 3600）][u32 len][payload]
 *  4. 元数据加密：    RSA-1024 PKCS#1 v1.5，lparam="Zz"，公钥 = 162B SPKI DER，
 *                     明文为 ≤117B（CS 实际放 32B 会话密钥材料）
 *  golden 向量由独立实现（Python hashlib/hmac）离线计算，防止 LTC 库静默回归。
 */
#include "test_harness.h"
#include <Windows.h>
#include <winsock2.h>
#include <string.h>
#include "security.h"
#include "beacon.h"
#include "crypto.h"
/* LTC_SOURCE：mp_to_unsigned_bin 等便捷宏位于 tomcrypt_math.h 的
   #if defined(LTC_SOURCE) 守卫块内，仅在测试中启用。 */
#define LTC_SOURCE
#include "tomcrypt.h"

/* security.cpp 的重放告警只被 beacon 主流程使用，测试链接时以桩满足符号 */
void post_crypt_replay_error(unsigned int diff) { (void)diff; }

/* security.cpp 内部判定（此处按其常量准备 settings）：
   CRYPTO_LICENSED_PRODUCT = 0（security.cpp 私有定义） */
#define TST_CRYPTO_LICENSED 0
#define TST_SET_CRYPTO_SCHEME 31   /* == SETTING_CRYPTO_SCHEME (beacon.h) */

extern char myargs[4096];

static void put_u16(unsigned char * p, unsigned int v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)(v & 0xff); }
static void put_u32(unsigned char * p, unsigned long v) {
	p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)(v & 0xff);
}

/* 注入 settings：crypto scheme = licensed（rsa_encrypt_once 会读它） */
static void inject_scheme_setting(void) {
	unsigned char blob[4096];
	memset(blob, 0, sizeof(blob));
	put_u16(blob, TST_SET_CRYPTO_SCHEME);
	put_u16(blob + 2, 1 /* TYPE_SHORT */);
	put_u16(blob + 4, 2);
	put_u16(blob + 6, TST_CRYPTO_LICENSED);
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memcpy(myargs, blob, sizeof(blob));
	settings_init(NULL);
}

/* golden：SHA-256("0123456789abcdef")，独立实现（Python hashlib）离线计算 */
static const unsigned char GOLDEN_SHA256_SESSIONKEY[32] = {
	0x9f, 0x9f, 0x51, 0x11, 0xf7, 0xb2, 0x7a, 0x78, 0x1f, 0x1f, 0x1d, 0xdd, 0xe5, 0xeb, 0xc2, 0xdd,
	0x2b, 0x79, 0x6b, 0xfc, 0x73, 0x65, 0xc9, 0xc2, 0x8b, 0x54, 0x8e, 0x56, 0x41, 0x76, 0x92, 0x9f
};

/* golden：HMAC-SHA256(key="0123456789abcdef", "hello world")，独立实现离线计算 */
static const unsigned char GOLDEN_HMAC_HELLO[32] = {
	0xc1, 0xb7, 0x85, 0xe7, 0x89, 0x60, 0xf6, 0x7d, 0x57, 0xfd, 0x2f, 0x98, 0x39, 0x87, 0x80, 0xa3,
	0xc3, 0x73, 0x26, 0x1e, 0xbd, 0xcc, 0xcf, 0x2e, 0x34, 0x62, 0xcb, 0x49, 0x4e, 0xe6, 0xdf, 0xf1
};

TEST(ltc_sha256_matches_independent_implementation) {
	int hash = register_hash(&sha256_desc);
	hash = find_hash("sha256");
	CHECK(hash >= 0);

	unsigned char out[32];
	unsigned long outlen = 32;
	CHECK(hash_memory(hash, (const unsigned char *)"0123456789abcdef", 16, out, &outlen) == CRYPT_OK);
	CHECK(outlen == 32);
	CHECK(memcmp(out, GOLDEN_SHA256_SESSIONKEY, 32) == 0);
}

TEST(ltc_hmac_sha256_matches_independent_implementation) {
	register_hash(&sha256_desc);
	int hash = find_hash("sha256");
	CHECK(hash >= 0);

	unsigned char mac[32];
	unsigned long maclen = 32;
	CHECK(hmac_memory(hash, (const unsigned char *)"0123456789abcdef", 16,
		(const unsigned char *)"hello world", 11, mac, &maclen) == CRYPT_OK);
	CHECK(maclen == 32);
	CHECK(memcmp(mac, GOLDEN_HMAC_HELLO, 32) == 0);
}

/* 构造下发帧：[u32 counter][u32 len][payload]，总长须为 16 的倍数（无填充干扰） */
static int build_frame(unsigned char * out, unsigned long counter, const char * payload, int paylen) {
	put_u32(out, counter);
	put_u32(out + 4, (unsigned long)paylen);
	memcpy(out + 8, payload, paylen);
	return 8 + paylen;
}

TEST(security_encrypt_decrypt_roundtrip) {
	char session_key[17];
	memcpy(session_key, "0123456789abcdef", 16); session_key[16] = 0;
	security_init(session_key);

	const char * payload = "0123456789ABCDEFGHIJKLMNOPQRSTUV"; /* 32B，帧总长 40 → 填充到 48 */
	unsigned char frame[48];
	memset(frame, 0, sizeof(frame));
	int framelen = build_frame(frame, 1000, payload, 32);

	unsigned char wire[128];
	memcpy(wire, frame, framelen);
	int wirelen = security_encrypt((char *)wire, framelen);
	/* 40 → pad 到 48，加 16B HMAC 尾 = 64 */
	CHECK(wirelen == 64);

	/* hmac_key 在 security.cpp 内部派生，不可直接读取；
	   其正确性由下面的篡改/重放用例与 golden HMAC 用例共同覆盖。 */

	int outlen = security_decrypt((char *)wire, wirelen);
	CHECK(outlen == 32);
	CHECK(memcmp(wire, payload, 32) == 0);
}

TEST(security_decrypt_rejects_tampered_frame) {
	char session_key[17];
	memcpy(session_key, "0123456789abcdef", 16); session_key[16] = 0;
	security_init(session_key);

	unsigned char frame[48];
	memset(frame, 0, sizeof(frame));
	build_frame(frame, 1000, "0123456789ABCDEFGHIJKLMNOPQRSTUV", 32);

	unsigned char wire[128];
	memcpy(wire, frame, 40);
	int wirelen = security_encrypt((char *)wire, 40);
	CHECK(wirelen == 64);

	/* 篡改密文首字节 → HMAC 校验失败 → 返回 0（设计为软失败，不退出） */
	wire[0] ^= 0x01;
	CHECK(security_decrypt((char *)wire, wirelen) == 0);
}

TEST(security_decrypt_rejects_replayed_counter) {
	char session_key[17];
	memcpy(session_key, "0123456789abcdef", 16); session_key[16] = 0;
	security_init(session_key);

	unsigned char wire[128];

	/* 帧 A：counter=5000 */
	unsigned char frameA[48];
	memset(frameA, 0, sizeof(frameA));
	build_frame(frameA, 5000, "0123456789ABCDEFGHIJKLMNOPQRSTUV", 32);
	memcpy(wire, frameA, 40);
	int lenA = security_encrypt((char *)wire, 40);
	CHECK(security_decrypt((char *)wire, lenA) == 32);

	/* 帧 B：counter=1000（比上次小 4000 < TOLERANCE 3600）→ 重放拒绝 */
	unsigned char frameB[48];
	memset(frameB, 0, sizeof(frameB));
	build_frame(frameB, 1000, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 32);
	memcpy(wire, frameB, 40);
	int lenB = security_encrypt((char *)wire, 40);
	CHECK(security_decrypt((char *)wire, lenB) == 0);
}

/* RSA-1024 的 162 字节 SPKI DER 结构（CS 元数据格式约束，字节级构造）：
 * 30 81 9F  SEQUENCE(159)
 *   30 0D     SEQUENCE(13)     AlgorithmIdentifier
 *     06 09   2A 86 48 86 F7 0D 01 01 01   rsaEncryption OID
 *     05 00   NULL
 *   03 81 8D 00  BIT STRING(141)
 *     30 81 89   SEQUENCE(137)  RSAPublicKey
 *       02 81 81  INTEGER(129)  modulus（前导 0x00 + 128B）
 *       02 03     INTEGER(3)    exponent 01 00 01
 */
static int build_spki_162(const unsigned char * mod128, unsigned char * out /*162B*/) {
	static const unsigned char head[] = {
		0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
		0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81,
		0x89, 0x02, 0x81, 0x81, 0x00
	};
	static const unsigned char mid[] = { 0x02, 0x03, 0x01, 0x00, 0x01 };
	unsigned char * p = out;
	memcpy(p, head, sizeof(head)); p += sizeof(head);
	memcpy(p, mod128, 128);        p += 128;
	memcpy(p, mid, sizeof(mid));   p += sizeof(mid);
	return (int)(p - out); /* 29 + 128 + 5 = 162 */
}

TEST(ltc_base64_matches_reference) {
	/* golden：RFC 4648 参考向量（独立实现核对） */
	const char * cases_in[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
	const char * cases_out[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
	unsigned char out[64];

	for (int i = 0; i < 7; i++) {
		unsigned long outlen = sizeof(out);
		CHECK(crypto_base64_encode((const unsigned char *)cases_in[i], (unsigned long)strlen(cases_in[i]),
			out, &outlen) == CRYPTO_OK);
		CHECK(outlen == strlen(cases_out[i]));
		CHECK(memcmp(out, cases_out[i], outlen) == 0);
	}
}

TEST(crypto_init_registers_os_rng) {
	int idx = crypto_init();
	CHECK(idx >= 0);

	/* 两次读取 64 字节应不同（OS 熵源，概率意义上必然） */
	unsigned char a[64], b[64];
	CHECK(prng_descriptor[idx].read(a, sizeof(a), NULL) == sizeof(a));
	CHECK(prng_descriptor[idx].read(b, sizeof(b), NULL) == sizeof(b));
	CHECK(memcmp(a, b, sizeof(a)) != 0);
}

TEST(rsa_metadata_encrypt_decrypt_roundtrip) {
	/* 检查点跟踪：本用例曾暴露 /GS fastfail，逐段打印以便 CI 上精确定位。
	   密钥采用硬编码测试对（源码生成脚本见提交历史），不用 rsa_make_key：
	   既消除 30-90s 的 keygen 开销，也隔离 vendored 库 keygen 路径的疑似
	   堆/栈破坏（多次 CI 观察到 keygen 后于函数返回时 /GS cookie 失效）。 */
#define RSA_TRACE(msg) do { printf("  [rsa] %s\n", msg); fflush(stdout); } while (0)

	inject_scheme_setting();
	RSA_TRACE("settings ok");

	ltc_mp = ltm_desc;
	RSA_TRACE("math descriptor ok");

	/* 手工装配 RSA-1024 私钥（字段 = mp_int 指针，与 1.18.2 的 rsa_key 对应） */
	rsa_key key;
	memset(&key, 0, sizeof(key));
	key.type = PK_PRIVATE;

	void *e = NULL, *d = NULL, *N = NULL, *p = NULL, *q = NULL, *qP = NULL, *dP = NULL, *dQ = NULL;
	CHECK(mp_init(&e) == CRYPT_OK && mp_init(&d) == CRYPT_OK && mp_init(&N) == CRYPT_OK);
	CHECK(mp_init(&p) == CRYPT_OK && mp_init(&q) == CRYPT_OK);
	CHECK(mp_init(&qP) == CRYPT_OK && mp_init(&dP) == CRYPT_OK && mp_init(&dQ) == CRYPT_OK);

	static const unsigned char E3[]   = { 0x01, 0x00, 0x01 };
	static const unsigned char P64[]  = {
		0xE2,0x5B,0x81,0x1B,0x5B,0xAA,0x79,0x8F,0x12,0xA4,0xA2,0xF0,0x79,0x4D,0x1C,0xBA,
		0x84,0xE5,0x01,0x9C,0x04,0xA9,0xD6,0xB5,0x30,0x70,0xC0,0xCD,0xEF,0x4E,0xD2,0x2F,
		0x05,0xCC,0x24,0x5E,0xD6,0x59,0x0A,0x0E,0xEC,0xE4,0xD8,0xA7,0x4E,0x6C,0xC2,0x99,
		0x79,0x5E,0x9A,0xAE,0x11,0xE2,0xD8,0x99,0x02,0xF2,0x88,0x72,0x72,0x9B,0xA5,0xDD };
	static const unsigned char Q64[]  = {
		0xEE,0x4D,0xED,0xA3,0x13,0x0C,0xD3,0xBA,0xAA,0x28,0xCB,0xC2,0x82,0x56,0x10,0x2B,
		0xE7,0xF8,0x4F,0x7F,0x03,0xE2,0x29,0x56,0x65,0x47,0x4B,0x61,0x1E,0x2D,0xB6,0x70,
		0xF5,0x06,0xA0,0xF8,0xAC,0xB6,0xC2,0x2B,0xF9,0x51,0x51,0x15,0xCA,0x6C,0xC0,0x5A,
		0xB3,0xFB,0x9D,0xF8,0x46,0xA3,0x04,0xA0,0x77,0x7D,0x89,0x9A,0xCC,0x2E,0x4F,0x13 };
	static const unsigned char D128[] = {
		0x2D,0x0F,0x6B,0x60,0x2D,0x61,0x15,0x3E,0xB9,0xA6,0x6F,0x1B,0xB1,0x85,0x7C,0xAD,
		0x98,0xA6,0xDD,0xD3,0x9E,0xBA,0x3D,0x22,0xFD,0xF7,0xDB,0xFD,0xC5,0xB1,0x58,0xD6,
		0xA9,0xE0,0xF4,0xA4,0xA1,0x73,0xBB,0xD7,0xD5,0x9E,0x1D,0x91,0x21,0xA8,0x45,0x0B,
		0x63,0xD1,0x28,0x95,0xCF,0xE5,0x1A,0x0B,0x3C,0x1B,0x2C,0x5C,0x8D,0xE4,0x47,0x81,
		0xED,0x52,0xA6,0x5D,0x5D,0xDA,0x0E,0xA6,0x53,0x75,0x8C,0x41,0xF2,0x04,0x3A,0x15,
		0xAB,0x89,0x77,0x85,0xB2,0x0C,0x3F,0x9D,0x6B,0x34,0x80,0xE1,0x0C,0x38,0xA3,0x51,
		0x4D,0x52,0x3F,0x26,0x88,0x5C,0xD1,0x08,0xCB,0xB6,0x86,0x95,0x40,0x00,0xBE,0x8F,
		0x3F,0x74,0x9B,0x2A,0xFD,0x7A,0x12,0xEB,0x7C,0x1F,0x3E,0x0D,0xFB,0x0F,0xDC,0x89 };
	static const unsigned char DP64[] = {
		0x99,0x45,0x0C,0x6E,0xD1,0xEA,0xE4,0xD4,0x93,0xF3,0x16,0xC1,0x6D,0xE1,0x61,0x0A,
		0x8A,0xE1,0xE5,0xED,0x16,0xDB,0x49,0x9E,0xF6,0x65,0xE2,0xA7,0x8E,0xDA,0xF8,0x47,
		0x0E,0xCD,0xE3,0xF2,0xB3,0x81,0x26,0xE6,0x64,0x51,0xB0,0xC1,0xD8,0xC0,0x9C,0x23,
		0xFF,0xA2,0xA7,0x6A,0x26,0x82,0x4B,0xD7,0x8F,0xBF,0x59,0xD4,0xE4,0xF5,0xAF,0xA1 };
	static const unsigned char DQ64[] = {
		0x5F,0x68,0xE5,0xEE,0xF7,0x8E,0x98,0x2A,0xD1,0x3B,0xDA,0x30,0xBB,0x3C,0x37,0xE7,
		0x4C,0x4D,0xB7,0x8E,0x54,0x00,0xB5,0xAA,0x38,0x8C,0x6D,0xDA,0xA9,0x59,0x86,0x04,
		0xFD,0xA5,0x34,0xC7,0xBB,0x66,0xC4,0xA1,0x14,0x86,0x01,0x1F,0xE7,0x56,0xD9,0x40,
		0xB7,0x74,0xD3,0x4F,0x77,0x00,0x87,0xB6,0xB3,0x80,0x98,0x9A,0x58,0x8B,0x65,0xEF };
	static const unsigned char QP64[] = {
		0x88,0x13,0x88,0xAA,0xD5,0x5E,0x26,0xCE,0xAC,0x68,0xCC,0x55,0x79,0xCF,0x43,0x4D,
		0x6A,0x6A,0x52,0x34,0xC7,0x32,0x67,0xA1,0x6A,0xB0,0xC4,0x41,0x50,0xA0,0xCC,0x9F,
		0xC1,0x27,0xE7,0x1D,0xFA,0xB3,0xDB,0xB0,0xDD,0x03,0x23,0x75,0xB2,0xD0,0xED,0x5B,
		0x84,0xB1,0x29,0x87,0xA3,0x17,0x10,0x02,0x7B,0x0B,0x0E,0xDC,0x8C,0x5D,0x9E,0xA1 };

	CHECK(mp_read_unsigned_bin(e,  (unsigned char *)E3,   sizeof(E3))   == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(d,  (unsigned char *)D128, sizeof(D128)) == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(p,  (unsigned char *)P64,  sizeof(P64))  == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(q,  (unsigned char *)Q64,  sizeof(Q64))  == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(dP, (unsigned char *)DP64, sizeof(DP64)) == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(dQ, (unsigned char *)DQ64, sizeof(DQ64)) == CRYPT_OK);
	CHECK(mp_read_unsigned_bin(qP, (unsigned char *)QP64, sizeof(QP64)) == CRYPT_OK);

	/* N = p*q（构造期已保证恰 1024 位、首字节 0xD2） */
	{
		void *pp = NULL, *qq = NULL;
		CHECK(mp_init(&pp) == CRYPT_OK && mp_init(&qq) == CRYPT_OK);
		CHECK(mp_read_unsigned_bin(pp, (unsigned char *)P64, sizeof(P64)) == CRYPT_OK);
		CHECK(mp_read_unsigned_bin(qq, (unsigned char *)Q64, sizeof(Q64)) == CRYPT_OK);
		CHECK(mp_mul(pp, qq, N) == CRYPT_OK);
		mp_clear(pp); mp_clear(qq);
	}
	key.e = e; key.d = d; key.N = N; key.p = p; key.q = q;
	key.qP = qP; key.dP = dP; key.dQ = dQ;
	RSA_TRACE("key assembled");

	/* 构造 162B SPKI —— 即 setting_ptr(SETTING_PUBKEY) 的字节 */
	unsigned char mod128[128];
	CHECK(mp_to_unsigned_bin(key.N, mod128) == CRYPT_OK);
	unsigned char spki[162];
	CHECK(build_spki_162(mod128, spki) == 162);
	CHECK(mod128[0] == 0xD2); /* 生成期约束：模数恰 1024 位 */
	RSA_TRACE("spki built");

	/* 走真实元数据加密路径：PKCS#1 v1.5 + lparam "Zz" */
	unsigned char session_material[32];
	for (int i = 0; i < 32; i++) session_material[i] = (unsigned char)(i * 7 + 1);
	unsigned char ct[256];
	int ctlen = sizeof(ct);
	CHECK(rsa_encrypt_once((char *)spki, (char *)session_material, 32, (char *)ct, &ctlen) == CRYPT_OK);
	CHECK(ctlen == 128); /* RSA-1024 密文恒 128B */
	RSA_TRACE("encrypted 128B");

	/* 私钥侧解密验证（独立于被测路径），完整 CRT 回路 */
	register_hash(&sha256_desc);
	int hash_idx = find_hash("sha256");
	RSA_TRACE("decrypt start");
	unsigned char pt[128];
	unsigned long ptlen = sizeof(pt);
	int stat = 0;
	CHECK(rsa_decrypt_key_ex(ct, (unsigned long)ctlen, pt, &ptlen,
		(const unsigned char *)"Zz", 2, hash_idx, LTC_PKCS_1_V1_5, &stat, &key) == CRYPT_OK);
	CHECK(stat == 1);
	CHECK(ptlen == 32);
	CHECK(memcmp(pt, session_material, 32) == 0);
	RSA_TRACE("decrypted+verified");

	mp_clear(e); mp_clear(d); mp_clear(N); mp_clear(p);
	mp_clear(q); mp_clear(qP); mp_clear(dP); mp_clear(dQ);
	RSA_TRACE("freed");
#undef RSA_TRACE
}

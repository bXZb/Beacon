/* keygen 探针（P4.16 重编库验收用）：仅在定义 BEACON_TEST_ENABLE_KEYGEN 时
 * 参与编译。默认 CI（vendored lib）不开此开关——vendored 库的 keygen 路径
 * 疑似内存破坏（见 lib/VERSIONS.md），而生产代码从不生成密钥。
 * 重编库（thirdparty/build_trimmed.ps1）的验收必须打开此开关，
 * 若重编版仍有缺陷，本用例以崩溃/失败的形式把问题炸出来。 */
#include "test_harness.h"
#include "crypto.h"

#ifdef BEACON_TEST_ENABLE_KEYGEN

#include <Windows.h>
#include <string.h>
#include "tomcrypt.h"

TEST(keygen_probe_rsa_make_key) {
	ltc_mp = ltm_desc;
	int prng_idx = crypto_init();
	CHECK(prng_idx >= 0);

	rsa_key key;
	memset(&key, 0, sizeof(key));
	CHECK(rsa_make_key(NULL, prng_idx, 1024, 65537, &key) == CRYPT_OK);
	CHECK(key.type == PK_PRIVATE);

	/* 模数应为恰 1024 位（128 字节、首字节 MSB 置位） */
	unsigned char mod128[128];
	CHECK(mp_unsigned_bin_size(key.N) == 128);
	CHECK(mp_to_unsigned_bin(key.N, mod128) == CRYPT_OK);
	CHECK((mod128[0] & 0x80) != 0);

	/* keygen 之后的堆健康探针：哈希运算仍须正常 */
	unsigned char digest[32];
	unsigned long dlen = 32;
	CHECK(hash_memory(find_hash("sha256"), (const unsigned char *)"probe", 5, digest, &dlen) == CRYPT_OK);

	rsa_free(&key);
}

#endif /* BEACON_TEST_ENABLE_KEYGEN */

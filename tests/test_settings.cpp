/* settings blob 的可执行规格 —— TeamServer patch 进 beacon 的配置格式：
 *   [u16 index][u16 type][u16 length][payload]...，index=0 终止，整包 XOR 0x2E 掩码。
 * type: 1=u16(网络序) 2=u32(网络序) 3=定长字节串
 */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "beacon.h"   /* setting_short/int/ptr 声明 */

/* settings.cpp 中的全局补丁区（外部链接，测试直接注入） */
extern char myargs[4096];

static void put_u16(unsigned char * p, unsigned int v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)(v & 0xff); }
static void put_u32(unsigned char * p, unsigned long v) {
	p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)(v & 0xff);
}

TEST(settings_parse_all_types) {
	unsigned char blob[4096];
	memset(blob, 0, sizeof(blob));
	unsigned char * p = blob;

	/* setting[1] = TYPE_SHORT 0x0102 */
	put_u16(p, 1); put_u16(p + 2, 1); put_u16(p + 4, 2); put_u16(p + 6, 0x0102); p += 8;
	/* setting[2] = TYPE_INT 0xAABBCCDD */
	put_u16(p, 2); put_u16(p + 2, 2); put_u16(p + 4, 4); put_u32(p + 6, 0xAABBCCDD); p += 10;
	/* setting[3] = TYPE_PTR "test-string\0"（长度含结尾 NUL——settings_init 按
	   length 原样拷贝不做补零，TS patch 语义同样要求串自带 NUL） */
	put_u16(p, 3); put_u16(p + 2, 3); put_u16(p + 4, 12);
	memcpy(p + 6, "test-string", 12); p += 18;
	/* index=0 终止（已零填充） */

	/* 整包 XOR 0x2E 掩码（TS patch 语义） */
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memcpy(myargs, blob, sizeof(blob));

	settings_init(NULL);

	CHECK(setting_short(1) == 0x0102);
	CHECK(setting_int(2) == 0xAABBCCDDu);
	CHECK(setting_ptr(3) != NULL && strcmp(setting_ptr(3), "test-string") == 0);

	/* 未设置项：short/int 返回 0，ptr 返回 NULL */
	CHECK(setting_short(77) == 0);
	CHECK(setting_int(77) == 0);
	CHECK(setting_ptr(77) == NULL);

	/* 类型不匹配：返回零值而非越界解释 */
	CHECK(setting_int(1) == 0);
	CHECK(setting_short(2) == 0);
	CHECK(setting_ptr(1) == NULL);
}

TEST(settings_empty_blob_parses_to_zero) {
	unsigned char blob[4096];
	memset(blob, 0, sizeof(blob));
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memcpy(myargs, blob, sizeof(blob));
	settings_init(NULL);
	CHECK(setting_short(1) == 0);
	CHECK(setting_ptr(1) == NULL);
}

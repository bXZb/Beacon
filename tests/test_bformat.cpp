/* formatp（bformat）追加式文本缓冲区的可执行规格。 */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "bformat.h"

TEST(bformat_printf_basic) {
	formatp f;
	bformat_init(&f, 1024);
	bformat_printf(&f, "hello %s %d", "world", 42);
	CHECK(strcmp(bformat_string(&f), "hello world 42") == 0);
	CHECK(bformat_length(&f) == 14);
	bformat_free(&f);
}

TEST(bformat_appends) {
	formatp f;
	bformat_init(&f, 1024);
	bformat_printf(&f, "a");
	bformat_printf(&f, "b");
	bformat_printf(&f, "c=%d", 3);
	CHECK(strcmp(bformat_string(&f), "abc=3") == 0);
	bformat_free(&f);
}

TEST(bformat_reset_clears_old_data) {
	/* 回归：原实现 memset 长度为刚清零的 buffer->length（恒 0 字节），
	   reset 后旧数据残留、且可能把后续内容拼在旧串尾部。 */
	formatp f;
	bformat_init(&f, 1024);
	bformat_printf(&f, "first-run-secret");
	bformat_reset(&f);
	CHECK(bformat_length(&f) == 0);
	CHECK(bformat_string(&f)[0] == '\0');
	CHECK(strncmp(bformat_string(&f), "first", 5) != 0);
	bformat_printf(&f, "x");
	CHECK(strcmp(bformat_string(&f), "x") == 0);
	bformat_free(&f);
}

TEST(bformat_int_is_network_order) {
	formatp f;
	bformat_init(&f, 64);
	bformat_int(&f, 0x11223344);
	const char * s = bformat_string(&f);
	CHECK((unsigned char)s[0] == 0x11);
	CHECK((unsigned char)s[1] == 0x22);
	CHECK((unsigned char)s[2] == 0x33);
	CHECK((unsigned char)s[3] == 0x44);
	CHECK(bformat_length(&f) == 4);
	bformat_free(&f);
}

TEST(bformat_copy_rejects_overflow) {
	formatp f;
	bformat_init(&f, 8);
	bformat_copy(&f, "12345678", 8);   /* 8 >= 8-0 → 拒绝（无 NUL 余量设计） */
	CHECK(bformat_length(&f) == 0);
	bformat_copy(&f, "1234567", 7);
	CHECK(bformat_length(&f) == 7);
	bformat_copy(&f, "9", 1);        /* 7+1 >= 8-0 → 拒绝 */
	CHECK(bformat_length(&f) == 7);
	bformat_free(&f);
}

TEST(bformat_tostring_reports_size) {
	/* 回归：原实现的 if (size == 0) 判断指针本身（恒假死分支）。 */
	formatp f;
	bformat_init(&f, 64);
	bformat_printf(&f, "abc");
	int sz = -1;
	char * p = bformat_tostring(&f, &sz);
	CHECK(p != NULL);
	CHECK(sz == 3);
	bformat_free(&f);
}

TEST(bformat_printf_overflow_rejected) {
	formatp f;
	bformat_init(&f, 8);
	bformat_printf(&f, "this string is way too long for an 8 byte buffer");
	CHECK(bformat_length(&f) == 0);
	bformat_free(&f);
}

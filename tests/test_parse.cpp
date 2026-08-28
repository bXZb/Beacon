/* datap 解析器的可执行规格 —— C2 线缆字节序（大端）的权威定义。 */
#include "test_harness.h"
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"

TEST(data_int_network_order) {
	char buf[8] = { 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0 };
	datap d;
	data_init(&d, buf, 8);
	CHECK(data_int(&d) == 0x12345678u);
	CHECK(data_length(&d) == 4);
}

TEST(data_int_truncated_returns_zero_without_consuming) {
	char buf[3] = { 0x12, 0x34, 0x56 };
	datap d;
	data_init(&d, buf, 3);
	CHECK(data_int(&d) == 0u);
	CHECK(data_length(&d) == 3); /* 不应推进 */
}

TEST(data_byte_and_truncation) {
	char buf[2] = { 0x7f, (char)0x80 };
	datap d;
	data_init(&d, buf, 2);
	CHECK(data_byte(&d) == 0x7fu);
	CHECK(data_byte(&d) == 0x80u); /* char 提取后转无符号 */
	CHECK(data_byte(&d) == 0u);    /* 耗尽返回 0 */
}

TEST(data_short_network_order_and_no_overread) {
	/* 回归：原实现按 unsigned int 读取（4 字节），缓冲区只剩 2 字节时越界读。
	   现按 unsigned short 读取，恰好消费 2 字节。 */
	char buf[2] = { 0x01, 0x02 };
	datap d;
	data_init(&d, buf, 2);
	CHECK(data_short(&d) == 0x0102u);
	CHECK(data_length(&d) == 0);
}

TEST(data_string_roundtrip) {
	/* 帧格式：[4B 大端长度][字节]，返回 len+1，缓冲区以 NUL 结尾 */
	char frame[16];
	unsigned int len = htonl(5);
	memcpy(frame, &len, 4);
	memcpy(frame + 4, "hello", 5);

	char out[32];
	datap d;
	data_init(&d, frame, 9);
	CHECK(data_string(&d, out, 32) == 6);
	CHECK(strcmp(out, "hello") == 0);
	CHECK(data_length(&d) == 0);
}

TEST(data_string_zero_len_rejected) {
	char frame[8] = { 0, 0, 0, 0 };
	char out[8];
	datap d;
	data_init(&d, frame, 4);
	CHECK(data_string(&d, out, 8) == 0);
}

TEST(data_string_exceeds_max_rejected) {
	char frame[16];
	unsigned int len = htonl(100);
	memcpy(frame, &len, 4);
	char out[8];
	datap d;
	data_init(&d, frame, 4);
	CHECK(data_string(&d, out, 8) == 0); /* 100+1 >= 8 */
}

TEST(data_extract_roundtrip) {
	char frame[16];
	unsigned int len = htonl(3);
	memcpy(frame, &len, 4);
	memcpy(frame + 4, "abc", 3);
	datap d;
	data_init(&d, frame, 7);
	datap_buffer b = data_extract(&d);
	CHECK(b.length == 3);
	CHECK(b.buffer != NULL && memcmp(b.buffer, "abc", 3) == 0);
}

TEST(data_ptr_exhausted_returns_null) {
	char buf[4] = { 0 };
	datap d;
	data_init(&d, buf, 4);
	CHECK(data_ptr(&d, 5) == NULL);
	CHECK(data_ptr(&d, 4) == buf);   /* 恰好剩余可用 */
	CHECK(data_ptr(&d, 1) == NULL);  /* 已耗尽 */
}

TEST(data_alloc_free_roundtrip) {
	datap * d = data_alloc(64);
	CHECK(d != NULL);
	CHECK(data_length(d) == 64);
	data_free(d);
}

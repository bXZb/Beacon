/* miniprintf 引擎单测（P5 瘦身组件的安全网）。
 * 本 TU 把 src/miniprintf.cpp 链进测试进程，CRT 的 sprintf/_snprintf/vsprintf_s
 * 内联包装都会汇入我们重写的 __stdio_common_vsprintf —— 因此直接调用 CRT
 * 入口即测得真实引擎行为。
 *
 * 重点回归：真实 TS 测试中 `ls` 崩溃的根因 —— 旧引擎对 %I64d 只吞掉 "I"，
 * '6' 落进转换分支导致 vararg 错位一格，尾部 %s 读整数当指针 → 访问违例。 */
#include "test_harness.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

TEST(mini_i64d_reads_64bit_and_consumes_arg) {
	/* 回归：%I64d 必须消费 64 位参数，且后续 %s 不得错位（旧版在此崩溃） */
	char buf[128];
	long long big = 0x7FFFFFFF1234LL; /* 高低位都非零，暴露任何 32 位截断 */
	int r = _snprintf(buf, sizeof(buf), "F %I64d %s", big, "tail");
	CHECK(r > 0);
	CHECK(strstr(buf, "F 549755743796 tail") == buf); /* 0x7FFFFFFF1234 = 549755743796 */
}

TEST(mini_lld_equivalent) {
	char buf[64];
	_snprintf(buf, sizeof(buf), "%lld", -42LL);
	CHECK(strcmp(buf, "-42") == 0);
}

TEST(mini_i32_keeps_32bit) {
	char buf[64];
	_snprintf(buf, sizeof(buf), "%I32d|%s", 12345, "x");
	CHECK(strcmp(buf, "12345|x") == 0);
}

TEST(mini_single_l_stays_32bit) {
	char buf[64];
	long v = 777; /* Windows 上 long = 32 位：%ld 必须按 32 位读 */
	_snprintf(buf, sizeof(buf), "%ld|%s", v, "y");
	CHECK(strcmp(buf, "777|y") == 0);
}

TEST(mini_basic_int_width_zero_pad) {
	char buf[64];
	_snprintf(buf, sizeof(buf), "%02d/%02d %5d|%-5d|", 7, 9, 42, 42);
	CHECK(strcmp(buf, "07/09    42|42   |") == 0);
}

TEST(mini_hex_and_percent) {
	char buf[64];
	_snprintf(buf, sizeof(buf), "%x %X 100%%", 255, 255);
	CHECK(strcmp(buf, "ff FF 100%") == 0);
}

TEST(mini_null_string_safe) {
	char buf[64];
	_snprintf(buf, sizeof(buf), "[%s]", (const char *)NULL);
	CHECK(strcmp(buf, "[(null)]") == 0);
}

TEST(mini_backslash_passthrough) {
	char buf[128];
	/* filesys.cpp 的路径拼接：fmt 里的 \\ 是两个字面反斜杠 */
	_snprintf(buf, sizeof(buf), "%s\\%s", "C:\\Windows", "file.txt");
	CHECK(strcmp(buf, "C:\\Windows\\file.txt") == 0);
}

TEST(mini_truncation_and_return_count) {
	char buf[8];
	int r = _snprintf(buf, sizeof(buf), "abcdefghijk");
	CHECK(r == 11);            /* C99 语义：返回"应写出"的字符数 */
	CHECK(strlen(buf) == 7);   /* 缓冲内截断且以 NUL 结尾 */
}

TEST(mini_vscprintf_counts_without_writing) {
	/* bformat_printf 的长度预估路径：_vscprintf 以 NULL 缓冲走同一引擎 */
	int n = _vscprintf("%s %I64d", "abc", 0x7FFFFFFF1234LL);
	CHECK(n == 3 + 1 + 12);
}

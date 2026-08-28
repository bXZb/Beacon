/* 宿主机侧测试框架：零依赖，断言失败即抛异常，main 汇总退出码。 */
#pragma once
#include <vector>
#include <string>
#include <stdexcept>

struct TestFailure : std::runtime_error {
	explicit TestFailure(const std::string& m) : std::runtime_error(m) {}
};

struct TestCase { const char* name; void (*fn)(); };

std::vector<TestCase>& test_registry();

inline int register_test(const char* name, void (*fn)()) {
	test_registry().push_back(TestCase{ name, fn });
	return 0;
}

int run_all_tests();

/* 注册一个用例：TEST(roundtrip) { CHECK(...); } */
#define TEST(name)                                                        \
	static void test_##name();                                            \
	namespace { static const int reg_##name = register_test(#name, &test_##name); } \
	static void test_##name()

#define CHECK(cond)                                                        \
	do {                                                                   \
		if (!(cond))                                                       \
			throw TestFailure(std::string("CHECK failed: ") + #cond +      \
				"  [" __FILE__ "]");                                       \
	} while (0)

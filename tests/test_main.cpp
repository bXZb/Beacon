#include "test_harness.h"
#include <cstdio>

std::vector<TestCase>& test_registry() {
	static std::vector<TestCase> registry;
	return registry;
}

int run_all_tests() {
	int failed = 0;
	std::vector<TestCase>& all = test_registry();
	printf("== %zu tests ==\n", all.size());

	for (size_t i = 0; i < all.size(); i++) {
		try {
			all[i].fn();
			printf("[PASS] %s\n", all[i].name);
		} catch (const TestFailure& e) {
			printf("[FAIL] %s\n       %s\n", all[i].name, e.what());
			failed++;
		} catch (const std::exception& e) {
			printf("[FAIL] %s\n       unexpected: %s\n", all[i].name, e.what());
			failed++;
		}
	}

	printf("== %zu/%zu passed ==\n", all.size() - failed, all.size());
	return failed == 0 ? 0 : 1;
}

int main() {
	return run_all_tests();
}

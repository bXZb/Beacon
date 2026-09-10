#include "test_harness.h"
#include <cstdio>

void command_shell_post(char * buffer, int length, int type, int sendNow) {
	(void)buffer;
	(void)length;
	(void)type;
	(void)sendNow;
}

char post_url[1024];

void http_flush_post(char * url) {
	(void)url;
}

std::vector<TestCase>& test_registry() {
	static std::vector<TestCase> registry;
	return registry;
}

int run_all_tests() {
	int failed = 0;
	std::vector<TestCase>& all = test_registry();
	printf("== %zu tests ==\n", all.size());
	fflush(stdout); /* CI 管道下 stdout 全缓冲，逐条冲刷保证崩溃时也能看到现场 */

	for (size_t i = 0; i < all.size(); i++) {
		printf("[RUN ] %s\n", all[i].name);
		fflush(stdout);
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
		fflush(stdout);
	}

	printf("== %zu/%zu passed ==\n", all.size() - failed, all.size());
	fflush(stdout);
	return failed == 0 ? 0 : 1;
}

int main() {
	return run_all_tests();
}

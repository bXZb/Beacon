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

#include <Windows.h>

/* process-wide VEH: any AV in any test prints code/fault/rip/rsp before the
 * process dies - the CI log is the only debugger we have */
static LONG WINAPI test_veh(PEXCEPTION_POINTERS ep) {
	printf("[veh] code=%08X fault=%p rip=%p rsp=%p
",
	       (unsigned)ep->ExceptionRecord->ExceptionCode,
	       (void *)(size_t)ep->ExceptionRecord->ExceptionInformation[1],
	       (void *)ep->ContextRecord->Rip,
	       (void *)ep->ContextRecord->Rsp);
	fflush(stdout);
	return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
	AddVectoredExceptionHandler(1, test_veh);
	return run_all_tests();
}

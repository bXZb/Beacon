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
	/* raw WriteFile with manual hex formatting: a corrupted CRT/heap must
	 * not take the VEH down with it (fprintf here dies twice and kills the
	 * whole log - the round-27 lesson) */
	char buf[192];
	static const char hex[] = "0123456789ABCDEF";
	unsigned code = (unsigned)ep->ExceptionRecord->ExceptionCode;
	unsigned long long fault = (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1];
	unsigned long long rip = (unsigned long long)ep->ContextRecord->Rip;
	unsigned long long rsp = (unsigned long long)ep->ContextRecord->Rsp;
	int n = 0, i;
	const char * pre = "[veh] code=";
	for (i = 0; pre[i]; i++) buf[n++] = pre[i];
	for (i = 28; i >= 0; i -= 4) buf[n++] = hex[(code >> i) & 0xF];
	pre = " fault=";
	for (i = 0; pre[i]; i++) buf[n++] = pre[i];
	for (i = 60; i >= 0; i -= 4) buf[n++] = hex[(fault >> i) & 0xF];
	pre = " rip=";
	for (i = 0; pre[i]; i++) buf[n++] = pre[i];
	for (i = 60; i >= 0; i -= 4) buf[n++] = hex[(rip >> i) & 0xF];
	pre = " rsp=";
	for (i = 0; pre[i]; i++) buf[n++] = pre[i];
	for (i = 60; i >= 0; i -= 4) buf[n++] = hex[(rsp >> i) & 0xF];
	buf[n++] = '\r';
	buf[n++] = '\n';
	{
		DWORD written = 0;
		WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)n, &written, NULL);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
	AddVectoredExceptionHandler(1, test_veh);
	return run_all_tests();
}

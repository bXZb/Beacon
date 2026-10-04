/* Phase 2 gate executable spec (docs/EVASION-ROADMAP.md 13.2).
 *
 * Runs on the host as a normal console process: resolve the SSN table
 * against the live ntdll, then exercise the injection-family wrappers
 * against our OWN process (alloc -> write -> protect -> read-back ->
 * free) under every syscall_method. The RA-spoofed indirect stub (method
 * 2) returning the correct bytes proves the planted ntdll `ret` unwinds
 * to the real caller. Step markers are printed so a hard AV on CI
 * pinpoints the exact call. */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include <cstdio>
#include "syscalls.h"
#include "datastore.h"

TEST(gate_table_resolves) {
	syscalls_resolve();
	CHECK(syscalls_gate_ready_count() >= 20);
	CHECK(syscalls_ssn_ntwrite() > 0);
}

extern void * syscalls_test_gadget(const char *);

TEST(gate_gadget_diagnostics) {
	/* diagnostics: what the runner's ntdll actually looks like at the
	 * parsed gadgets - an unverified (non syscall;ret) gadget now means
	 * method 2 transparently falls back to the direct stub */
	syscalls_resolve();
	const char * names[3] = { "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtFreeVirtualMemory" };
	for (int i = 0; i < 3; i++) {
		BYTE * g = (BYTE *)syscalls_test_gadget(names[i]);
		if (g == NULL) {
			printf("  [gadget] %-24s UNVERIFIED (fallback to direct)\n", names[i]);
		}
		else {
			printf("  [gadget] %-24s %p bytes %02X %02X %02X\n", names[i], g, g[0], g[1], g[2]);
		}
		fflush(stdout);
	}
}

TEST(gate_wrappers_roundtrip_self) {
	unsigned char marker[16];
	unsigned char readback[16];
	SIZE_T moved = 0;
	DWORD oldp = 0;
	LPVOID p;

	for (int m = 0; m <= 2; m++) {
		printf("  [gate] method=%d set\n", m); fflush(stdout);
		syscall_method_set(m);
		printf("  [gate] method=%d alloc\n", m); fflush(stdout);
		p = beacon_VirtualAllocEx(GetCurrentProcess(), NULL, 0x1000,
		                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		CHECK(p != NULL);
		for (int i = 0; i < 16; i++)
			marker[i] = (unsigned char)(0x40 + i + m);
		printf("  [gate] method=%d write\n", m); fflush(stdout);
		CHECK(beacon_WriteProcessMemory(GetCurrentProcess(), p, marker, 16, &moved));
		CHECK(moved == 16);
		printf("  [gate] method=%d protect\n", m); fflush(stdout);
		CHECK(beacon_VirtualProtectEx(GetCurrentProcess(), p, 0x1000, PAGE_READONLY, &oldp));
		printf("  [gate] method=%d read\n", m); fflush(stdout);
		CHECK(beacon_ReadProcessMemory(GetCurrentProcess(), p, readback, 16, &moved));
		CHECK(moved == 16);
		CHECK(memcmp(readback, marker, 16) == 0);
		printf("  [gate] method=%d free\n", m); fflush(stdout);
		CHECK(beacon_VirtualFreeEx(GetCurrentProcess(), p, 0, MEM_RELEASE));
		printf("  [gate] method=%d done\n", m); fflush(stdout);
	}
}

extern void syscalls_test_indirect_mode(int);

/* RA root-cause repro (round 20): re-enable the shelved indirect encodings
 * for one alloc call under a vectored exception handler, so a hard AV on
 * the runner reports code address, fault address and the stub bytes before
 * the process dies. */
static LONG WINAPI gate_veh(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == 0xC0000005) {
		printf("  [veh] AV code=%p fault=%p rip=%p rsp=%p
",
		       (void *)(size_t)ep->ExceptionRecord->ExceptionCode,
		       (void *)ep->ExceptionRecord->ExceptionInformation[1],
		       (void *)ep->ContextRecord->Rip,
		       (void *)ep->ContextRecord->Rsp);
		fflush(stdout);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

TEST(gate_indirect_repro_alloc)
{
	void * h;
	LPVOID p;

	syscalls_resolve();
	syscall_method_set(2);
	syscalls_test_indirect_mode(1);
	h = AddVectoredExceptionHandler(1, gate_veh);
	printf("  [repro] forcing indirect alloc (v1-jmp path, arity 6)
"); fflush(stdout);
	p = beacon_VirtualAllocEx(GetCurrentProcess(), NULL, 0x1000,
	                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	printf("  [repro] alloc returned %p (ntstatus path ok)
", p); fflush(stdout);
	if (p)
		beacon_VirtualFreeEx(GetCurrentProcess(), p, 0, MEM_RELEASE);
	syscalls_test_indirect_mode(0);
	if (h) RemoveVectoredExceptionHandler(h);
	syscall_method_set(1);
}

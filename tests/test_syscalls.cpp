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

static LONG WINAPI gate_veh(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == 0xC0000005) {
		printf("  [veh] AV code=%p fault=%p rip=%p rsp=%p\n",
		       (void *)(size_t)ep->ExceptionRecord->ExceptionCode,
		       (void *)ep->ExceptionRecord->ExceptionInformation[1],
		       (void *)ep->ContextRecord->Rip,
		       (void *)ep->ContextRecord->Rsp);
		fflush(stdout);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

TEST(gate_install_veh)
{
	AddVectoredExceptionHandler(1, gate_veh);
}

TEST(gate_table_resolves) {
	syscalls_resolve();
	CHECK(syscalls_gate_ready_count() >= 20);
	CHECK(syscalls_ssn_ntwrite() > 0);
}

extern void * syscalls_test_gadget(const char *);
extern void * syscalls_test_leave_gadget(void);
extern const char * syscalls_test_form(const char * name);

TEST(gate_gadget_diagnostics) {
	/* diagnostics: what the runner's ntdll actually looks like at the
	 * parsed gadgets - an unverified (non syscall;ret) gadget now means
	 * method 2 transparently falls back to the direct stub */
	BYTE * leave;
	const char * names[4] = { "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtFreeVirtualMemory", "NtCreateThreadEx" };
	syscalls_resolve();
	for (int i = 0; i < 4; i++) {
		BYTE * g = (BYTE *)syscalls_test_gadget(names[i]);
		if (g == NULL) {
			printf("  [gadget] %-24s UNVERIFIED (fallback to direct)\n", names[i]);
		}
		else {
			printf("  [gadget] %-24s %p bytes %02X %02X %02X\n", names[i], g, g[0], g[1], g[2]);
		}
		fflush(stdout);
	}
	leave = (BYTE *)syscalls_test_leave_gadget();
	if (leave == NULL) {
		printf("  [gadget] leave;ret NOT FOUND - v3 unavailable, v2/direct fallback\n");
	}
	else {
		printf("  [gadget] leave;ret %p bytes %02X %02X\n", leave, leave[0], leave[1]);
	}
	for (int i = 0; i < 4; i++) {
		printf("  [form]   %-24s -> %s\n", names[i], syscalls_test_form(names[i]));
		fflush(stdout);
	}
	/* the round-26 assertion: with a verified syscall gadget the runner
	 * must NOT fall back to a direct stub for the injection family - the
	 * synthetic-frame path (or at worst v2 for <=4 arity) has to engage */
	CHECK(strcmp(syscalls_test_form("NtWriteVirtualMemory"), "direct") != 0);
	CHECK(strcmp(syscalls_test_form("NtAllocateVirtualMemory"), "direct") != 0);
}

TEST(gate_wrappers_roundtrip_self) {
	unsigned char marker[16];
	unsigned char readback[16];
	SIZE_T moved = 0;
	DWORD oldp = 0;
	LPVOID p;

	/* method 2 now routes the stack-argument syscalls (alloc=6, write=5,
	 * protect=5, read=5) through the v3 synthetic-frame stub: a green
	 * roundtrip proves the leave;ret pivot restores the real frame and
	 * the NTSTATUS lands in rax for every arity */
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

TEST(gate_indirect_repro_alloc)
{
	void * h;
	LPVOID p;

	syscalls_resolve();
	syscall_method_set(2);
	syscalls_test_indirect_mode(1);
	(void)h;
	printf("  [repro] m=2 alloc (arity 6 -> v3 synth stub; the arity-0 bug used to crash here)\n"); fflush(stdout);
	p = beacon_VirtualAllocEx(GetCurrentProcess(), NULL, 0x1000,
	                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	printf("  [repro] alloc returned %p\n", p); fflush(stdout);
	if (p) {
		printf("  [repro] m=2 free (arity 4 -> v3 too; v2 chain was the round-20 proof)\n"); fflush(stdout);
		CHECK(beacon_VirtualFreeEx(GetCurrentProcess(), p, 0, MEM_RELEASE));
		printf("  [repro] v3 synth free survived - leave;ret pivoted back to the real frame\n"); fflush(stdout);
	}
	syscalls_test_indirect_mode(0);
	syscall_method_set(1);
}

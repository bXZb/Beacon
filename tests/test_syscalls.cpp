/* Phase 2 gate executable spec (docs/EVASION-ROADMAP.md 13.2).
 *
 * Runs on the host as a normal console process: resolve the SSN table
 * against the live ntdll, then exercise the injection-family wrappers
 * against our OWN process (alloc -> write -> protect -> read-back ->
 * free) under every syscall_method. The RA-spoofed indirect stub (method
 * 2) returning the correct bytes proves the planted ntdll `ret` unwinds
 * to the real caller. */
#include "test_harness.h"
#include <Windows.h>
#include <string.h>
#include "syscalls.h"
#include "datastore.h"

TEST(gate_table_resolves) {
	syscalls_resolve();
	CHECK(syscalls_gate_ready_count() >= 20);
	CHECK(syscalls_ssn_ntwrite() > 0);
}

TEST(gate_wrappers_roundtrip_self) {
	unsigned char marker[16];
	unsigned char readback[16];
	SIZE_T moved = 0;
	DWORD oldp = 0;
	LPVOID p;

	for (int m = 0; m <= 2; m++) {
		syscall_method_set(m);
		p = beacon_VirtualAllocEx(GetCurrentProcess(), NULL, 0x1000,
		                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		CHECK(p != NULL);
		for (int i = 0; i < 16; i++)
			marker[i] = (unsigned char)(0x40 + i + m);
		CHECK(beacon_WriteProcessMemory(GetCurrentProcess(), p, marker, 16, &moved));
		CHECK(moved == 16);
		CHECK(beacon_VirtualProtectEx(GetCurrentProcess(), p, 0x1000, PAGE_READONLY, &oldp));
		CHECK(beacon_ReadProcessMemory(GetCurrentProcess(), p, readback, 16, &moved));
		CHECK(moved == 16);
		CHECK(memcmp(readback, marker, 16) == 0);
		/* MEM_RELEASE ignores protection - the page goes away */
		CHECK(beacon_VirtualFreeEx(GetCurrentProcess(), p, 0, MEM_RELEASE));
	}
}

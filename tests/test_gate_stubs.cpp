/* beacon_gate.cpp is not part of the host test link (it pulls in the gen3
 * and trace code), but syscalls.cpp calls the gate_* wrappers first. Give
 * it the gate-off behaviour - the plain API - so tests.exe links and the
 * syscall tests exercise exactly what they always did. The gate itself is
 * covered on target (kdebug probes) and its call thunk by
 * test_gate_thunk.cpp. */
#include "beacon_gate.h"

int gate_enabled(void) { return 0; }
int gate_api_enabled(int api) { (void)api; return 0; }

LPVOID gate_VirtualAlloc(LPVOID a, SIZE_T b, DWORD c, DWORD d) { return VirtualAlloc(a, b, c, d); }
LPVOID gate_VirtualAllocEx(HANDLE p, LPVOID a, SIZE_T b, DWORD c, DWORD d) { return VirtualAllocEx(p, a, b, c, d); }
BOOL gate_VirtualProtect(LPVOID a, SIZE_T b, DWORD c, PDWORD d) { return VirtualProtect(a, b, c, d); }
BOOL gate_VirtualProtectEx(HANDLE p, LPVOID a, SIZE_T b, DWORD c, PDWORD d) { return VirtualProtectEx(p, a, b, c, d); }
BOOL gate_VirtualFree(LPVOID a, SIZE_T b, DWORD c) { return VirtualFree(a, b, c); }
BOOL gate_GetThreadContext(HANDLE t, CONTEXT * c) { return GetThreadContext(t, c); }
BOOL gate_SetThreadContext(HANDLE t, CONTEXT * c) { return SetThreadContext(t, c); }
DWORD gate_ResumeThread(HANDLE t) { return ResumeThread(t); }
HANDLE gate_CreateThread(LPSECURITY_ATTRIBUTES a, SIZE_T b, LPTHREAD_START_ROUTINE c, LPVOID d, DWORD e, LPDWORD f) { return CreateThread(a, b, c, d, e, f); }
HANDLE gate_CreateRemoteThread(HANDLE p, LPSECURITY_ATTRIBUTES a, SIZE_T b, LPTHREAD_START_ROUTINE c, LPVOID d, DWORD e, LPDWORD f) { return CreateRemoteThread(p, a, b, c, d, e, f); }
HANDLE gate_OpenProcess(DWORD a, BOOL b, DWORD c) { return OpenProcess(a, b, c); }
HANDLE gate_OpenThread(DWORD a, BOOL b, DWORD c) { return OpenThread(a, b, c); }
BOOL gate_CloseHandle(HANDLE h) { return CloseHandle(h); }
HANDLE gate_CreateFileMappingA(HANDLE f, LPSECURITY_ATTRIBUTES a, DWORD b, DWORD c, DWORD d, const char * e) { return CreateFileMappingA(f, a, b, c, d, e); }
LPVOID gate_MapViewOfFile(HANDLE m, DWORD a, DWORD b, DWORD c, SIZE_T d) { return MapViewOfFile(m, a, b, c, d); }
BOOL gate_UnmapViewOfFile(LPCVOID b) { return UnmapViewOfFile(b); }
SIZE_T gate_VirtualQuery(LPCVOID a, PMEMORY_BASIC_INFORMATION b, SIZE_T c) { return VirtualQuery(a, b, c); }
BOOL gate_DuplicateHandle(HANDLE a, HANDLE b, HANDLE c, LPHANDLE d, DWORD e, BOOL f, DWORD g) { return DuplicateHandle(a, b, c, d, e, f, g); }
BOOL gate_ReadProcessMemory(HANDLE p, LPCVOID a, LPVOID b, SIZE_T c, SIZE_T * d) { return ReadProcessMemory(p, a, b, c, d); }
BOOL gate_WriteProcessMemory(HANDLE p, LPVOID a, LPCVOID b, SIZE_T c, SIZE_T * d) { return WriteProcessMemory(p, a, b, c, d); }
void gate_ExitThread(DWORD c) { ExitThread(c); }

/* The rest of what the suite links to but does not carry. Each was added
 * to a source of the test link after the suite last built (f15ccdc,
 * October) - nothing compiled the suite, so nothing missed them:
 *  - gargle_mask_bytes (gargleint.cpp): the session's mask bytes for
 *    BEACON_INFO.mask. Here a fixed pattern; nothing in the suite reads it.
 *  - spawn_log (spawn.cpp): the kdebug trace. A no-op in a release build
 *    too.
 *  - g3_snapshot_for_bofwin (sleepmask_gen3.cpp): 0 = no snapshot, so the
 *    bofwin engine finds nothing to mask.
 *  - gated_tramp / gated_target (gate_tramp.asm): the 16 bytes the gate's
 *    thunk returns through. Nothing in the suite arms the thunk. */
#include "gargleint.h"
#include "sleepmask_gen3.h"

void gargle_mask_bytes(char * out, int len) {
	int k;
	for (k = 0; k < len; k++)
		out[k] = (char)(0x5A ^ k);
}

extern "C" void spawn_log(const char * msg, long v) { (void)msg; (void)v; }

int g3_snapshot_for_bofwin(G3_HEADER_BLOCK * out, int max, DWORD * text_span) {
	(void)out; (void)max; (void)text_span;
	return 0;
}

extern "C" const unsigned char gated_tramp[16] = { 0xFF, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
extern "C" unsigned long long gated_target = 0;

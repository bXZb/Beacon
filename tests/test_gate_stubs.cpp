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

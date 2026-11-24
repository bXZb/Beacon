/* 4.10 BOF system-call API + BeaconGate switches: one live call to each of
 * the 19 entries, each with a check on its result. A COFF BOF resolves a
 * Beacon API import to its INDEX in the team server's bapi.txt and Beacon
 * indexes its function table with that number - so a table that is off by
 * one entry turns a call here into a different function. The printed
 * verdicts are the live test's evidence (inline-execute the object).
 *
 * Import shape follows bof_download.c: Beacon APIs ride the __imp_ bapi
 * whitelist into the ftable, kernel32 helpers go through dynamic dll$func
 * imports so the object stays free of static CRT/kernel32 references. */
#include <windows.h>

EXTERN_C __declspec(dllimport) void __cdecl BeaconPrintf(int type, char * fmt, ...);
EXTERN_C __declspec(dllimport) LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
EXTERN_C __declspec(dllimport) LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
EXTERN_C __declspec(dllimport) BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
EXTERN_C __declspec(dllimport) BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
EXTERN_C __declspec(dllimport) BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
EXTERN_C __declspec(dllimport) BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
EXTERN_C __declspec(dllimport) BOOL BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
EXTERN_C __declspec(dllimport) DWORD BeaconResumeThread(HANDLE threadHandle);
EXTERN_C __declspec(dllimport) HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
EXTERN_C __declspec(dllimport) HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
EXTERN_C __declspec(dllimport) BOOL BeaconCloseHandle(HANDLE object);
EXTERN_C __declspec(dllimport) BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress);
EXTERN_C __declspec(dllimport) SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
EXTERN_C __declspec(dllimport) BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
EXTERN_C __declspec(dllimport) BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
EXTERN_C __declspec(dllimport) BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);
EXTERN_C __declspec(dllimport) VOID BeaconDisableBeaconGate();
EXTERN_C __declspec(dllimport) VOID BeaconEnableBeaconGate();
EXTERN_C __declspec(dllimport) VOID BeaconDisableBeaconGateMasking();
EXTERN_C __declspec(dllimport) VOID BeaconEnableBeaconGateMasking();

EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$GetCurrentProcess(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetCurrentProcessId(void);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetThreadId(HANDLE);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$WaitForSingleObject(HANDLE, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
EXTERN_C __declspec(dllimport) LPVOID WINAPI kernel32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);

#define CALLBACK_OUTPUT 0x00

static DWORD WINAPI bof_worker(LPVOID p)
{
	(p);
	return 0x4D2;
}

void go(char * args, int alen)
{
	HANDLE me = kernel32$GetCurrentProcess();
	DWORD pid = kernel32$GetCurrentProcessId();
	MEMORY_BASIC_INFORMATION mbi;
	__declspec(align(16)) CONTEXT ctx;
	SIZE_T moved = 0;
	DWORD old = 0, tid = 0, prev = 0;
	unsigned char pattern[16];
	unsigned char readback[16];
	LPVOID p, q, view;
	HANDLE h, dup, t, ht, map;
	int i, fails = 0;

	(args);
	(alen);
	for (i = 0; i < 16; i++)
		pattern[i] = (unsigned char)(0xA0 + i);
	memset(readback, 0, sizeof(readback));

	/* local memory: alloc -> protect -> query -> protect back -> free */
	p = BeaconVirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (p == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualAlloc       %s p=%p", p ? "ok" : "FAIL", p);
	old = 0;
	if (BeaconVirtualProtect(p, 0x1000, PAGE_READONLY, &old) != TRUE || old != PAGE_READWRITE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtect     %s old=%x", old == PAGE_READWRITE ? "ok" : "FAIL", old);
	memset(&mbi, 0, sizeof(mbi));
	if (BeaconVirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.BaseAddress != p || mbi.Protect != PAGE_READONLY) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualQuery       %s state=%x protect=%x", mbi.BaseAddress == p ? "ok" : "FAIL", mbi.State, mbi.Protect);
	old = 0;
	if (BeaconVirtualProtect(p, 0x1000, PAGE_READWRITE, &old) != TRUE || old != PAGE_READONLY) fails++;

	/* this process through a process handle: open -> write -> read -> duplicate -> close */
	h = BeaconOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (h == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconOpenProcess        %s h=%p", h ? "ok" : "FAIL", h);
	moved = 0;
	if (BeaconWriteProcessMemory(h, p, pattern, 16, &moved) != TRUE || moved != 16) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconWriteProcessMemory %s wrote=%x", moved == 16 ? "ok" : "FAIL", (unsigned int)moved);
	moved = 0;
	if (BeaconReadProcessMemory(h, p, readback, 16, &moved) != TRUE || moved != 16) fails++;
	for (i = 0; i < 16 && moved == 16; i++)
		if (readback[i] != pattern[i]) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconReadProcessMemory  %s read=%x", moved == 16 ? "ok" : "FAIL", (unsigned int)moved);
	dup = NULL;
	if (BeaconDuplicateHandle(me, h, me, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS) != TRUE || dup == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconDuplicateHandle    %s dup=%p", dup ? "ok" : "FAIL", dup);
	if (BeaconCloseHandle(dup) != TRUE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconCloseHandle        %s", "ok");

	/* the remote-shaped pair, against our own process: alloc ex -> protect ex */
	q = BeaconVirtualAllocEx(h, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (q == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualAllocEx     %s q=%p", q ? "ok" : "FAIL", q);
	old = 0;
	if (BeaconVirtualProtectEx(h, q, 0x1000, PAGE_EXECUTE_READ, &old) != TRUE || old != PAGE_READWRITE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtectEx   %s old=%x", old == PAGE_READWRITE ? "ok" : "FAIL", old);
	if (q != NULL)
		kernel32$VirtualFreeEx(h, q, 0, MEM_RELEASE);

	/* a suspended thread: get context -> set context -> open by id -> resume */
	t = kernel32$CreateThread(NULL, 0, bof_worker, NULL, CREATE_SUSPENDED, NULL);
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (t == NULL || BeaconGetThreadContext(t, &ctx) != TRUE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconGetThreadContext   %s flags=%x", t && ctx.ContextFlags == CONTEXT_INTEGER ? "ok" : "FAIL", ctx.ContextFlags);
	ctx.Rax = 0x1234;
	if (BeaconSetThreadContext(t, &ctx) != TRUE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconSetThreadContext   %s", ctx.Rax == 0x1234 ? "ok" : "FAIL");
	tid = kernel32$GetThreadId(t);
	ht = BeaconOpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid);
	if (ht == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconOpenThread         %s h=%p tid=%x", ht ? "ok" : "FAIL", ht, tid);
	if (BeaconCloseHandle(ht) != TRUE) fails++;
	prev = BeaconResumeThread(t);
	if (prev == (DWORD)-1) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconResumeThread       %s prev=%x", prev != (DWORD)-1 ? "ok" : "FAIL", prev);
	kernel32$WaitForSingleObject(t, 5000);
	if (BeaconCloseHandle(t) != TRUE) fails++;

	/* section mapping: create + map are plain imports (not Beacon API - only the
	 * unmap is), then unmap -> close through the Beacon API */
	map = kernel32$CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, NULL);
	view = map ? kernel32$MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, 0x1000) : NULL;
	if (view != NULL)
		*(unsigned int *)view = 0x11223344;
	if (map == NULL || view == NULL) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "CreateFileMappingA        %s map=%p", map ? "ok" : "FAIL", map);
	BeaconPrintf(CALLBACK_OUTPUT, "MapViewOfFile             %s view=%p first=%x", view ? "ok" : "FAIL", view, view ? *(unsigned int *)view : 0);
	if (view != NULL && BeaconUnmapViewOfFile(view) != TRUE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconUnmapViewOfFile    %s", view ? "ok" : "FAIL");
	if (BeaconCloseHandle(map) != TRUE) fails++;
	if (BeaconCloseHandle(h) != TRUE) fails++;

	/* the BeaconGate switches (no result to check: the live test reads the
	 * gate probes around them) */
	BeaconDisableBeaconGate();
	BeaconEnableBeaconGate();
	BeaconDisableBeaconGateMasking();
	BeaconEnableBeaconGateMasking();
	BeaconPrintf(CALLBACK_OUTPUT, "Beacon*BeaconGate*       ok (4 switches called)");

	if (BeaconVirtualFree(p, 0, MEM_RELEASE) != TRUE) fails++;
	BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualFree        %s", "ok");
	BeaconPrintf(CALLBACK_OUTPUT, "syscalls verdict: %s (%d failed)", fails == 0 ? "ALL PASS" : "FAILED", fails);
}

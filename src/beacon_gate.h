/* beacon_gate.h - C-58 BeaconGate (4.10 parity) */
#pragma once

#include <windows.h>

/* per-API bits (setting 96) */
#define GATE_API_VIRTUALALLOC     (1 << 0)
#define GATE_API_VIRTUALALLOCEX   (1 << 1)
#define GATE_API_VIRTUALPROTECT   (1 << 2)
#define GATE_API_VIRTUALPROTECTEX (1 << 3)
#define GATE_API_INTERNETOPENA    (1 << 4)
#define GATE_API_INTERNETCONNECTA (1 << 5)
#define GATE_API_EXITTHREAD       (1 << 6)
#define GATE_API_ANY              0x7fffffff

#define MAX_BEACON_GATE_ARGUMENTS 8

/* official 4.10 contract shape (blog: instrumenting-beacon-with-beacongate) */
typedef struct _FUNCTION_CALL {
	void *              functionPtr;
	int                 function;    /* GATE_API_* bit */
	int                 numOfArgs;
	unsigned long long  args[MAX_BEACON_GATE_ARGUMENTS];
	BOOL                bMask;
	unsigned long long  retValue;
} FUNCTION_CALL, *PFUNCTION_CALL;

int  gate_enabled(void);
int  gate_api_enabled(int api_bit);
unsigned long long gate_dispatch(FUNCTION_CALL * fc);

LPVOID gate_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
LPVOID gate_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
BOOL   gate_VirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD old);
BOOL   gate_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old);

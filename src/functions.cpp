#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"

/* Wow64DisableWow64FsRedirection */
void DisableWow64(PVOID *OldValue) {
	BOOL (WINAPI *function)(PVOID *);

	function = (BOOL (WINAPI *)(PVOID *)) GetProcAddress(GetModuleHandleA("kernel32"), "Wow64DisableWow64FsRedirection");

	if (NULL != function) {
		function(OldValue);
	}
}

void RevertWow64(PVOID OldValue) {
	BOOL (WINAPI *function)(PVOID);

	function = (BOOL (WINAPI *)(PVOID)) GetProcAddress(GetModuleHandleA("kernel32"), "Wow64RevertWow64FsRedirection");

	if (NULL != function) {
		function(OldValue);
	}
}

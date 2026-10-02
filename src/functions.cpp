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

/* 就地把 "sysnative" 折叠为 "system32"（9 -> 8 字节，尾部左移一格）。
 * 三个调用点原先各自手写 20 行临时缓冲搬运。 */
void fold_sysnative(char * buf) {
	char * foundp = strstr(buf, "sysnative");
	if (foundp == NULL)
		return;
	memcpy(foundp, "system32", 8);
	foundp += 9;
	memmove(foundp - 1, foundp, strlen(foundp) + 1);
}

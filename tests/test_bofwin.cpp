/* Phase 3 BOF-window executable spec (docs/EVASION-ROADMAP.md 13.11).
 *
 * Runs on the host as a normal console process: settings_init points the
 * engine at THIS test exe, so the masked "beacon image" is the test module
 * itself. The "BOF" is a hand-assembled position-independent checker on a
 * private RWX page (exactly where a real BOF lives) that checksums the
 * module's .text while the window has it encrypted and stores the result
 * into an unmasked args buffer.
 *
 *  roundtrip: the checksum taken inside the window differs from the
 *  plaintext sum, and the sum taken after the window matches the
 *  pre-window plaintext (mask + unmask restored every byte, protections
 *  back to their original values).
 *
 *  watchdog: the checker spins long after a 50ms watchdog; the fire count
 *  hook proves the timer path restored everything while the "BOF" was
 *  still running, and the post-window sum still matches plaintext (the
 *  exit path correctly skipped the double unmask). */
#include "test_harness.h"
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "beacon.h"   /* settings_init / setting_int declarations */
#include "gargleint.h" /* GARGLEP layout; setup stubbed below */
#include "sleepmask_bofwin.h"

/* test-local stubs (test_datastore.cpp owns the shared gparms in this
 * link; bofwin needs a working setup that points beacon_ptr at the module
 * and an empty section table - the engine then snapshots the test exe's
 * real PE layout through its own parser) */
volatile long threadcount = 0;

void gargle_setup_parms(void * begin, void * end, int mask_fn_in_beacon) {
	(void)begin; (void)end; (void)mask_fn_in_beacon;
	if (gparms != NULL)
		return;
	gparms = (GARGLEP *)malloc(sizeof(GARGLEP));
	memset(gparms, 0, sizeof(GARGLEP));
	gparms->beacon_ptr = (char *)GetModuleHandleA(NULL);
}

/* checker blob: rcx = args { void *region; unsigned int *result; }
 *   sum = bytes of region[0..0x100); *result = sum; ret
 * watchdog variant computes the sum first, then spins ~0.6-2s, THEN stores
 * - proving the watchdog restored plaintext while the spin was running. */
static const unsigned char checker[] = {
	0x48, 0x8B, 0x01,                         /* mov rax, [rcx]            */
	0x45, 0x31, 0xC0,                         /* xor r8d, r8d              */
	0x41, 0xB9, 0x00, 0x01, 0x00, 0x00,       /* mov r9d, 0x100            */
	/* loop: */
	0x44, 0x0F, 0xB6, 0x10,                   /* movzx r10d, byte [rax]    */
	0x45, 0x01, 0xD0,                         /* add r8d, r10d             */
	0x48, 0xFF, 0xC0,                         /* inc rax                   */
	0x41, 0xFF, 0xC9,                         /* dec r9d                   */
	0x75, 0xF1,                               /* jne loop                  */
	0x48, 0x8B, 0x41, 0x08,                   /* mov rax, [rcx+8]          */
	0x44, 0x89, 0x00,                         /* mov [rax], r8d  (45 89 00 decoded as mov [r8],r8d - the store used the SUM as a pointer, the CI crash) */
	0xC3,                                     /* ret                       */
};

static const unsigned char checker_wd[] = {
	0x48, 0x8B, 0x01,                         /* mov rax, [rcx]            */
	0x45, 0x31, 0xC0,                         /* xor r8d, r8d              */
	0x41, 0xB9, 0x00, 0x01, 0x00, 0x00,       /* mov r9d, 0x100            */
	/* loop: */
	0x44, 0x0F, 0xB6, 0x10,
	0x45, 0x01, 0xD0,
	0x48, 0xFF, 0xC0,
	0x41, 0xFF, 0xC9,
	0x75, 0xF1,
	/* spin ~0x5-1.5s so the 50ms watchdog lands mid-run */
	0x41, 0xBB, 0x00, 0x00, 0x00, 0x10,       /* mov r11d, 0x10000000      */
	/* spin: */
	0x49, 0xFF, 0xCB,                         /* dec r11                   */
	0x75, 0xFD,                               /* jne spin                  */
	0x48, 0x8B, 0x41, 0x08,                   /* mov rax, [rcx+8]          */
	0x44, 0x89, 0x00,                         /* mov [rax], r8d            */
	0xC3,
};

extern volatile long g_bw_watchdog_fires;

static unsigned int sum_region(const unsigned char * p, int n)
{
	unsigned int s = 0;
	int i;

	for (i = 0; i < n; i++)
		s += p[i];
	return s;
}

static void * make_page(const unsigned char * code, int len)
{
	void * p = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (p == NULL)
		return NULL;
	memcpy(p, code, len);
	{
		DWORD old = 0;
		VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &old);
		FlushInstructionCache(GetCurrentProcess(), p, 0x1000);
	}
	return p;
}

TEST(bofwin_engine_ready) {
	settings_init(GetModuleHandleA(NULL));
	gargle_setup_parms(NULL, NULL, 0);
	CHECK(gparms != NULL);
	CHECK(gparms->beacon_ptr == (char *)GetModuleHandleA(NULL));
	CHECK(bofwin_supported());
}

TEST(bofwin_window_roundtrip) {
	unsigned char * region = (unsigned char *)gparms->beacon_ptr + 0x1000;
	void * args;
	unsigned int * result;
	unsigned int before, after;
	void (*bof)(void *, int) = (void (*)(void *, int))make_page(checker, sizeof(checker));

	CHECK(bof != NULL);
	args = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	result = (unsigned int *)((unsigned char *)args + 0x100);
	((void **)args)[0] = region;
	((void **)args)[1] = result;

	before = sum_region(region, 0x100);
	printf("  [bofwin] plaintext sum  = %u\n", before); fflush(stdout);
	CHECK(bofwin_window(bof, args, 16, 0) == TRUE);
	after = sum_region(region, 0x100);
	printf("  [bofwin] window sum     = %u (masked)\n", *result);
	printf("  [bofwin] restored sum   = %u\n", after); fflush(stdout);
	CHECK(*result != before);   /* the window really had .text encrypted  */
	CHECK(after == before);     /* and the unmask restored every byte     */
}

TEST(bofwin_watchdog_restores) {
	unsigned char * region = (unsigned char *)gparms->beacon_ptr + 0x1000;
	void * args;
	unsigned int * result;
	unsigned int before, after;
	long fires0;
	void (*bof)(void *, int) = (void (*)(void *, int))make_page(checker_wd, sizeof(checker_wd));

	CHECK(bof != NULL);
	args = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	result = (unsigned int *)((unsigned char *)args + 0x100);
	((void **)args)[0] = region;
	((void **)args)[1] = result;

	before = sum_region(region, 0x100);
	fires0 = g_bw_watchdog_fires;
	CHECK(bofwin_window(bof, args, 16, 50) == TRUE);
	after = sum_region(region, 0x100);
	printf("  [bofwin] wd fires delta = %ld, masked sum %u, restored %u\n",
	       g_bw_watchdog_fires - fires0, *result, after); fflush(stdout);
	CHECK(g_bw_watchdog_fires == fires0 + 1); /* the timer path ran        */
	CHECK(*result != before);                 /* checksum taken masked     */
	CHECK(after == before);                   /* restored, no double-unmask*/
}

TEST(bofwin_stub_page_dump) {
	unsigned char * page = (unsigned char *)bofwin_test_stub_page();
	/* declared in sleepmask_bofwin.h; this use also pins the export */
	int i;

	CHECK(page != NULL);
	printf("  [bofwin] stub page:");
	for (i = 0; i < 0x30; i++)
		printf(" %02X", page[i]);
	printf(" ...\n"); fflush(stdout);
}

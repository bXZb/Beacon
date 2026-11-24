/* BeaconGate call thunk (sleepmask_bofwin.cpp, BW_CALL_OFF) executable
 * spec.
 *
 * The thunk is hand-assembled and lays out an x64 call frame by hand: the
 * four register arguments, the six stack slots, 32 bytes of shadow space
 * between the callee's return address and its first stack argument, and a
 * 16-byte alignment. This runs the REAL bytes the REAL page builder emits
 * for every arity 0..10:
 *
 *   - each argument arrives in its own slot (a shifted record offset shows
 *     up as the neighbour's value; a missing shadow space shows up as a
 *     zero or a neighbour's value in a4..a7),
 *   - the callee enters with rsp%16==8, as after a real call,
 *   - the return value lands in the record and the caller's stack is
 *     intact when the thunk returns (a wrong `add rsp` returns to garbage
 *     or trips the caller's /GS cookie).
 *
 * It is called straight from C, which gives it the same entry state
 * enter_stub does (rsp%16==8, a return address on top). Only the page
 * builder is linked - no image, no mask window. */
#include "test_harness.h"
#include <Windows.h>
#include <intrin.h>
#include <stdio.h>
#include "sleepmask_bofwin.h"
#include "gargleint.h"
#include "sleepmask_gen3.h"
#include "crypto.h"

/* must match sleepmask_bofwin.cpp */
#define BW_CALL_OFF 0x210

/* the engine's externs: the page builder never calls them, the linker
 * wants them */
volatile long threadcount = 0;
GARGLEP * gparms = NULL;
int g3_snapshot_for_bofwin(G3_HEADER_BLOCK * out, int max, DWORD * text_span) {
	(void)out; (void)max; (void)text_span;
	return 0;
}
unsigned long crypto_rng_get_bytes(unsigned char * out, unsigned long outlen) {
	unsigned long i;
	for (i = 0; i < outlen; i++)
		out[i] = (unsigned char)(i * 7 + 1);
	return outlen;
}

/* the record the thunk reads: {fn, ret, args[10]} */
struct CALL_RECORD {
	unsigned long long fn;
	unsigned long long ret;
	unsigned long long args[10];
};

/* ten distinct odd multipliers: the return value depends on every
 * argument in its own slot */
static unsigned long long mix(const unsigned long long * a)
{
	static const unsigned long long k[10] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31 };
	unsigned long long r = 0;
	int i;
	for (i = 0; i < 10; i++)
		r += a[i] * k[i];
	return r;
}

static unsigned long long g_seen[10];
static unsigned long long g_bad_align;

/* noinline: the checks must run in the callee's own frame */
extern "C" __declspec(noinline) unsigned long long thunk_callee(
	unsigned long long a0, unsigned long long a1, unsigned long long a2, unsigned long long a3,
	unsigned long long a4, unsigned long long a5, unsigned long long a6, unsigned long long a7,
	unsigned long long a8, unsigned long long a9)
{
	/* a callee is entered right after a call: the return address sits at
	 * rsp, rsp%16 == 8. The compiler addresses a4..a9 at return+0x28..,
	 * so reading them is the shadow-space check. */
	if (((unsigned long long)_AddressOfReturnAddress() & 15) != 8)
		g_bad_align++;

	g_seen[0] = a0; g_seen[1] = a1; g_seen[2] = a2; g_seen[3] = a3;
	g_seen[4] = a4; g_seen[5] = a5; g_seen[6] = a6; g_seen[7] = a7;
	g_seen[8] = a8; g_seen[9] = a9;
	return mix(g_seen);
}

TEST(gate_thunk_page) {
	CHECK(bofwin_supported());
	CHECK(bofwin_test_stub_page() != NULL);
	/* the thunk starts with `push rbx` */
	CHECK(((unsigned char *)bofwin_test_stub_page())[BW_CALL_OFF] == 0x53);
}

TEST(gate_thunk_call_every_arity) {
	unsigned char * page = (unsigned char *)bofwin_test_stub_page();
	void (*thunk)(void *) = (void (*)(void *))(page + BW_CALL_OFF);
	unsigned long long want[10];
	int n, i;
	struct CALL_RECORD rec;

	FlushInstructionCache(GetCurrentProcess(), page, 0x1000);
	for (n = 0; n <= 10; n++) {
		memset(&rec, 0, sizeof(rec));
		memset(want, 0, sizeof(want));
		rec.fn = (unsigned long long)(size_t)thunk_callee;
		for (i = 0; i < n; i++) {
			want[i] = 0x0101010101010101ull * (unsigned long long)(i + 1) + 0x1000ull * (unsigned long long)n;
			rec.args[i] = want[i];
		}
		g_bad_align = 0;
		memset(g_seen, 0xEE, sizeof(g_seen));
		thunk(&rec);

		printf("  [thunk] nargs=%d ret=%016llx align=%llu\n", n, rec.ret, g_bad_align);
		fflush(stdout);
		CHECK(g_bad_align == 0);
		for (i = 0; i < 10; i++) {
			if (g_seen[i] != want[i]) {
				printf("  [thunk] nargs=%d arg %d: got %016llx want %016llx\n", n, i, g_seen[i], want[i]);
				fflush(stdout);
				CHECK(g_seen[i] == want[i]);
			}
		}
		CHECK(rec.ret == mix(want));
	}
}

/* a real Win32 call through the thunk: a buffer argument and an output
 * pointer must be usable by the callee */
TEST(gate_thunk_call_win32) {
	unsigned char * page = (unsigned char *)bofwin_test_stub_page();
	void (*thunk)(void *) = (void (*)(void *))(page + BW_CALL_OFF);
	struct CALL_RECORD rec;
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID p = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	CHECK(p != NULL);
	memset(&rec, 0, sizeof(rec));
	rec.fn = (unsigned long long)(size_t)VirtualQuery;
	/* VirtualQuery(address, buffer, length) */
	rec.args[0] = (unsigned long long)(size_t)p;
	rec.args[1] = (unsigned long long)(size_t)&mbi;
	rec.args[2] = sizeof(mbi);
	memset(&mbi, 0, sizeof(mbi));
	thunk(&rec);
	printf("  [thunk] VirtualQuery ret=%llx state=%lx base=%p\n",
	       (unsigned long long)rec.ret, (unsigned long)mbi.State, mbi.BaseAddress);
	fflush(stdout);
	/* the buffer and the output pointer were usable by the callee */
	CHECK(rec.ret == sizeof(mbi));
	CHECK(mbi.State == MEM_COMMIT);
	CHECK(mbi.BaseAddress == p);
	VirtualFree(p, 0, MEM_RELEASE);
}

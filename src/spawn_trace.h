#pragma once
/* Spawn-path tracing. The file-logger sink (spawn.cpp) is compiled only
 * when BW_SPAWN_TRACE is defined — the MSVC product preset sets that.
 * The llvm preset leaves it undefined so LLVM objects never embed
 * C:\Users\Public\spawn_trace.txt. */
#include <windows.h>

#ifdef BW_SPAWN_TRACE
#ifdef __cplusplus
extern "C"
#endif
void spawn_log(const char * msg, long v);
#else
static __inline void spawn_log(const char * msg, long v)
{
	(void)msg;
	(void)v;
}
#endif

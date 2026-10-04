#pragma once
/* Lightweight spawn-path tracing (round 23): file-write trace points in the
 * spawn/inject/link chain. One shared implementation lives in spawn.cpp
 * (NOT per-site inlined - the x86 sleeve has a 2KB size margin). Writes to
 * C:\Users\Public\spawn_trace.txt. */
#include <windows.h>

#ifdef __cplusplus
extern "C"
#endif
void spawn_log(const char * msg, long v);

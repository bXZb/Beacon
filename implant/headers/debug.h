#ifndef LINUX_BEACON_DEBUG_H
#define LINUX_BEACON_DEBUG_H

#include <stdio.h>

#ifdef DEBUG
#define DEBUG_PRINT(...) do { fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif

#define ERROR_PRINT(...) do { fprintf(stderr, __VA_ARGS__); } while (0)

#endif

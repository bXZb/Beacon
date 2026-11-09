/* beacon_tests link shims for sources the 2026-11-09 feat merge brought in.
 *
 * The merged datastore.cpp posts the UDC2STORE probe through post_error_dd
 * (real definition in callback.cpp, a DLL-side source the unit-test target
 * deliberately excludes) and security.cpp carries spawn_log probes (real
 * sink in spawn.cpp). The tests never assert on these reporters, so no-op
 * definitions keep the unit target linking without dragging the DLL's
 * dependency graph in. */
#include <windows.h>

void post_error_dd(int error, int arg1, int arg2) {
	(void)error; (void)arg1; (void)arg2;
}

void spawn_log(const char * msg, long v) {
	(void)msg; (void)v;
}

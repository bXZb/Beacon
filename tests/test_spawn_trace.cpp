#include "test_harness.h"
#include "spawn_trace.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifndef BEACON_SRC_DIR
#define BEACON_SRC_DIR "."
#endif

static std::string slurp(const char * rel)
{
	std::string path = std::string(BEACON_SRC_DIR) + "/" + rel;
	FILE * f = fopen(path.c_str(), "rb");
	CHECK(f != NULL);
	std::string out;
	char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		out.append(buf, n);
	fclose(f);
	return out;
}

TEST(spawn_trace_header_is_noop_without_def) {
#ifdef BW_SPAWN_TRACE
	CHECK(!"host_unit must not compile with BW_SPAWN_TRACE");
#endif
	spawn_log("spawn_trace.txt", 0);
}

TEST(spawn_trace_sink_gated_in_source) {
	std::string cpp = slurp("src/spawn.cpp");
	std::string hdr = slurp("src/spawn_trace.h");
	const char * path = "C:\\\\Users\\\\Public\\\\spawn_trace.txt";
	CHECK(cpp.find(path) != std::string::npos);
	CHECK(cpp.find("#ifdef BW_SPAWN_TRACE") != std::string::npos);
	size_t ifdef_pos = cpp.find("#ifdef BW_SPAWN_TRACE");
	size_t path_pos = cpp.find(path);
	size_t endif_pos = cpp.rfind("#endif");
	CHECK(ifdef_pos < path_pos);
	CHECK(path_pos < endif_pos);
	CHECK(hdr.find("static __inline void spawn_log") != std::string::npos);
	CHECK(hdr.find("#ifdef BW_SPAWN_TRACE") != std::string::npos);
}

TEST(ci_llvm_mutation_contract) {
	std::string yml = slurp(".github/workflows/ci.yml");
	CHECK(yml.find("gen_yara.py") != std::string::npos);
	CHECK(yml.find("[ \"$BM\" -ge 12 ]") != std::string::npos);
	CHECK(yml.find("[ \"$LOST\" -ge 10 ]") != std::string::npos);
	CHECK(yml.find("DETERMINISM FAIL") != std::string::npos);
	CHECK(yml.find("UNIQUENESS FAIL") != std::string::npos);
	CHECK(yml.find("if: always()") != std::string::npos);
	CHECK(yml.find("-DBEACON_OBF=ON") != std::string::npos);
	CHECK(yml.find("load_smoke mutated DLL") != std::string::npos);
	CHECK(yml.find("check_spawn_trace_off.cmake") != std::string::npos);
	CHECK(yml.find("byte-diff") == std::string::npos);
	CHECK(yml.find("tools/llvm/CMakeLists.txt") == std::string::npos);
	CHECK(yml.find("plainsleep") == std::string::npos);
	CHECK(yml.find("noexcreg") == std::string::npos);
	CHECK(yml.find("diagretaddr") == std::string::npos);
}

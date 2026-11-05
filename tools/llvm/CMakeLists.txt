cmake_minimum_required(VERSION 3.20)
project(beacon_llvm_retired NONE)
message(FATAL_ERROR
  "LLVM variants are built from the repo root with the xwin toolchain:\n"
  "  cmake -S . -B build-llvm -G Ninja --toolchain cmake/toolchain-clang-cl-xwin.cmake \\\n"
  "    -DCLANG_CL=... -DLLD_LINK=... -DXWIN_DIR=... -DCMAKE_BUILD_TYPE=Release \\\n"
  "    [-DBEACON_OBF_PLUGIN=/path/obfpasses.so]\n"
  "  cmake --build build-llvm\n"
  "The pass plugin is still tools/llvm/pass (native host CMake + AddLLVM).")

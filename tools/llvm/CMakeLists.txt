cmake_minimum_required(VERSION 3.21)
project(beacon_llvm_retired NONE)
message(FATAL_ERROR
  "LLVM variants are built from the repo root:\n"
  "  cmake --preset llvm [-DBEACON_OBF=ON -DLLVM_DIR=...]\n"
  "  cmake --build --preset llvm\n"
  "The pass plugin is tools/llvm/pass, hosted via ExternalProject when BEACON_OBF=ON.")

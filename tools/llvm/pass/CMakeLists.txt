# Phase 3 CMake introduction point: the pass pipeline builds with CMake+AddLLVM
# against the SAME pinned LLVM release tarball the cross toolchain uses — so the
# plugin's LLVM version matches clang-cl's exactly (a mismatch aborts at load).
cmake_minimum_required(VERSION 3.16)
project(obfpasses LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(LLVM REQUIRED CONFIG)  # no version arg: the tarball's config version-negotiation rejects "19" vs "19.1.7"
message(STATUS "obfpasses: LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# MODULE = loadable plugin (-fpass-plugin / opt -load-pass-plugin)
add_llvm_pass_plugin(obfpasses ObfPasses.cpp)

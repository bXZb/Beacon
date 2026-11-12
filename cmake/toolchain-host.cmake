# Host build for tools/llvm/pass. Must not inherit the xwin cross toolchain.
# On Windows GHA, git-bash PATH puts MinGW first; that ABI cannot link the
# MSVC-built LLVM libraries. Pin clang-cl from the same LLVM tree the
# plugin will load into.
if(WIN32 AND DEFINED ENV{LLVM_CLANG} AND EXISTS "$ENV{LLVM_CLANG}")
  set(CMAKE_CXX_COMPILER "$ENV{LLVM_CLANG}" CACHE FILEPATH "host clang-cl" FORCE)
  set(CMAKE_C_COMPILER "$ENV{LLVM_CLANG}" CACHE FILEPATH "host clang-cl" FORCE)
endif()

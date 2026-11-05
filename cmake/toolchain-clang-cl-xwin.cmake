# clang-cl + lld-link + xwin splat. Target is always Windows x86_64.
#
#   cmake -S . -B build-llvm -G Ninja --toolchain cmake/toolchain-clang-cl-xwin.cmake \
#     -DCLANG_CL=/path/clang-cl -DLLD_LINK=/path/lld-link -DXWIN_DIR=/path/xwin-splat \
#     -DCMAKE_BUILD_TYPE=Release
#
# setup-host.sh writes ~/.llvm-cross/toolpath.env (LLVM_CLANG, LLVM_LLD, XWIN_SPLAT).

if(NOT CLANG_CL)
  if(DEFINED ENV{LLVM_CLANG})
    set(CLANG_CL "$ENV{LLVM_CLANG}")
  else()
    set(CLANG_CL "clang-cl")
  endif()
endif()
if(NOT LLD_LINK)
  if(DEFINED ENV{LLVM_LLD})
    set(LLD_LINK "$ENV{LLVM_LLD}")
  else()
    set(LLD_LINK "lld-link")
  endif()
endif()
if(NOT XWIN_DIR)
  if(DEFINED ENV{XWIN_SPLAT})
    set(XWIN_DIR "$ENV{XWIN_SPLAT}")
  endif()
endif()

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_C_COMPILER "${CLANG_CL}" CACHE FILEPATH "" FORCE)
set(CMAKE_CXX_COMPILER "${CLANG_CL}" CACHE FILEPATH "" FORCE)
set(CMAKE_LINKER "${LLD_LINK}" CACHE FILEPATH "" FORCE)
set(CMAKE_C_COMPILER_TARGET x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

get_filename_component(_llvm_bin "${CLANG_CL}" DIRECTORY)
if(EXISTS "${_llvm_bin}/llvm-lib${CMAKE_EXECUTABLE_SUFFIX}")
  set(CMAKE_AR "${_llvm_bin}/llvm-lib${CMAKE_EXECUTABLE_SUFFIX}" CACHE FILEPATH "" FORCE)
endif()
if(EXISTS "${_llvm_bin}/llvm-rc${CMAKE_EXECUTABLE_SUFFIX}")
  set(CMAKE_RC_COMPILER "${_llvm_bin}/llvm-rc${CMAKE_EXECUTABLE_SUFFIX}" CACHE FILEPATH "" FORCE)
endif()

if(XWIN_DIR)
  foreach(_inc
      "${XWIN_DIR}/crt/include"
      "${XWIN_DIR}/sdk/include/ucrt"
      "${XWIN_DIR}/sdk/include/um"
      "${XWIN_DIR}/sdk/include/shared")
    string(APPEND CMAKE_C_FLAGS_INIT " /imsvc${_inc}")
    string(APPEND CMAKE_CXX_FLAGS_INIT " /imsvc${_inc}")
  endforeach()
  foreach(_lib
      "${XWIN_DIR}/crt/lib/x86_64"
      "${XWIN_DIR}/sdk/lib/um/x86_64"
      "${XWIN_DIR}/sdk/lib/ucrt/x86_64")
    string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " /libpath:${_lib}")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS_INIT " /libpath:${_lib}")
    string(APPEND CMAKE_MODULE_LINKER_FLAGS_INIT " /libpath:${_lib}")
    string(APPEND CMAKE_STATIC_LINKER_FLAGS_INIT " /libpath:${_lib}")
  endforeach()
endif()

set(BEACON_LLVM ON CACHE BOOL "clang-cl + xwin LLVM line")
set(CMAKE_FIND_ROOT_PATH "${XWIN_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

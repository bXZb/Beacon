# Fail if a product DLL embeds the spawn_trace file-logger path.
# Used as a CTest on the llvm preset (MSVC builds keep the logger).
if(NOT DLL)
  message(FATAL_ERROR "check_spawn_trace_off.cmake requires -DDLL=<path>")
endif()
file(READ "${DLL}" _bytes HEX)
# ASCII "spawn_trace.txt" = 73 70 61 77 6e 5f 74 72 61 63 65 2e 74 78 74
string(TOLOWER "${_bytes}" _bytes)
if(_bytes MATCHES "737061776e5f74726163652e747874")
  message(FATAL_ERROR "${DLL} embeds spawn_trace.txt — llvm product must not")
endif()
message(STATUS "spawn_trace path absent in ${DLL}")

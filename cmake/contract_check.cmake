# Install-prefix contract for cmake --install. Driven as a CTest.
if(NOT PREFIX)
  message(FATAL_ERROR "PREFIX is required")
endif()
set(_bin "${PREFIX}/bin")
set(_lib "${PREFIX}/lib")
foreach(_f
    beacon.x64.dll
    winhttpb.x64.dll
    dnsb.x64.dll
    extc2.x64.dll
    pivot.x64.dll
    tests.exe
    load_smoke.exe
    host_template_x64.exe)
  if(NOT EXISTS "${_bin}/${_f}")
    message(FATAL_ERROR "cmake --install missing ${_bin}/${_f}")
  endif()
endforeach()
foreach(_f ReflectiveLoader.x64.obj ReflectiveLoader.rwx.x64.obj)
  if(NOT EXISTS "${_lib}/${_f}")
    message(FATAL_ERROR "cmake --install missing ${_lib}/${_f}")
  endif()
endforeach()
if(CONTRACT_STAMP)
  file(READ "${CONTRACT_STAMP}" _stamp)
  if(NOT _stamp MATCHES "tomcrypt_imported=1")
    message(FATAL_ERROR "IMPORTED tomcrypt stamp missing")
  endif()
  if(NOT _stamp MATCHES "NDEBUG_unconditional=0")
    message(FATAL_ERROR "NDEBUG must not be an unconditional product def")
  endif()
endif()
message(STATUS "cmake --install contract ok under ${PREFIX}")

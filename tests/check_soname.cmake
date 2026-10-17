# Fails unless the shared library's SONAME is EXPECTED (see tests/CMakeLists.txt, abi_soname).
execute_process(COMMAND ${READELF} -d ${LIB}
  OUTPUT_VARIABLE dynamic RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "readelf -d ${LIB} failed (${rc})")
endif()
if(NOT dynamic MATCHES "\\(SONAME\\)[ \t]+Library soname: \\[${EXPECTED}\\]")
  message(FATAL_ERROR "SONAME is not ${EXPECTED}:\n${dynamic}")
endif()
message(STATUS "SONAME ${EXPECTED}")

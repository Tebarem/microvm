# SPDX-License-Identifier: MIT
# cmake -DSTATUS=N -DCMD="exe;arg;..." [-DEXPECT=REGEX] -P expect_status.cmake
# Runs CMD and fails unless its exit status is exactly N (ctest itself only
# tells zero from non-zero) and, with EXPECT, its output matches REGEX.
execute_process(COMMAND ${CMD} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(rc STREQUAL "77") # no usable hypervisor here: ctest's SKIP_REGULAR_EXPRESSION
  message(STATUS "skipped: ${err}")
  return()
endif()
if(NOT rc STREQUAL "${STATUS}")
  message(FATAL_ERROR "exit status ${rc}, expected ${STATUS}\nstdout: ${out}\nstderr: ${err}")
endif()
if(DEFINED EXPECT AND NOT "${out}${err}" MATCHES "${EXPECT}")
  message(FATAL_ERROR "output doesn't match '${EXPECT}'\nstdout: ${out}\nstderr: ${err}")
endif()

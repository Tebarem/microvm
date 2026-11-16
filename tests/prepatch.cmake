# SPDX-License-Identifier: MIT
# cmake -DEXE=microvm -DKERNEL=vmlinux -DOUT=FILE -DSRC=SOURCE_DIR -P prepatch.cmake
# Kernel patch 0026 end to end. Pre-patches a fresh KERNEL's alternatives
# for this host's CPU view into OUT (tools/prepatch-alternatives.*), then
# boots OUT three ways, each of which must reach /init:
# - as it is: the fast path, nothing patched at boot;
# - on another CPU, made by hiding CPUID bits: PKU, whose pre-patched test
#   made a KVM-pre-patched image set CR4.PKE and die under WHP, which lacks
#   it; and LAHF/SAHF, which every x86-64 CPU in use has, so the view always
#   differs. The compiled text must go back before any of it runs;
# - with other mitigations (mitigations=off): the same CPU, so the
#   compiled text goes back at the patch point.
if(WIN32)
  set(prep powershell -NoProfile -ExecutionPolicy Bypass -File ${SRC}/tools/prepatch-alternatives.ps1
      -Exe ${EXE} -Kernel ${KERNEL} -Out ${OUT})
else()
  set(ENV{EXE} ${EXE})
  set(prep bash ${SRC}/tools/prepatch-alternatives.sh -k ${KERNEL} -o ${OUT})
endif()
execute_process(COMMAND ${prep} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  if("${out}${err}" MATCHES "already pre-patched")
    message(STATUS "skipped: ${KERNEL} is pre-patched already; this needs a fresh build")
    return()
  elseif("${out}${err}" MATCHES "no usable hypervisor")
    message(STATUS "skipped: no usable hypervisor")
    return()
  endif()
  message(FATAL_ERROR "pre-patching failed (${rc}):\n${out}${err}")
endif()

function(boot expect)
  execute_process(COMMAND ${EXE} --kernel ${OUT} ${ARGN} TIMEOUT 20
                  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc STREQUAL "0" OR NOT "${out}${err}" MATCHES "image pre-patched, ${expect}\n" OR
     NOT "${out}${err}" MATCHES "hello from /init")
    message(FATAL_ERROR "boot with '${ARGN}': status ${rc}, expected 'image pre-patched, "
                        "${expect}' and /init:\n${out}${err}")
  endif()
  message(STATUS "'${ARGN}': ${expect}")
endfunction()
boot("inputs match, not patching")
boot("for another CPU, compiled text restored at boot"
     --cpuid-hide 7.0:ecx:0x8 --cpuid-hide 0x80000001:ecx:0x1)
boot("inputs differ, compiled text restored" --append mitigations=off)

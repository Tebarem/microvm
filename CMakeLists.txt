# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.25)
project(microvm VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(MICROVM_WERROR "Treat warnings as errors" ON)
option(MICROVM_SANITIZE "Build with AddressSanitizer + UBSan (tests/debug only)" OFF)

set(core_src
  src/os.c
  src/vm.c
  src/snapshot.c
  src/boot/x86.c
  src/boot/elf.c
  src/dev/uart8250.c
  src/dev/cmos.c
  src/dev/ioapic.c
  src/dev/virtio_mmio.c
  src/dev/vsock.c
  src/dev/net.c
  src/dev/balloon.c
  src/net_helper.c)
if(WIN32)
  list(APPEND core_src src/sandbox_win.c)
else()
  list(APPEND core_src src/sandbox_linux.c)
endif()

if(WIN32)
  list(APPEND core_src src/hv_whp.c)
  set(hv_libs winhvplatform winhvemulation onecore synchronization ws2_32 iphlpapi)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND core_src src/hv_kvm.c)
  set(hv_libs)
else()
  message(FATAL_ERROR "microvm supports Linux (KVM) and Windows (WHP) hosts only")
endif()

# ---- warnings + hardening ---------------------------------------------------
set(mvm_cflags -Wall -Wextra -Wshadow -Wstrict-prototypes -Wvla -Wformat=2
               -Wimplicit-fallthrough -fno-strict-aliasing
               -fstack-protector-strong -fcf-protection=full -ftrivial-auto-var-init=zero)
set(mvm_ldflags)
if(MICROVM_WERROR)
  list(APPEND mvm_cflags -Werror)
endif()
if(WIN32)
  list(APPEND mvm_ldflags -static -Wl,--dynamicbase,--nxcompat,--high-entropy-va)
else()
  list(APPEND mvm_cflags -fPIE $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>)
  if(NOT MICROVM_SANITIZE)
    list(APPEND mvm_ldflags -static-pie)
  endif()
  list(APPEND mvm_ldflags -Wl,-z,relro,-z,now,-z,noexecstack)
endif()
if(MICROVM_SANITIZE)
  list(APPEND mvm_cflags -fsanitize=address,undefined -fno-omit-frame-pointer)
  list(APPEND mvm_ldflags -fsanitize=address,undefined)
endif()

add_library(mvmcore STATIC ${core_src})
target_compile_options(mvmcore PUBLIC ${mvm_cflags})
target_link_options(mvmcore PUBLIC ${mvm_ldflags})
target_link_libraries(mvmcore PUBLIC ${hv_libs})
if(NOT WIN32)
  target_compile_definitions(mvmcore PUBLIC _GNU_SOURCE)
endif()

add_executable(microvm src/main.c)
target_link_libraries(microvm PRIVATE mvmcore)

# Root filesystem images: tar layers -> EROFS (untrusted input, parsed in memory).
add_library(mvmimage STATIC src/image/fstree.c src/image/erofs.c src/image/sha256.c
                            src/image/inflate.c src/image/zstd.c src/image/json.c
                            src/image/oci.c)
target_link_libraries(mvmimage PUBLIC mvmcore)
add_executable(microvm-mkrootfs src/mkrootfs.c)
target_link_libraries(microvm-mkrootfs PRIVATE mvmimage)

# Function invocations: the host side of the guest agent's protocol
# (src/agent/proto.h). The parser reads hostile guest output.
set(agent_src src/agent/parse.c)
if(NOT WIN32)
  list(APPEND agent_src src/agent/client.c) # POSIX sockets
endif()
add_library(mvmagent STATIC ${agent_src})
target_link_libraries(mvmagent PUBLIC mvmcore)
if(NOT WIN32)
  add_executable(microvm-invoke tools/invoke.c)
  target_include_directories(microvm-invoke PRIVATE src)
  target_link_libraries(microvm-invoke PRIVATE mvmagent)
endif()

# Agent sandboxes: the host side of the guest's sandbox protocol
# (src/sbx/proto.h). The reader takes hostile guest output.
add_library(mvmsbx STATIC src/sbx/wire.c)
target_include_directories(mvmsbx PUBLIC src)
target_link_libraries(mvmsbx PUBLIC mvmcore)
if(NOT WIN32)
  # The E2B-compatible sandbox daemon (SANDBOX.md): HTTP/1.1, the REST control
  # plane, envd's Connect API, port tunnels.
  # http.c: what API clients send (untrusted; fuzz_http).
  add_library(mvmhttp STATIC src/sbxd/http.c)
  target_include_directories(mvmhttp PUBLIC src)
  target_link_libraries(mvmhttp PUBLIC mvmcore)
  add_executable(microvm-sbxd src/sbxd/main.c src/sbxd/api.c src/sbxd/envd.c src/sbxd/fetch.c)
  target_link_libraries(microvm-sbxd PRIVATE mvmsbx mvmhttp mvmimage)
endif()

# Test images from layer tarballs (no docker, no registry); inflate benchmark.
add_executable(mvm-mkoci tools/mkoci.c)
target_include_directories(mvm-mkoci PRIVATE src tests)
target_link_libraries(mvm-mkoci PRIVATE mvmimage)

# Per-VM host isolation (Linux): namespaces, new root, cgroup, per-VM uid.
if(NOT WIN32)
  # Links the network helper (src/net_helper.c) for --net.
  add_executable(microvm-jail src/jail.c)
  target_link_libraries(microvm-jail PRIVATE mvmcore)
endif()

# Benchmark helper: N cold starts in parallel.
if(WIN32)
  add_executable(mvm-parlaunch tools/parlaunch.c)
else()
  add_executable(mvm-parlaunch tools/parlaunch_posix.c)
endif()
target_compile_options(mvm-parlaunch PRIVATE ${mvm_cflags})
target_link_options(mvm-parlaunch PRIVATE ${mvm_ldflags})

# ---- tests --------------------------------------------------------------------
enable_testing()
add_executable(mvm_tests tests/test_main.c)
target_include_directories(mvm_tests PRIVATE src)
target_link_libraries(mvm_tests PRIVATE mvmcore)
add_test(NAME unit COMMAND mvm_tests)
add_executable(mvm_sandbox_tests tests/test_sandbox.c)
target_include_directories(mvm_sandbox_tests PRIVATE src)
target_link_libraries(mvm_sandbox_tests PRIVATE mvmcore)
add_test(NAME sandbox COMMAND mvm_sandbox_tests)
add_executable(mvm_image_tests tests/test_image.c)
target_include_directories(mvm_image_tests PRIVATE src)
target_link_libraries(mvm_image_tests PRIVATE mvmimage)
add_test(NAME image COMMAND mvm_image_tests)
add_executable(mvm_agent_proto_tests tests/test_agent_proto.c)
target_include_directories(mvm_agent_proto_tests PRIVATE src)
target_link_libraries(mvm_agent_proto_tests PRIVATE mvmagent)
add_test(NAME agent_proto COMMAND mvm_agent_proto_tests)
add_executable(mvm_oci_tests tests/test_oci.c)
target_include_directories(mvm_oci_tests PRIVATE src tests)
target_link_libraries(mvm_oci_tests PRIVATE mvmimage)
add_test(NAME oci COMMAND mvm_oci_tests)
add_executable(mvm_zstd_tests tests/test_zstd.c)
target_include_directories(mvm_zstd_tests PRIVATE src tests)
target_link_libraries(mvm_zstd_tests PRIVATE mvmimage)
add_test(NAME zstd COMMAND mvm_zstd_tests)
# The CLI on an OCI layout and a docker-archive written by the tests.
set(mvm_oci_dir ${CMAKE_BINARY_DIR}/oci-sample)
add_test(NAME oci_sample COMMAND mvm_oci_tests --write-sample ${mvm_oci_dir})
add_test(NAME oci_cli_layout COMMAND microvm-mkrootfs --config ${mvm_oci_dir}/layout.cfg
         --oci ${mvm_oci_dir}/layout ${mvm_oci_dir}/layout.erofs)
add_test(NAME oci_cli_docker COMMAND microvm-mkrootfs --docker-archive ${mvm_oci_dir}/docker.tar
         ${mvm_oci_dir}/docker.erofs)
add_test(NAME oci_cli_check COMMAND mvm_oci_tests --check-sample ${mvm_oci_dir}/layout.erofs
         ${mvm_oci_dir}/layout.cfg)
add_test(NAME oci_cli_check_docker COMMAND mvm_oci_tests --check-sample ${mvm_oci_dir}/docker.erofs)
set_tests_properties(oci_sample PROPERTIES FIXTURES_SETUP oci_sample)
set_tests_properties(oci_cli_layout oci_cli_docker PROPERTIES FIXTURES_REQUIRED oci_sample
                                                             FIXTURES_SETUP oci_images)
set_tests_properties(oci_cli_check oci_cli_check_docker PROPERTIES FIXTURES_REQUIRED oci_images)
if(NOT WIN32)
  # Static, like the VMM: it is run inside the jail's empty root.
  add_executable(mvm_jail_tests tests/test_jail.c)
  target_include_directories(mvm_jail_tests PRIVATE src)
  target_link_libraries(mvm_jail_tests PRIVATE mvmcore) # net_helper_open() for the --net checks
  add_test(NAME jail COMMAND mvm_jail_tests $<TARGET_FILE:microvm-jail>)
  set_tests_properties(jail PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)
  # virtio-net: the egress policy here, end to end below.
  add_executable(mvm_net_tests tests/test_net.c)
  target_include_directories(mvm_net_tests PRIVATE src)
  target_link_libraries(mvm_net_tests PRIVATE mvmcore)
  add_test(NAME net_policy COMMAND mvm_net_tests --policy)
  # The KVM suites (run below when a guest kernel is built here, or on a
  # KVM host with one built elsewhere): built either way.
  # virtio-vsock end to end: the host side's socket to /bin/vsock-echo.
  add_executable(mvm_vsock_tests tests/test_vsock.c)
  target_compile_options(mvm_vsock_tests PRIVATE ${mvm_cflags})
  target_link_options(mvm_vsock_tests PRIVATE ${mvm_ldflags})
  # Function invocations: snapshot after the demo runtime's warm-up,
  # restore, invoke through the guest agent.
  add_executable(mvm_agent_tests tests/test_agent.c)
  target_include_directories(mvm_agent_tests PRIVATE src)
  target_link_libraries(mvm_agent_tests PRIVATE mvmagent)
  # Agent sandboxes: /init sandbox driven over vsock.
  add_executable(mvm_sbx_tests tests/test_sbx.c)
  target_include_directories(mvm_sbx_tests PRIVATE src tests)
  target_link_libraries(mvm_sbx_tests PRIVATE mvmsbx)
endif()

if(WIN32)
  # virtio-net: the egress policy here, end to end below.
  add_executable(mvm_net_tests tests/test_net_win.c)
  target_include_directories(mvm_net_tests PRIVATE src tests)
  target_link_libraries(mvm_net_tests PRIVATE mvmcore)
  add_test(NAME net_policy COMMAND mvm_net_tests --policy)
  # virtio-vsock end to end on a Windows host (Winsock Unix sockets).
  add_executable(mvm_vsock_tests tests/test_vsock_win.c)
  target_compile_options(mvm_vsock_tests PRIVATE ${mvm_cflags})
  target_link_options(mvm_vsock_tests PRIVATE ${mvm_ldflags})
  target_link_libraries(mvm_vsock_tests PRIVATE ws2_32)
endif()

# Fuzz harnesses (tests/fuzz). The standalone driver mutates built-in seeds;
# ctest runs a short smoke pass. Real campaigns: build with
# -DMICROVM_SANITIZE=ON and run e.g. `fuzz_elf -runs=10000000 -seed=N`, or
# reuse the harnesses with libFuzzer/AFL++ (see tests/fuzz/driver.c).
foreach(target elf devices virtq snapshot balloon)
  add_executable(fuzz_${target} tests/fuzz/fuzz_${target}.c tests/fuzz/driver.c)
  target_include_directories(fuzz_${target} PRIVATE src tests/fuzz)
  target_link_libraries(fuzz_${target} PRIVATE mvmcore)
  add_test(NAME fuzz_${target} COMMAND fuzz_${target} -runs=30000 -seed=1)
endforeach()
if(NOT WIN32) # the device's host side is Linux-only for now
  add_executable(fuzz_vsock tests/fuzz/fuzz_vsock.c tests/fuzz/driver.c)
  target_include_directories(fuzz_vsock PRIVATE src tests/fuzz)
  target_link_libraries(fuzz_vsock PRIVATE mvmcore)
  add_test(NAME fuzz_vsock COMMAND fuzz_vsock -runs=30000 -seed=1)
  add_executable(fuzz_net tests/fuzz/fuzz_net.c tests/fuzz/driver.c)
  target_include_directories(fuzz_net PRIVATE src tests/fuzz)
  target_link_libraries(fuzz_net PRIVATE mvmcore)
  add_test(NAME fuzz_net COMMAND fuzz_net -runs=30000 -seed=1)
endif()
foreach(target tar erofs inflate zstd json oci)
  add_executable(fuzz_${target} tests/fuzz/fuzz_${target}.c tests/fuzz/driver.c)
  target_include_directories(fuzz_${target} PRIVATE src tests tests/fuzz)
  target_link_libraries(fuzz_${target} PRIVATE mvmimage)
endforeach()
add_test(NAME fuzz_tar COMMAND fuzz_tar -runs=30000 -seed=1)
add_test(NAME fuzz_erofs COMMAND fuzz_erofs -runs=30000 -seed=1)
add_executable(fuzz_agent tests/fuzz/fuzz_agent.c tests/fuzz/driver.c)
target_include_directories(fuzz_agent PRIVATE src tests/fuzz)
target_link_libraries(fuzz_agent PRIVATE mvmagent)
add_test(NAME fuzz_agent COMMAND fuzz_agent -runs=30000 -seed=1)
add_executable(fuzz_sbx tests/fuzz/fuzz_sbx.c tests/fuzz/driver.c)
target_include_directories(fuzz_sbx PRIVATE src tests/fuzz)
target_link_libraries(fuzz_sbx PRIVATE mvmsbx)
add_test(NAME fuzz_sbx COMMAND fuzz_sbx -runs=30000 -seed=1)
add_test(NAME fuzz_inflate COMMAND fuzz_inflate -runs=30000 -seed=1)
add_test(NAME fuzz_zstd COMMAND fuzz_zstd -runs=30000 -seed=1)
add_test(NAME fuzz_json COMMAND fuzz_json -runs=30000 -seed=1)
add_test(NAME fuzz_oci COMMAND fuzz_oci -runs=10000 -seed=1 -max_len=16384)
if(NOT WIN32)
  add_executable(fuzz_http tests/fuzz/fuzz_http.c tests/fuzz/driver.c)
  target_include_directories(fuzz_http PRIVATE src tests/fuzz)
  target_link_libraries(fuzz_http PRIVATE mvmhttp mvmimage)
  add_test(NAME fuzz_http COMMAND fuzz_http -runs=30000 -seed=1)
endif()
# Needs a usable hypervisor (/dev/kvm or Windows Hypervisor Platform).
add_test(NAME hello COMMAND microvm --hello)
set_tests_properties(hello PROPERTIES PASS_REGULAR_EXPRESSION "^OK" SKIP_RETURN_CODE 77)
# --env is for a command in an image; refused before any VM exists.
add_test(NAME env_needs_rootfs COMMAND microvm --hello -e A=1)
add_test(NAME env_bad_name COMMAND microvm --kernel nonexistent --rootfs nonexistent -e =1)
set_tests_properties(env_needs_rootfs PROPERTIES PASS_REGULAR_EXPRESSION "need --rootfs")
set_tests_properties(env_bad_name PROPERTIES PASS_REGULAR_EXPRESSION "no variable name")
# Full boot to /init; only when the guest kernel has been built (guest/kernel/build.sh).
set(mvm_vmlinux ${CMAKE_SOURCE_DIR}/guest/kernel/out/vmlinux)
if(EXISTS ${mvm_vmlinux})
  add_test(NAME boot COMMAND microvm --kernel ${mvm_vmlinux} --quiet)
  set_tests_properties(boot PROPERTIES PASS_REGULAR_EXPRESSION "hello from /init" TIMEOUT 10
                                        SKIP_RETURN_CODE 77)
  # Patch 0026: an image pre-patched here boots on this CPU without
  # patching, and on another CPU (CPUID bits hidden) as a fresh one.
  add_test(NAME prepatch COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:microvm>
           -DKERNEL=${mvm_vmlinux} -DOUT=${CMAKE_BINARY_DIR}/vmlinux-prepatched
           -DSRC=${CMAKE_SOURCE_DIR} -P ${CMAKE_SOURCE_DIR}/tests/prepatch.cmake)
  set_tests_properties(prepatch PROPERTIES TIMEOUT 120 SKIP_REGULAR_EXPRESSION "skipped: ")
endif()
# A container run: image from the test layer (built with the kernel), the
# command's output and exact exit status.
set(mvm_layer ${CMAKE_SOURCE_DIR}/guest/kernel/out/test-layer.tar)
if(EXISTS ${mvm_vmlinux} AND EXISTS ${mvm_layer})
  set(mvm_img ${CMAKE_BINARY_DIR}/test-rootfs.erofs)
  set(mvm_run microvm --kernel ${mvm_vmlinux} --quiet --rootfs ${mvm_img} --)
  add_test(NAME rootfs_image COMMAND microvm-mkrootfs ${mvm_img} ${mvm_layer})
  set_tests_properties(rootfs_image PROPERTIES FIXTURES_SETUP rootfs)
  add_test(NAME rootfs_run COMMAND ${mvm_run} p "a b" c)
  set_tests_properties(rootfs_run PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10 SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "probe: \\[a b\\] \\[c\\] message: from the image\nprobe: stderr")
  foreach(case "42;/bin/probe;42" "127;nosuch" "126;/etc/message")
    list(GET case 0 status)
    list(SUBLIST case 1 -1 cmd)
    list(JOIN cmd "_" name)
    string(MAKE_C_IDENTIFIER "rootfs_status_${name}" name)
    add_test(NAME ${name} COMMAND ${CMAKE_COMMAND} -DSTATUS=${status}
             "-DCMD=$<TARGET_FILE:microvm>;--kernel;${mvm_vmlinux};--quiet;--rootfs;${mvm_img};--;${cmd}"
             -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
    set_tests_properties(${name} PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10
                                             SKIP_REGULAR_EXPRESSION "skipped: ")
  endforeach()
  # The root is writable (a tmpfs over the image) and set up as a
  # container's: /proc, a /dev of its own, /etc/hostname.
  add_test(NAME rootfs_container COMMAND ${mvm_run} p write:/etc/new read:/etc/new read:/dev/null
           read:/proc/self/comm read:/etc/hostname id)
  set_tests_properties(rootfs_container PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10 SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION " /etc/new: ok /etc/new: written /dev/null:  /proc/self/comm: p /etc/hostname: microvm id: uid=0 gid=0 groups= message: from the image")
  # No command, and no image config to take one from.
  add_test(NAME rootfs_no_command COMMAND ${CMAKE_COMMAND} -DSTATUS=125 -DEXPECT=no.command.given
           "-DCMD=$<TARGET_FILE:microvm>;--kernel;${mvm_vmlinux};--quiet;--rootfs;${mvm_img}"
           -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
  set_tests_properties(rootfs_no_command PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10
                                                    SKIP_REGULAR_EXPRESSION "skipped: ")
  # An OCI image with a config, applied as Docker applies it (IMAGES.md):
  # Entrypoint, then Cmd or the caller's arguments; Env plus PATH, HOSTNAME
  # and HOME; WorkingDir, created if missing; User.
  set(mvm_cimg_dir ${CMAKE_BINARY_DIR}/config-image)
  set(mvm_cimg ${CMAKE_BINARY_DIR}/config-image.erofs)
  set(mvm_cimg_json [=[{"Entrypoint":["/bin/probe","7"],"Cmd":["id","cwd","env:FOO","env:HOME","env:PATH","env:HOSTNAME"],"Env":["FOO=bar baz"],"WorkingDir":"/work/dir","User":"1000:1000"}]=])
  add_test(NAME image_config_oci COMMAND ${CMAKE_COMMAND} -E rm -rf ${mvm_cimg_dir})
  add_test(NAME image_config_layout COMMAND mvm-mkoci --config ${mvm_cimg_json} ${mvm_cimg_dir} ${mvm_layer})
  add_test(NAME image_config_rootfs COMMAND microvm-mkrootfs --oci ${mvm_cimg_dir} ${mvm_cimg})
  set_tests_properties(image_config_oci PROPERTIES FIXTURES_SETUP cimg_clean)
  set_tests_properties(image_config_layout PROPERTIES FIXTURES_REQUIRED cimg_clean FIXTURES_SETUP cimg_layout)
  set_tests_properties(image_config_rootfs PROPERTIES FIXTURES_REQUIRED cimg_layout FIXTURES_SETUP cimg)
  # A layer on top (opened before the sandbox, read inside it).
  add_test(NAME image_add_layer COMMAND microvm-mkrootfs --stats --oci ${mvm_cimg_dir} --add-layer ${mvm_layer}
           ${CMAKE_BINARY_DIR}/add-layer.erofs)
  set_tests_properties(image_add_layer PROPERTIES FIXTURES_REQUIRED cimg_layout)
  if(NOT WIN32) # the converter is sandboxed on Linux only
    set_tests_properties(image_add_layer PROPERTIES PASS_REGULAR_EXPRESSION "sandbox: seccomp=kill")
  endif()
  set(mvm_crun $<TARGET_FILE:microvm> --kernel ${mvm_vmlinux} --quiet --rootfs ${mvm_cimg})
  add_test(NAME image_config_cmd COMMAND ${CMAKE_COMMAND} -DSTATUS=7
           "-DEXPECT=probe: .id. .cwd. .env:FOO. .env:HOME. .env:PATH. .env:HOSTNAME. id: uid=1000 gid=1000 groups=1001 cwd: /work/dir FOO=bar baz HOME=/ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOSTNAME=microvm message: from the image"
           "-DCMD=${mvm_crun}" -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
  # Arguments replace Cmd, not Entrypoint; the user can write /tmp but not /etc.
  add_test(NAME image_config_args COMMAND ${CMAKE_COMMAND} -DSTATUS=7
           "-DEXPECT=probe: .write:/tmp/x. .read:/tmp/x. .write:/etc/x. /tmp/x: ok /tmp/x: written /etc/x: error 13 message"
           "-DCMD=${mvm_crun};--;write:/tmp/x;read:/tmp/x;write:/etc/x" -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
  set_tests_properties(image_config_cmd image_config_args PROPERTIES FIXTURES_REQUIRED "rootfs;cimg" TIMEOUT 10
                                                                    SKIP_REGULAR_EXPRESSION "skipped: ")
  # --env-file and -e over the image's Env, as docker run's: the files
  # first, then -e, a later NAME winning; a bare NAME takes the VMM's own
  # NAME, or unsets NAME when the VMM has none. A value holds anything but NUL.
  set(mvm_envf ${CMAKE_BINARY_DIR}/test.env)
  if(WIN32)
    # file(WRITE) there turns each \n into \r\n (so one line would end \r\r\n):
    # LF ends every line instead, and the \r\n line is left to Linux hosts.
    file(CONFIGURE OUTPUT ${mvm_envf} @ONLY NEWLINE_STYLE LF
         CONTENT "# a comment\n\n  FROMFILE=file value\nFOO=from the file\nMVM_TEST_HOST\nMVM_TEST_NOPE\n")
  else()
    file(WRITE ${mvm_envf} "# a comment\n\n  FROMFILE=file value\r\nFOO=from the file\nMVM_TEST_HOST\nMVM_TEST_NOPE\n")
  endif()
  add_test(NAME image_env COMMAND ${CMAKE_COMMAND} -DSTATUS=7
           "-DEXPECT=probe: .*FOO=from -e QUOTE=a \"b\" = c FROMFILE=file value MVM_TEST_HOST=from the host MVM_TEST_NOPE unset PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin message"
           "-DCMD=${mvm_crun};--env-file;${mvm_envf};-e;FOO=from -e;--env;QUOTE=a \"b\" = c;--;env:FOO;env:QUOTE;env:FROMFILE;env:MVM_TEST_HOST;env:MVM_TEST_NOPE;env:PATH"
           -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
  # A bare NAME the VMM doesn't have removes the image's; the defaults
  # (PATH, HOSTNAME, HOME) give way to -e.
  add_test(NAME image_env_unset COMMAND ${CMAKE_COMMAND} -DSTATUS=7
           "-DEXPECT=probe: .* FOO unset PATH=/bin HOSTNAME=h HOME=/ message"
           "-DCMD=${mvm_crun};-e;FOO;-e;PATH=/bin;-e;HOSTNAME=h;--;env:FOO;env:PATH;env:HOSTNAME;env:HOME"
           -P ${CMAKE_SOURCE_DIR}/tests/expect_status.cmake)
  set_tests_properties(image_env image_env_unset PROPERTIES FIXTURES_REQUIRED "rootfs;cimg" TIMEOUT 10
                       SKIP_REGULAR_EXPRESSION "skipped: "
                       ENVIRONMENT_MODIFICATION "MVM_TEST_HOST=set:from the host;MVM_TEST_NOPE=unset:;FOO=unset:")
  # Without an image config: root's environment, with -e on top.
  add_test(NAME rootfs_env COMMAND microvm --kernel ${mvm_vmlinux} --quiet --rootfs ${mvm_img}
           -e A=1 -e HOSTNAME=box -e B=x=y -- p env:A env:HOSTNAME env:B env:HOME)
  set_tests_properties(rootfs_env PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10 SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION " A=1 HOSTNAME=box B=x=y HOME=/root message: from the image")
  if(WIN32)
    add_test(NAME vsock COMMAND mvm_vsock_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    add_test(NAME net COMMAND mvm_net_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    set_tests_properties(vsock net PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 60 SKIP_RETURN_CODE 77)
    # With a network, the image's /etc/resolv.conf names the VMM's resolver.
    add_test(NAME net_resolv_conf COMMAND microvm --kernel ${mvm_vmlinux} --quiet --net --rootfs ${mvm_img}
             -- p read:/etc/resolv.conf)
    set_tests_properties(net_resolv_conf PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10 SKIP_RETURN_CODE 77
                                                    PASS_REGULAR_EXPRESSION "/etc/resolv.conf: nameserver 10.0.2.3")
  endif()
  if(NOT WIN32)
    add_test(NAME vsock COMMAND mvm_vsock_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    set_tests_properties(vsock PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 30 SKIP_RETURN_CODE 77)
    add_test(NAME agent COMMAND mvm_agent_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    set_tests_properties(agent PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 60 SKIP_RETURN_CODE 77)
    add_test(NAME sbx COMMAND mvm_sbx_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    set_tests_properties(sbx PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 90 SKIP_RETURN_CODE 77)
    # Several vCPUs: the SMP kernel (VARIANT=smp guest/kernel/build.sh).
    set(mvm_vmlinux_smp ${CMAKE_SOURCE_DIR}/guest/kernel/out/vmlinux-smp)
    if(EXISTS ${mvm_vmlinux_smp})
      add_test(NAME sbx_smp COMMAND mvm_sbx_tests $<TARGET_FILE:microvm> ${mvm_vmlinux_smp} ${mvm_img} --cpus 4)
      set_tests_properties(sbx_smp PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 90 SKIP_RETURN_CODE 77)
    endif()
    add_test(NAME net COMMAND mvm_net_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img})
    set_tests_properties(net PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 60 SKIP_RETURN_CODE 77)
    # With a network, the image's /etc/resolv.conf names the VMM's resolver.
    add_test(NAME net_resolv_conf COMMAND microvm --kernel ${mvm_vmlinux} --quiet --net --rootfs ${mvm_img}
             -- p read:/etc/resolv.conf)
    set_tests_properties(net_resolv_conf PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 10 SKIP_RETURN_CODE 77
                                                    PASS_REGULAR_EXPRESSION "/etc/resolv.conf: nameserver 10.0.2.3")
    # The same suites with every VM started through microvm-jail.
    add_test(NAME agent_jail COMMAND mvm_agent_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img}
             --jail $<TARGET_FILE:microvm-jail>)
    add_test(NAME net_jail COMMAND mvm_net_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img}
             --jail $<TARGET_FILE:microvm-jail>)
    add_test(NAME sbx_jail COMMAND mvm_sbx_tests $<TARGET_FILE:microvm> ${mvm_vmlinux} ${mvm_img}
             --jail $<TARGET_FILE:microvm-jail>)
    set_tests_properties(agent_jail net_jail PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 60
                                                         SKIP_RETURN_CODE 77)
    set_tests_properties(sbx_jail PROPERTIES FIXTURES_REQUIRED rootfs TIMEOUT 90 SKIP_RETURN_CODE 77)
  endif()
endif()

# ---- version and install ------------------------------------------------------
# The user-facing executables: each prints PROJECT_VERSION for --version.
set(mvm_user_targets microvm microvm-mkrootfs)
if(NOT WIN32)
  list(APPEND mvm_user_targets microvm-sbxd microvm-jail microvm-invoke)
endif()
foreach(mvm_target IN LISTS mvm_user_targets)
  target_compile_definitions(${mvm_target} PRIVATE MICROVM_VERSION="${PROJECT_VERSION}")
endforeach()

include(GNUInstallDirs)
install(TARGETS ${mvm_user_targets} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
file(GLOB mvm_docs CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/*.md)
install(FILES ${mvm_docs} ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR} OPTIONAL)

string(REPLACE "." "\\." mvm_version_re "${PROJECT_VERSION}")
add_test(NAME version COMMAND microvm --version)
set_tests_properties(version PROPERTIES PASS_REGULAR_EXPRESSION "^microvm ${mvm_version_re}[\r\n]")
